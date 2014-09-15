
/*--------------------------------------------------------------------*/
/*--- Instrument IR to propagate taint.            tnt_translate.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Taintgrind, the taint analysis Valgrind tool.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#include "pub_tool_basics.h"
#include "pub_tool_hashtable.h"   // For tnt_include.h, VgHashtable
#include "pub_tool_libcassert.h"  // tl_assert
#include "pub_tool_libcbase.h"    // VG_STREQN, VG_(memset), VG_(random)
#include "pub_tool_libcprint.h"   // VG_(message), VG_(printf)
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)
#include "pub_tool_mallocfree.h"  // VG_(malloc), VG_(free)
//#include "pub_tool_options.h"   // VG_STR/BHEX/BINT_CLO
#include "pub_tool_replacemalloc.h" // 0
#include "pub_tool_stacktrace.h"  // VG_get_StackTrace
#include "pub_tool_tooliface.h"
#include "pub_tool_xarray.h"      // VG_(sizeXA), VG_(newXA), VG_(addtoXA)

#include "tnt_include.h"
//#include "tnt_strings.h"
#include "copy.h"

/*------------------------------------------------------------*/
/*--- Forward decls                                        ---*/
/*------------------------------------------------------------*/

struct _MCEnv;

static IRType  shadowTypeV ( IRType ty );
// Taintgrind: Primarily used by do_shadow_WRTMP
static IRExpr* expr2vbits ( struct _MCEnv* mce, IRExpr* e );
// Taintgrind: Same as expr2vbits, except only for Iex_RdTmp's and Iex_Const's,
//          Used by all functions except do_shadow_WRTMP
static IRExpr* atom2vbits ( struct _MCEnv* mce, IRExpr* e );
//static IRTemp  findShadowTmpB ( struct _MCEnv* mce, IRTemp orig );

static IRExpr *i128_const_zero(void);

// Taintgrind: count the number of BBs read. For turning on/off instrumentation
Int numBBs = 0;
// Kilo-BBs
Int numKBBs = 0;

/* Carries info about a particular tmp.  The tmp's number is not
   recorded, as this is implied by (equal to) its index in the tmpMap
   in MCEnv.  The tmp's type is also not recorded, as this is present
   in MCEnv.sb->tyenv.

   When .kind is Orig, .shadowV and .shadowB may give the identities
   of the temps currently holding the associated definedness (shadowV)
   and origin (shadowB) values, or these may be IRTemp_INVALID if code
   to compute such values has not yet been emitted.

   When .kind is VSh or BSh then the tmp is holds a V- or B- value,
   and so .shadowV and .shadowB must be IRTemp_INVALID, since it is
   illogical for a shadow tmp itself to be shadowed.
*/
typedef
   enum { Orig=1, VSh=2 } //, BSh=3 }  Not doing origin tracking
   TempKind;

typedef
   struct {
      TempKind kind;
      IRTemp   shadowV;
//      IRTemp   shadowB;      Not doing origin tracking
   }
   TempMapEnt;

/* Carries around state during instrumentation. */
typedef
   struct _MCEnv {
      /* MODIFIED: the superblock being constructed.  IRStmts are
         added. */
      IRSB* sb;
      Bool  trace;

      /* MODIFIED: a table [0 .. #temps_in_sb-1] which gives the
         current kind and possibly shadow temps for each temp in the
         IRSB being constructed.  Note that it does not contain the
         type of each tmp.  If you want to know the type, look at the
         relevant entry in sb->tyenv.  It follows that at all times
         during the instrumentation process, the valid indices for
         tmpMap and sb->tyenv are identical, being 0 .. N-1 where N is
         total number of Orig, V- and B- temps allocated so far.

         The reason for this strange split (types in one place, all
         other info in another) is that we need the types to be
         attached to sb so as to make it possible to do
         "typeOfIRExpr(mce->bb->tyenv, ...)" at various places in the
         instrumentation process. */
      XArray* /* of TempMapEnt */ tmpMap;

      /* MODIFIED: indicates whether "bogus" literals have so far been
         found.  Starts off False, and may change to True. */
      Bool    bogusLiterals;

      /* READONLY: indicates whether we should use expensive
         interpretations of integer adds, since unfortunately LLVM
         uses them to do ORs in some circumstances.  Defaulted to True
         on MacOS and False everywhere else. */
      Bool useLLVMworkarounds;

      /* READONLY: the guest layout.  This indicates which parts of
         the guest state should be regarded as 'always defined'. */
      VexGuestLayout* layout;

      /* READONLY: the host word type.  Needed for constructing
         arguments of type 'HWord' to be passed to helper functions.
         Ity_I32 or Ity_I64 only. */
      IRType hWordTy;
   }
   MCEnv;

/* SHADOW TMP MANAGEMENT. */
/* Create a new IRTemp of type 'ty' and kind 'kind', and add it to
   both the table in mce->sb and to our auxiliary mapping.  Note that
   newTemp may cause mce->tmpMap to resize, hence previous results
   from VG_(indexXA)(mce->tmpMap) are invalidated. */
static IRTemp newTemp ( MCEnv* mce, IRType ty, TempKind kind )
{
   Word       newIx;
   TempMapEnt ent;
   IRTemp     tmp = newIRTemp(mce->sb->tyenv, ty);
   ent.kind    = kind;
   ent.shadowV = IRTemp_INVALID;
//   ent.shadowB = IRTemp_INVALID;
   newIx = VG_(addToXA)( mce->tmpMap, &ent );
   tl_assert(newIx == (Word)tmp);
   return tmp;
}


/* Find the tmp currently shadowing the given original tmp.  If none
   so far exists, allocate one.  */
static IRTemp findShadowTmpV ( MCEnv* mce, IRTemp orig )
{
   TempMapEnt* ent;
   /* VG_(indexXA) range-checks 'orig', hence no need to check
      here. */
   ent = (TempMapEnt*)VG_(indexXA)( mce->tmpMap, (Word)orig );
   tl_assert(ent->kind == Orig);
   if (ent->shadowV == IRTemp_INVALID) {
      IRTemp tmpV
        = newTemp( mce, shadowTypeV(mce->sb->tyenv->types[orig]), VSh );
      /* newTemp may cause mce->tmpMap to resize, hence previous results
         from VG_(indexXA) are invalid. */
      ent = (TempMapEnt*)VG_(indexXA)( mce->tmpMap, (Word)orig );
      tl_assert(ent->kind == Orig);
      tl_assert(ent->shadowV == IRTemp_INVALID);
      ent->shadowV = tmpV;
   }
   return ent->shadowV;
}

/* Allocate a new shadow for the given original tmp.  This means any
   previous shadow is abandoned.  This is needed because it is
   necessary to give a new value to a shadow once it has been tested
   for undefinedness, but unfortunately IR's SSA property disallows
   this.  Instead we must abandon the old shadow, allocate a new one
   and use that instead.

   This is the same as findShadowTmpV, except we don't bother to see
   if a shadow temp already existed -- we simply allocate a new one
   regardless. */
//static void newShadowTmpV ( MCEnv* mce, IRTemp orig )
//{
//   TempMapEnt* ent;
   /* VG_(indexXA) range-checks 'orig', hence no need to check
      here. */
//   ent = (TempMapEnt*)VG_(indexXA)( mce->tmpMap, (Word)orig );
//   tl_assert(ent->kind == Orig);
//   if (1) {
//      IRTemp tmpV
//        = newTemp( mce, shadowTypeV(mce->sb->tyenv->types[orig]), VSh );
      /* newTemp may cause mce->tmpMap to resize, hence previous results
         from VG_(indexXA) are invalid. */
//      ent = (TempMapEnt*)VG_(indexXA)( mce->tmpMap, (Word)orig );
//      tl_assert(ent->kind == Orig);
//      ent->shadowV = tmpV;
//   }
//}

/*------------------------------------------------------------*/
/*--- IRAtoms -- a subset of IRExprs                       ---*/
/*------------------------------------------------------------*/

/* An atom is either an IRExpr_Const or an IRExpr_Tmp, as defined by
   isIRAtom() in libvex_ir.h.  Because this instrumenter expects flat
   input, most of this code deals in atoms.  Usefully, a value atom
   always has a V-value which is also an atom: constants are shadowed
   by constants, and temps are shadowed by the corresponding shadow
   temporary. */

typedef  IRExpr  IRAtom;

/* (used for sanity checks only): is this an atom which looks
   like it's from original code? */
static Bool isOriginalAtom ( MCEnv* mce, IRAtom* a1 ) //303
{
   if (a1->tag == Iex_Const)
      return True;
   if (a1->tag == Iex_RdTmp) {
      TempMapEnt* ent = VG_(indexXA)( mce->tmpMap, a1->Iex.RdTmp.tmp );
      return ent->kind == Orig;
   }
   return False;
}

/* (used for sanity checks only): is this an atom which looks
   like it's from shadow code? */
static Bool isShadowAtom ( MCEnv* mce, IRAtom* a1 )
{
   if (a1->tag == Iex_Const)
      return True;
   if (a1->tag == Iex_RdTmp) {
      TempMapEnt* ent = VG_(indexXA)( mce->tmpMap, a1->Iex.RdTmp.tmp );
      return ent->kind == VSh; // || ent->kind == BSh;
   }
   return False;
}

/* (used for sanity checks only): check that both args are atoms and
   are identically-kinded. */
static Bool sameKindedAtoms ( IRAtom* a1, IRAtom* a2 )
{
   if (a1->tag == Iex_RdTmp && a2->tag == Iex_RdTmp)
      return True;
   if (a1->tag == Iex_Const && a2->tag == Iex_Const)
      return True;
   return False;
}


/*------------------------------------------------------------*/
/*--- Type management                                      ---*/
/*------------------------------------------------------------*/

/* Shadow state is always accessed using integer types.  This returns
   an integer type with the same size (as per sizeofIRType) as the
   given type.  The only valid shadow types are Bit, I8, I16, I32,
   I64, V128. */

static IRType shadowTypeV ( IRType ty ) //348
{
   switch (ty) {
      case Ity_I1:
      case Ity_I8:
      case Ity_I16:
      case Ity_I32:
      case Ity_I64:
      case Ity_I128: return ty;
      case Ity_F32:  return Ity_I32;
      case Ity_D32:  return Ity_I32;
      case Ity_F64:  return Ity_I64;
      case Ity_D64:  return Ity_I64;
      case Ity_F128: return Ity_I128;
      case Ity_D128: return Ity_I128;
      case Ity_V128: return Ity_V128;
      case Ity_V256: return Ity_V256;
      default: ppIRType(ty);
               VG_(tool_panic)("tnt_translate.c: shadowTypeV");
   }
}

/* Produce a 'defined' value of the given shadow type.  Should only be
   supplied shadow types (Bit/I8/I16/I32/UI64). */
static IRExpr* definedOfType ( IRType ty ) { //367
   switch (ty) {
      case Ity_I1:   return IRExpr_Const(IRConst_U1(False));
      case Ity_I8:   return IRExpr_Const(IRConst_U8(0));
      case Ity_I16:  return IRExpr_Const(IRConst_U16(0));
      case Ity_I32:  return IRExpr_Const(IRConst_U32(0));
      case Ity_I64:  return IRExpr_Const(IRConst_U64(0));
      case Ity_I128: return i128_const_zero();
      case Ity_V128: return IRExpr_Const(IRConst_V128(0x0000));
      default:       VG_(tool_panic)("tnt_translate.c: definedOfType");
   }
}

/*------------------------------------------------------------*/
/*--- Constructing IR fragments                            ---*/
/*------------------------------------------------------------*/

/* add stmt to a bb */
static inline void stmt ( HChar cat, MCEnv* mce, IRStmt* st ) { //385
   if (mce->trace) {
      VG_(printf)("  %c: ", cat);
      ppIRStmt(st);
      VG_(printf)("\n");
   }
   addStmtToIRSB(mce->sb, st);
}

/* assign value to tmp */
static inline
void assign ( HChar cat, MCEnv* mce, IRTemp tmp, IRExpr* expr ) {
   stmt(cat, mce, IRStmt_WrTmp(tmp,expr));
}

/* build various kinds of expressions *///400
#define triop(_op, _arg1, _arg2, _arg3) \
                                 IRExpr_Triop((_op),(_arg1),(_arg2),(_arg3))
#define binop(_op, _arg1, _arg2) IRExpr_Binop((_op),(_arg1),(_arg2))
#define unop(_op, _arg)          IRExpr_Unop((_op),(_arg))
#define mkU1(_n)                 IRExpr_Const(IRConst_U1(_n))
#define mkU8(_n)                 IRExpr_Const(IRConst_U8(_n))
#define mkU16(_n)                IRExpr_Const(IRConst_U16(_n))
#define mkU32(_n)                IRExpr_Const(IRConst_U32(_n))
#define mkU64(_n)                IRExpr_Const(IRConst_U64(_n))
#define mkV128(_n)               IRExpr_Const(IRConst_V128(_n))
#define mkexpr(_tmp)             IRExpr_RdTmp((_tmp))

/* Bind the given expression to a new temporary, and return the
   temporary.  This effectively converts an arbitrary expression into
   an atom.

   'ty' is the type of 'e' and hence the type that the new temporary
   needs to be.  But passing it in is redundant, since we can deduce
   the type merely by inspecting 'e'.  So at least use that fact to
   assert that the two types agree. */
static IRAtom* assignNew ( HChar cat, MCEnv* mce, IRType ty, IRExpr* e ) //418
{
   TempKind k;
   IRTemp   t;
   IRType   tyE = typeOfIRExpr(mce->sb->tyenv, e);
   tl_assert(tyE == ty); /* so 'ty' is redundant (!) */
   switch (cat) {
      case 'V': k = VSh;  break;
//      case 'B': k = BSh;  break;
      case 'C': k = Orig; break;
                /* happens when we are making up new "orig"
                   expressions, for IRCAS handling */
      default: tl_assert(0);
   }
   t = newTemp(mce, ty, k);
   assign(cat, mce, t, e);
   return mkexpr(t);
}


/*------------------------------------------------------------*/
/*--- Helper functions for 128-bit ops                     ---*/
/*------------------------------------------------------------*/

static IRExpr *i128_const_zero(void)
{
   IRAtom* z64 = IRExpr_Const(IRConst_U64(0));
   return binop(Iop_64HLto128, z64, z64);
}

/* There are no I128-bit loads and/or stores [as generated by any
   current front ends].  So we do not need to worry about that in
   expr2vbits_Load */


/*------------------------------------------------------------*/
/*--- Constructing definedness primitive ops               ---*/
/*------------------------------------------------------------*/

/* --------- Defined-if-either-defined --------- */

static IRAtom* mkDifD8 ( MCEnv* mce, IRAtom* a1, IRAtom* a2 ) { //444
   tl_assert(isShadowAtom(mce,a1));
   tl_assert(isShadowAtom(mce,a2));
   return assignNew('V', mce, Ity_I8, binop(Iop_And8, a1, a2));
}

static IRAtom* mkDifD16 ( MCEnv* mce, IRAtom* a1, IRAtom* a2 ) {
   tl_assert(isShadowAtom(mce,a1));
   tl_assert(isShadowAtom(mce,a2));
   return assignNew('V', mce, Ity_I16, binop(Iop_And16, a1, a2));
}

static IRAtom* mkDifD32 ( MCEnv* mce, IRAtom* a1, IRAtom* a2 ) {
   tl_assert(isShadowAtom(mce,a1));
   tl_assert(isShadowAtom(mce,a2));
   return assignNew('V', mce, Ity_I32, binop(Iop_And32, a1, a2));
}
static IRAtom* mkDifD64 ( MCEnv* mce, IRAtom* a1, IRAtom* a2 ) {
   tl_assert(isShadowAtom(mce,a1));
   tl_assert(isShadowAtom(mce,a2));
   return assignNew('V', mce, Ity_I64, binop(Iop_And64, a1, a2));
}

static IRAtom* mkDifDV128 ( MCEnv* mce, IRAtom* a1, IRAtom* a2 ) {
   tl_assert(isShadowAtom(mce,a1));
   tl_assert(isShadowAtom(mce,a2));
   return assignNew('V', mce, Ity_V128, binop(Iop_AndV128, a1, a2));
}

static IRAtom* mkDifDV256 ( MCEnv* mce, IRAtom* a1, IRAtom* a2 ) {
   tl_assert(isShadowAtom(mce,a1));
   tl_assert(isShadowAtom(mce,a2));
   return assignNew('V', mce, Ity_V256, binop(Iop_AndV256, a1, a2));
}

/* --------- Undefined-if-either-undefined --------- */

static IRAtom* mkUifU8 ( MCEnv* mce, IRAtom* a1, IRAtom* a2 ) {
   tl_assert(isShadowAtom(mce,a1));
   tl_assert(isShadowAtom(mce,a2));
   return assignNew('V', mce, Ity_I8, binop(Iop_Or8, a1, a2));
}

static IRAtom* mkUifU16 ( MCEnv* mce, IRAtom* a1, IRAtom* a2 ) {
   tl_assert(isShadowAtom(mce,a1));
   tl_assert(isShadowAtom(mce,a2));
   return assignNew('V', mce, Ity_I16, binop(Iop_Or16, a1, a2));
}

static IRAtom* mkUifU32 ( MCEnv* mce, IRAtom* a1, IRAtom* a2 ) {
   tl_assert(isShadowAtom(mce,a1));
   tl_assert(isShadowAtom(mce,a2));
   return assignNew('V', mce, Ity_I32, binop(Iop_Or32, a1, a2));
}

static IRAtom* mkUifU64 ( MCEnv* mce, IRAtom* a1, IRAtom* a2 ) {
   tl_assert(isShadowAtom(mce,a1));
   tl_assert(isShadowAtom(mce,a2));
   return assignNew('V', mce, Ity_I64, binop(Iop_Or64, a1, a2));
}

static IRAtom* mkUifUV128 ( MCEnv* mce, IRAtom* a1, IRAtom* a2 ) {
   tl_assert(isShadowAtom(mce,a1));
   tl_assert(isShadowAtom(mce,a2));
   return assignNew('V', mce, Ity_V128, binop(Iop_OrV128, a1, a2));
}

static IRAtom* mkUifUV256 ( MCEnv* mce, IRAtom* a1, IRAtom* a2 ) {
   tl_assert(isShadowAtom(mce,a1));
   tl_assert(isShadowAtom(mce,a2));
   return assignNew('V', mce, Ity_V256, binop(Iop_OrV256, a1, a2));
}

static IRAtom* mkUifU ( MCEnv* mce, IRType vty, IRAtom* a1, IRAtom* a2 ) {
   switch (vty) {
      case Ity_I8:   return mkUifU8(mce, a1, a2);
      case Ity_I16:  return mkUifU16(mce, a1, a2);
      case Ity_I32:  return mkUifU32(mce, a1, a2);
      case Ity_I64:  return mkUifU64(mce, a1, a2);
      case Ity_V128: return mkUifUV128(mce, a1, a2);
      case Ity_V256: return mkUifUV256(mce, a1, a2);
      default:
         VG_(printf)("\n"); ppIRType(vty); VG_(printf)("\n");
         VG_(tool_panic)("tnt_translate.c:mkUifU");
   }
}

/* --------- The Left-family of operations. --------- */

static IRAtom* mkLeft8 ( MCEnv* mce, IRAtom* a1 ) {
   tl_assert(isShadowAtom(mce,a1));
   return assignNew('V', mce, Ity_I8, unop(Iop_Left8, a1));
}

static IRAtom* mkLeft16 ( MCEnv* mce, IRAtom* a1 ) {
   tl_assert(isShadowAtom(mce,a1));
   return assignNew('V', mce, Ity_I16, unop(Iop_Left16, a1));
}

static IRAtom* mkLeft32 ( MCEnv* mce, IRAtom* a1 ) {
   tl_assert(isShadowAtom(mce,a1));
   return assignNew('V', mce, Ity_I32, unop(Iop_Left32, a1));
}

static IRAtom* mkLeft64 ( MCEnv* mce, IRAtom* a1 ) {
   tl_assert(isShadowAtom(mce,a1));
   return assignNew('V', mce, Ity_I64, unop(Iop_Left64, a1));
}

/* --------- 'Improvement' functions for AND/OR. --------- */

/* ImproveAND(data, vbits) = data OR vbits.  Defined (0) data 0s give
   defined (0); all other -> undefined (1).
*/
static IRAtom* mkImproveAND8 ( MCEnv* mce, IRAtom* data, IRAtom* vbits ) //546
{
   tl_assert(isOriginalAtom(mce, data));
   tl_assert(isShadowAtom(mce, vbits));
   tl_assert(sameKindedAtoms(data, vbits));
   return assignNew('V', mce, Ity_I8, binop(Iop_Or8, data, vbits));
}

static IRAtom* mkImproveAND16 ( MCEnv* mce, IRAtom* data, IRAtom* vbits )
{
   tl_assert(isOriginalAtom(mce, data));
   tl_assert(isShadowAtom(mce, vbits));
   tl_assert(sameKindedAtoms(data, vbits));
   return assignNew('V', mce, Ity_I16, binop(Iop_Or16, data, vbits));
}

static IRAtom* mkImproveAND32 ( MCEnv* mce, IRAtom* data, IRAtom* vbits )
{
   tl_assert(isOriginalAtom(mce, data));
   tl_assert(isShadowAtom(mce, vbits));
   tl_assert(sameKindedAtoms(data, vbits));
   return assignNew('V', mce, Ity_I32, binop(Iop_Or32, data, vbits));
}

static IRAtom* mkImproveAND64 ( MCEnv* mce, IRAtom* data, IRAtom* vbits )
{
   tl_assert(isOriginalAtom(mce, data));
   tl_assert(isShadowAtom(mce, vbits));
   tl_assert(sameKindedAtoms(data, vbits));
   return assignNew('V', mce, Ity_I64, binop(Iop_Or64, data, vbits));
}

static IRAtom* mkImproveANDV128 ( MCEnv* mce, IRAtom* data, IRAtom* vbits )
{
   tl_assert(isOriginalAtom(mce, data));
   tl_assert(isShadowAtom(mce, vbits));
   tl_assert(sameKindedAtoms(data, vbits));
   return assignNew('V', mce, Ity_V128, binop(Iop_OrV128, data, vbits));
}

static IRAtom* mkImproveANDV256 ( MCEnv* mce, IRAtom* data, IRAtom* vbits )
{
   tl_assert(isOriginalAtom(mce, data));
   tl_assert(isShadowAtom(mce, vbits));
   tl_assert(sameKindedAtoms(data, vbits));
   return assignNew('V', mce, Ity_V256, binop(Iop_OrV256, data, vbits));
}

/* ImproveOR(data, vbits) = ~data OR vbits.  Defined (0) data 1s give
   defined (0); all other -> undefined (1).
*/
static IRAtom* mkImproveOR8 ( MCEnv* mce, IRAtom* data, IRAtom* vbits )
{
   tl_assert(isOriginalAtom(mce, data));
   tl_assert(isShadowAtom(mce, vbits));
   tl_assert(sameKindedAtoms(data, vbits));
   return assignNew(
             'V', mce, Ity_I8,
             binop(Iop_Or8,
                   assignNew('V', mce, Ity_I8, unop(Iop_Not8, data)),
                   vbits) );
}

static IRAtom* mkImproveOR16 ( MCEnv* mce, IRAtom* data, IRAtom* vbits )
{
   tl_assert(isOriginalAtom(mce, data));
   tl_assert(isShadowAtom(mce, vbits));
   tl_assert(sameKindedAtoms(data, vbits));
   return assignNew(
             'V', mce, Ity_I16,
             binop(Iop_Or16,
                   assignNew('V', mce, Ity_I16, unop(Iop_Not16, data)),
                   vbits) );
}

static IRAtom* mkImproveOR32 ( MCEnv* mce, IRAtom* data, IRAtom* vbits )
{
   tl_assert(isOriginalAtom(mce, data));
   tl_assert(isShadowAtom(mce, vbits));
   tl_assert(sameKindedAtoms(data, vbits));
   return assignNew(
             'V', mce, Ity_I32,
             binop(Iop_Or32,
                   assignNew('V', mce, Ity_I32, unop(Iop_Not32, data)),
                   vbits) );
}

static IRAtom* mkImproveOR64 ( MCEnv* mce, IRAtom* data, IRAtom* vbits )
{
   tl_assert(isOriginalAtom(mce, data));
   tl_assert(isShadowAtom(mce, vbits));
   tl_assert(sameKindedAtoms(data, vbits));
   return assignNew(
             'V', mce, Ity_I64,
             binop(Iop_Or64,
                   assignNew('V', mce, Ity_I64, unop(Iop_Not64, data)),
                   vbits) );
}

static IRAtom* mkImproveORV128 ( MCEnv* mce, IRAtom* data, IRAtom* vbits )
{
   tl_assert(isOriginalAtom(mce, data));
   tl_assert(isShadowAtom(mce, vbits));
   tl_assert(sameKindedAtoms(data, vbits));
   return assignNew(
             'V', mce, Ity_V128,
             binop(Iop_OrV128,
                   assignNew('V', mce, Ity_V128, unop(Iop_NotV128, data)),
                   vbits) );
}

static IRAtom* mkImproveORV256 ( MCEnv* mce, IRAtom* data, IRAtom* vbits )
{
   tl_assert(isOriginalAtom(mce, data));
   tl_assert(isShadowAtom(mce, vbits));
   tl_assert(sameKindedAtoms(data, vbits));
   return assignNew(
             'V', mce, Ity_V256,
             binop(Iop_OrV256,
                   assignNew('V', mce, Ity_V256, unop(Iop_NotV256, data)),
                   vbits) );
}

/* --------- Pessimising casts. --------- */

static IRAtom* mkPCastTo( MCEnv* mce, IRType dst_ty, IRAtom* vbits )
{
   IRType  src_ty;
   IRAtom* tmp1;

   /* Note, dst_ty is a shadow type, not an original type. */
   tl_assert(isShadowAtom(mce,vbits));
   src_ty = typeOfIRExpr(mce->sb->tyenv, vbits);

   /* Fast-track some common cases */
   if (src_ty == Ity_I32 && dst_ty == Ity_I32)
      return assignNew('V', mce, Ity_I32, unop(Iop_CmpwNEZ32, vbits));

   if (src_ty == Ity_I64 && dst_ty == Ity_I64)
      return assignNew('V', mce, Ity_I64, unop(Iop_CmpwNEZ64, vbits));

   if (src_ty == Ity_I32 && dst_ty == Ity_I64) {
      IRAtom* tmp = assignNew('V', mce, Ity_I32, unop(Iop_CmpwNEZ32, vbits));
      return assignNew('V', mce, Ity_I64, binop(Iop_32HLto64, tmp, tmp));
   }

   if (src_ty == Ity_I64 && dst_ty == Ity_I32) {
      /* PCast the arg.  This gives all 0s or all 1s.  Then throw away
         the top half. */
      IRAtom* tmp = assignNew('V', mce, Ity_I64, unop(Iop_CmpwNEZ64, vbits));
      return assignNew('V', mce, Ity_I32, unop(Iop_64to32, tmp));
   }

   /* Else do it the slow way .. */
   /* First of all, collapse vbits down to a single bit. */
   tmp1   = NULL;
   switch (src_ty) {
      case Ity_I1:
         tmp1 = vbits;
         break;
      case Ity_I8:
         tmp1 = assignNew('V', mce, Ity_I1, unop(Iop_CmpNEZ8, vbits));
         break;
      case Ity_I16:
         tmp1 = assignNew('V', mce, Ity_I1, unop(Iop_CmpNEZ16, vbits));
         break;
      case Ity_I32:
         tmp1 = assignNew('V', mce, Ity_I1, unop(Iop_CmpNEZ32, vbits));
         break;
      case Ity_I64:
         tmp1 = assignNew('V', mce, Ity_I1, unop(Iop_CmpNEZ64, vbits));
         break;
      case Ity_I128: {
         /* Gah.  Chop it in half, OR the halves together, and compare
            that with zero. */
         IRAtom* tmp2 = assignNew('V', mce, Ity_I64, unop(Iop_128HIto64, vbits));
         IRAtom* tmp3 = assignNew('V', mce, Ity_I64, unop(Iop_128to64, vbits));
         IRAtom* tmp4 = assignNew('V', mce, Ity_I64, binop(Iop_Or64, tmp2, tmp3));
         tmp1         = assignNew('V', mce, Ity_I1,
                                       unop(Iop_CmpNEZ64, tmp4));
         break;
      }
      default:
         ppIRType(src_ty);
         VG_(tool_panic)("tnt_translate.c: mkPCastTo(1)");
   }
   tl_assert(tmp1);
   /* Now widen up to the dst type. */
   switch (dst_ty) {
      case Ity_I1:
         return tmp1;
      case Ity_I8:
         return assignNew('V', mce, Ity_I8, unop(Iop_1Sto8, tmp1));
      case Ity_I16:
         return assignNew('V', mce, Ity_I16, unop(Iop_1Sto16, tmp1));
      case Ity_I32:
         return assignNew('V', mce, Ity_I32, unop(Iop_1Sto32, tmp1));
      case Ity_I64:
         return assignNew('V', mce, Ity_I64, unop(Iop_1Sto64, tmp1));
      case Ity_V128:
         tmp1 = assignNew('V', mce, Ity_I64,  unop(Iop_1Sto64, tmp1));
         tmp1 = assignNew('V', mce, Ity_V128, binop(Iop_64HLtoV128, tmp1, tmp1));
         return tmp1;
      case Ity_I128:
         tmp1 = assignNew('V', mce, Ity_I64,  unop(Iop_1Sto64, tmp1));
         tmp1 = assignNew('V', mce, Ity_I128, binop(Iop_64HLto128, tmp1, tmp1));
         return tmp1;
      case Ity_V256:
         tmp1 = assignNew('V', mce, Ity_I64,  unop(Iop_1Sto64, tmp1));
         tmp1 = assignNew('V', mce, Ity_V128, binop(Iop_64HLtoV128,
                                                    tmp1, tmp1));
         tmp1 = assignNew('V', mce, Ity_V256, binop(Iop_V128HLtoV256,
                                                    tmp1, tmp1));
         return tmp1;
      default:
         ppIRType(dst_ty);
         VG_(tool_panic)("tnt_translate.c: mkPCastTo(2)");
   }
}

/* This is a minor variant.  It takes an arg of some type and returns
   a value of the same type.  The result consists entirely of Defined
   (zero) bits except its least significant bit, which is a PCast of
   the entire argument down to a single bit. */
static IRAtom* mkPCastXXtoXXlsb ( MCEnv* mce, IRAtom* varg, IRType ty )
{
   if (ty == Ity_V128) {
      /* --- Case for V128 --- */
      IRAtom* varg128 = varg;
      // generates: PCast-to-I64(varg128)
      IRAtom* pcdTo64 = mkPCastTo(mce, Ity_I64, varg128);
      // Now introduce zeros (defined bits) in the top 63 places
      // generates: Def--(63)--Def PCast-to-I1(varg128)
      IRAtom* d63pc
         = assignNew('V', mce, Ity_I64, binop(Iop_And64, pcdTo64, mkU64(1)));
      // generates: Def--(64)--Def
      IRAtom* d64
         = definedOfType(Ity_I64);
      // generates: Def--(127)--Def PCast-to-I1(varg128)
      IRAtom* res
         = assignNew('V', mce, Ity_V128, binop(Iop_64HLtoV128, d64, d63pc));
      return res;
   }
   if (ty == Ity_I64) {
      /* --- Case for I64 --- */
      // PCast to 64
      IRAtom* pcd = mkPCastTo(mce, Ity_I64, varg);
      // Zero (Def) out the top 63 bits
      IRAtom* res
         = assignNew('V', mce, Ity_I64, binop(Iop_And64, pcd, mkU64(1)));
      return res;
   }
   /*NOTREACHED*/
   tl_assert(0);
}

/* --------- Accurate interpretation of CmpEQ/CmpNE. --------- */
static IRAtom* expensiveCmpEQorNE ( MCEnv*  mce, //774
                                    IRType  ty,
                                    IRAtom* vxx, IRAtom* vyy,
                                    IRAtom* xx,  IRAtom* yy )
{
   IRAtom *naive, *vec, *improvement_term;
   IRAtom *improved, *final_cast, *top;
   IROp   opDIFD, opUIFU, opXOR, opNOT, opCMP, opOR;

   tl_assert(isShadowAtom(mce,vxx));
   tl_assert(isShadowAtom(mce,vyy));
   tl_assert(isOriginalAtom(mce,xx));
   tl_assert(isOriginalAtom(mce,yy));
   tl_assert(sameKindedAtoms(vxx,xx));
   tl_assert(sameKindedAtoms(vyy,yy));

   switch (ty) {
      case Ity_I16:
         opOR   = Iop_Or16;
         opDIFD = Iop_And16;
         opUIFU = Iop_Or16;
         opNOT  = Iop_Not16;
         opXOR  = Iop_Xor16;
         opCMP  = Iop_CmpEQ16;
         top    = mkU16(0xFFFF);
         break;
      case Ity_I32:
         opOR   = Iop_Or32;
         opDIFD = Iop_And32;
         opUIFU = Iop_Or32;
         opNOT  = Iop_Not32;
         opXOR  = Iop_Xor32;
         opCMP  = Iop_CmpEQ32;
         top    = mkU32(0xFFFFFFFF);
         break;
      case Ity_I64:
         opOR   = Iop_Or64;
         opDIFD = Iop_And64;
         opUIFU = Iop_Or64;
         opNOT  = Iop_Not64;
         opXOR  = Iop_Xor64;
         opCMP  = Iop_CmpEQ64;
         top    = mkU64(0xFFFFFFFFFFFFFFFFULL);
         break;
      default:
         VG_(tool_panic)("expensiveCmpEQorNE");
   }

   naive
      = mkPCastTo(mce,ty,
                  assignNew('V', mce, ty, binop(opUIFU, vxx, vyy)));

   vec
      = assignNew(
           'V', mce,ty,
           binop( opOR,
                  assignNew('V', mce,ty, binop(opOR, vxx, vyy)),
                  assignNew(
                     'V', mce,ty,
                     unop( opNOT,
                           assignNew('V', mce,ty, binop(opXOR, xx, yy))))));

   improvement_term
      = mkPCastTo( mce,ty,
                   assignNew('V', mce,Ity_I1, binop(opCMP, vec, top)));

   improved
      = assignNew( 'V', mce,ty, binop(opDIFD, naive, improvement_term) );

   final_cast
      = mkPCastTo( mce, Ity_I1, improved );

   return final_cast;
}


/* --------- Semi-accurate interpretation of CmpORD. --------- */
static Bool isZeroU32 ( IRAtom* e ) //886
{
   return
      toBool( e->tag == Iex_Const
              && e->Iex.Const.con->tag == Ico_U32
              && e->Iex.Const.con->Ico.U32 == 0 );
}

static Bool isZeroU64 ( IRAtom* e )
{
   return
      toBool( e->tag == Iex_Const
              && e->Iex.Const.con->tag == Ico_U64
              && e->Iex.Const.con->Ico.U64 == 0 );
}

static IRAtom* doCmpORD ( MCEnv*  mce,
                          IROp    cmp_op,
                          IRAtom* xxhash, IRAtom* yyhash,
                          IRAtom* xx,     IRAtom* yy )
{
   Bool   m64    = cmp_op == Iop_CmpORD64S || cmp_op == Iop_CmpORD64U;
   Bool   syned  = cmp_op == Iop_CmpORD64S || cmp_op == Iop_CmpORD32S;
   IROp   opOR   = m64 ? Iop_Or64  : Iop_Or32;
   IROp   opAND  = m64 ? Iop_And64 : Iop_And32;
   IROp   opSHL  = m64 ? Iop_Shl64 : Iop_Shl32;
   IROp   opSHR  = m64 ? Iop_Shr64 : Iop_Shr32;
   IRType ty     = m64 ? Ity_I64   : Ity_I32;
   Int    width  = m64 ? 64        : 32;

   Bool (*isZero)(IRAtom*) = m64 ? isZeroU64 : isZeroU32;

   IRAtom* threeLeft1 = NULL;
   IRAtom* sevenLeft1 = NULL;

   tl_assert(isShadowAtom(mce,xxhash));
   tl_assert(isShadowAtom(mce,yyhash));
   tl_assert(isOriginalAtom(mce,xx));
   tl_assert(isOriginalAtom(mce,yy));
   tl_assert(sameKindedAtoms(xxhash,xx));
   tl_assert(sameKindedAtoms(yyhash,yy));
   tl_assert(cmp_op == Iop_CmpORD32S || cmp_op == Iop_CmpORD32U
             || cmp_op == Iop_CmpORD64S || cmp_op == Iop_CmpORD64U);

   if (0) {
      ppIROp(cmp_op); VG_(printf)(" ");
      ppIRExpr(xx); VG_(printf)(" "); ppIRExpr( yy ); VG_(printf)("\n");
   }

   if (syned && isZero(yy)) {
      /* fancy interpretation */
      /* if yy is zero, then it must be fully defined (zero#). */
      tl_assert(isZero(yyhash));
      threeLeft1 = m64 ? mkU64(3<<1) : mkU32(3<<1);
      return
         binop(
            opOR,
            assignNew(
               'V', mce,ty,
               binop(
                  opAND,
                  mkPCastTo(mce,ty, xxhash),
                  threeLeft1
               )),
            assignNew(
               'V', mce,ty,
               binop(
                  opSHL,
                  assignNew(
                     'V', mce,ty,
                     binop(opSHR, xxhash, mkU8(width-1))),
                  mkU8(3)
               ))
         );
   } else {
      /* standard interpretation */
      sevenLeft1 = m64 ? mkU64(7<<1) : mkU32(7<<1);
      return
         binop(
            opAND,
            mkPCastTo( mce,ty,
                       mkUifU(mce,ty, xxhash,yyhash)),
            sevenLeft1
         );
   }
}


/* Set the annotations on a dirty helper to indicate that the stack
   pointer and instruction pointers might be read.  This is the
   behaviour of all 'emit-a-complaint' style functions we might
   call. */

static void setHelperAnns ( MCEnv* mce, IRDirty* di ) { //970
   di->nFxState = 2;
   di->fxState[0].fx     = Ifx_Read;
   di->fxState[0].offset = mce->layout->offset_SP;
   di->fxState[0].size   = mce->layout->sizeof_SP;
   di->fxState[0].nRepeats  = 0;
   di->fxState[0].repeatLen = 0;
   di->fxState[1].fx     = Ifx_Read;
   di->fxState[1].offset = mce->layout->offset_IP;
   di->fxState[1].size   = mce->layout->sizeof_IP;
   di->fxState[1].nRepeats  = 0;
   di->fxState[1].repeatLen = 0;
}

// Taintgrind: Forward decls
Int extract_IRAtom( IRAtom* atom );
Int extract_IRConst( IRConst* con );
ULong extract_IRConst64( IRConst* con );

// Convert to Dirty helper arg type IRExpr*
static IRExpr* convert_Value( MCEnv* mce, IRAtom* atom );

// The IRStmt types
IRDirty* create_dirty_PUT( MCEnv* mce, IRStmt *clone, Int offset, IRExpr* data );
IRDirty* create_dirty_PUTI( MCEnv* mce, IRRegArray* descr, IRExpr* ix, Int bias, IRExpr* data );
IRDirty* create_dirty_STORE( MCEnv* mce, IRStmt *clone, IREndness end,
                             IRTemp resSC, IRExpr* addr,
                             IRExpr* data );
IRDirty* create_dirty_CAS( MCEnv* mce, IRCAS* details );
IRDirty* create_dirty_DIRTY( MCEnv* mce, IRDirty* details );
IRDirty* create_dirty_EXIT( MCEnv* mce, IRStmt *clone, IRExpr* guard, IRJumpKind jk, IRConst* dst );
IRDirty* create_dirty_NEXT( MCEnv* mce, IRExpr* next );

// The IRExpr types with the destination tmp, dst, as an additional argument
IRDirty* create_dirty_WRTMP( MCEnv* mce, IRStmt *clone, IRTemp dst, IRExpr* data );
IRDirty *create_dirty_WRTMP_const( MCEnv *mce, IRStmt *clone, IRTemp tmp );
IRDirty* create_dirty_GET( MCEnv* mce, IRStmt *clone, IRTemp dst, Int offset, IRType ty );
IRDirty* create_dirty_GETI( MCEnv* mce, IRStmt *clone, IRTemp dst, IRRegArray* descr, IRExpr* ix, Int bias );
IRDirty* create_dirty_RDTMP( MCEnv* mce, IRStmt *clone, IRTemp dst, IRTemp tmp );
IRDirty* create_dirty_QOP( MCEnv* mce, IRStmt *clone, IRTemp dst, IROp op,
                           IRExpr* arg1, IRExpr* arg2, IRExpr* arg3, IRExpr* arg4 );
IRDirty* create_dirty_TRIOP( MCEnv* mce, IRStmt *clone, IRTemp dst, IROp op, 
                             IRExpr* arg1, IRExpr* arg2, IRExpr* arg3 );
IRDirty* create_dirty_BINOP( MCEnv* mce, IRStmt *clone, IRTemp dst, IROp op, IRExpr* arg1, IRExpr* arg2 );
IRDirty* create_dirty_UNOP( MCEnv* mce, IRStmt *clone, IRTemp dst, IROp op, IRExpr* arg );
IRDirty* create_dirty_LOAD( MCEnv* mce, IRStmt *clone, IRTemp tmp, Bool isLL, IREndness end,
                            IRType ty, IRExpr* addr );
IRDirty* create_dirty_CCALL( MCEnv* mce, IRStmt *clone, IRTemp tmp, 
                             IRCallee* cee, IRType retty, IRExpr** args );
IRDirty* create_dirty_ITE( MCEnv* mce, IRStmt *clone, IRTemp tmp, 
                           IRExpr* cond, IRExpr* iftrue, IRExpr* iffalse );
IRDirty* create_dirty_from_dirty( IRDirty* di_old );

/* Check the supplied **original** atom for undefinedness, and emit
   a complaint if so.  Once that happens, mark it as defined.  This is
   possible because the atom is either a tmp or literal.  If it's a
   tmp, it will be shadowed by a tmp, and so we can set the shadow to
   be defined.  In fact as mentioned above, we will have to allocate a
   new tmp to carry the new 'defined' shadow value, and update the
   original->tmp mapping accordingly; we cannot simply assign a new
   value to an existing shadow tmp as this breaks SSAness -- resulting
   in the post-instrumentation sanity checker spluttering in disapproval.
*/
/* Taintgrind: Since we want to continue taint propagation after the check,
   we skip the creation of a new shadow.
   The IRDirty statement di2 is created by the respective function so
   we know which IRStmt is currently being checked. This is for the
   purpose of pretty printing the IRStmt during run-time.
*/
static void complainIfTainted ( MCEnv* mce, IRAtom* atom, IRDirty* di2 )
{
//   IRAtom*  vatom;
//   IRAtom*  cond;
//   IRType   ty;

   /* Since the original expression is atomic, there's no duplicated
      work generated by making multiple V-expressions for it.  So we
      don't really care about the possibility that someone else may
      also create a V-interpretion for it. */
//   tl_assert(isOriginalAtom(mce, atom));
//   vatom = atom2vbits( mce, atom );
//   tl_assert(isShadowAtom(mce, vatom));
//   tl_assert(sameKindedAtoms(atom, vatom));

   // Taintgrind: mkPCastTo can't handle Ity_F32, Ity_F64, Ity_V128 types
 /*  if( typeOfIRExpr(mce->sb->tyenv, vatom) == Ity_F32 ||
       typeOfIRExpr(mce->sb->tyenv, vatom) == Ity_F32 ||
       typeOfIRExpr(mce->sb->tyenv, vatom) == Ity_V128 ){
     // VG_(printf)("\nTaintgrind: Can't handle IEEE floats/doubles,");
     // VG_(printf)(" or 128-bit SIMD operations atm.\n");
     // VG_(printf)("atom: "); ppIRExpr(atom); VG_(printf)("\n");
     // VG_(printf)("di2: ");  ppIRDirty(di2); VG_(printf)("\n");
      return;
   }
*/
//   cond = mkPCastTo( mce, Ity_I1, vatom );
   /* cond will be 0 if all defined, and 1 if any not defined. */

   if( !di2 ) return;

//   di2->guard = cond;
   // Taintgrind: unconditional
//   di2->guard = NULL;
   setHelperAnns( mce, di2 );
   stmt( 'V', mce, IRStmt_Dirty(di2));

   /* Set the shadow tmp to be defined.  First, update the
      orig->shadow tmp mapping to reflect the fact that this shadow is
      getting a new value. */
//   ty = typeOfIRExpr(mce->sb->tyenv, vatom);

//   tl_assert(isIRAtom(vatom));
   /* sameKindedAtoms ... */
/*   if (vatom->tag == Iex_RdTmp &&
       ty    != Ity_I8    &&
       ty    != Ity_I16   &&
       ty    != Ity_I32   &&
       ty    != Ity_I64  ) {
      tl_assert(atom->tag == Iex_RdTmp);
      newShadowTmpV(mce, atom->Iex.RdTmp.tmp);
      assign('V', mce, findShadowTmpV(mce, atom->Iex.RdTmp.tmp),
                       definedOfType(ty));
   }*/
}



/*------------------------------------------------------------*/
/*--- Shadowing PUTs/GETs, and indexed variants thereof    ---*/
/*------------------------------------------------------------*/

/* Examine the always-defined sections declared in layout to see if
   the (offset,size) section is within one.  Note, is is an error to
   partially fall into such a region: (offset,size) should either be
   completely in such a region or completely not-in such a region.
*/
static Bool isAlwaysDefd ( MCEnv* mce, Int offset, Int size ) //1159
{
   Int minoffD, maxoffD, i;
   Int minoff = offset;
   Int maxoff = minoff + size - 1;
   tl_assert((minoff & ~0xFFFF) == 0);
   tl_assert((maxoff & ~0xFFFF) == 0);

   for (i = 0; i < mce->layout->n_alwaysDefd; i++) {
      minoffD = mce->layout->alwaysDefd[i].offset;
      maxoffD = minoffD + mce->layout->alwaysDefd[i].size - 1;
      tl_assert((minoffD & ~0xFFFF) == 0);
      tl_assert((maxoffD & ~0xFFFF) == 0);

      if (maxoff < minoffD || maxoffD < minoff)
         continue; /* no overlap */
      if (minoff >= minoffD && maxoff <= maxoffD)
         return True; /* completely contained in an always-defd section */

      VG_(tool_panic)("tnt_translate.c: isAlwaysDefd:partial overlap");
   }
   return False; /* could not find any containing section */
}

/* Generate into bb suitable actions to shadow this Put.  If the state
   slice is marked 'always defined', do nothing.  Otherwise, write the
   supplied V bits to the shadow state.  We can pass in either an
   original atom or a V-atom, but not both.  In the former case the
   relevant V-bits are then generated from the original.
*/
static
void do_shadow_PUT ( MCEnv* mce, IRStmt *clone, Int offset,
                     IRAtom* atom, IRAtom* vatom, IRExpr *guard )
{
   IRType ty;

   // Don't do shadow PUTs if we're not doing undefined value checking.
   // Their absence lets Vex's optimiser remove all the shadow computation
   // that they depend on, which includes GETs of the shadow registers.
   // Taintgrind: We're doing undefined value checking no matter what
//   if (TNT_(clo_tnt_level) == 1)
//      return;

   if (atom) {
      tl_assert(!vatom);
      tl_assert(isOriginalAtom(mce, atom));
      vatom = atom2vbits( mce, atom );
   } else {
      tl_assert(vatom);
      tl_assert(isShadowAtom(mce, vatom));
   }

   ty = typeOfIRExpr(mce->sb->tyenv, vatom);
   tl_assert(ty != Ity_I1);

   // Taintgrind: Let's keep the vbits regardless
//   if (isAlwaysDefd(mce, offset, sizeofIRType(ty))) {
      /* later: no ... */
      /* emit code to emit a complaint if any of the vbits are 1. */
      /* complainIfTainted(mce, atom); */
//   } else {
      /* Do a plain shadow Put. */
      if (guard) {
         /* If the guard expression evaluates to false we simply Put the value
            that is already stored in the guest state slot */
         IRAtom *cond, *iffalse;

         cond    = assignNew('V', mce, Ity_I1, guard);
         iffalse = assignNew('V', mce, ty,
                             IRExpr_Get(offset + mce->layout->total_sizeB, ty));
         vatom   = assignNew('V', mce, ty, IRExpr_ITE(cond, vatom, iffalse));
      }
      stmt( 'V', mce, IRStmt_Put( offset + mce->layout->total_sizeB, vatom ) );

      // Taintgrind: include this check only if we're not tracking critical ins
      // For why total_sizeB is added to offset, 
      // see VEX/pub/libvex.h "A note about guest state layout"
      if( atom && clone && !TNT_(clo_critical_ins_only) ){
         IRDirty* di2 = create_dirty_PUT( mce, clone, offset, atom );
         if ( di2 ) complainIfTainted( mce, NULL /*atom*/, di2 ); 
      }
//   }
}

/* Return an expression which contains the V bits corresponding to the
   given PUTI (passed in in pieces).
*/
static
void do_shadow_PUTI ( MCEnv* mce, IRPutI *puti )
//                      IRRegArray* descr,
//                      IRAtom* ix, Int bias, IRAtom* atom )
{
   IRAtom* vatom;
   IRType  ty, tyS;
   //Int     arrSize;
   IRRegArray* descr = puti->descr;
   IRAtom*     ix    = puti->ix;
   Int         bias  = puti->bias;
   IRAtom*     atom  = puti->data;
   IRDirty* di2;

   // Don't do shadow PUTIs if we're not doing undefined value checking.
   // Their absence lets Vex's optimiser remove all the shadow computation
   // that they depend on, which includes GETIs of the shadow registers.
   // Taintgrind: Check regardless
//   if (TNT_(clo_tnt_level) == 1)
//      return;

   tl_assert(isOriginalAtom(mce,atom));
   vatom = atom2vbits( mce, atom );
   tl_assert(sameKindedAtoms(atom, vatom));
   ty   = descr->elemTy;
   tyS  = shadowTypeV(ty);
   //arrSize = descr->nElems * sizeofIRType(ty);
   tl_assert(ty != Ity_I1);
   tl_assert(isOriginalAtom(mce,ix));

   // Taintgrind:
   di2 = create_dirty_PUTI( mce, descr, ix, bias, atom );
   complainIfTainted(mce, ix, di2);

   // Taintgrind: Let's keep the vbits regardless
//   if (isAlwaysDefd(mce, descr->base, arrSize)) {
      /* later: no ... */
      /* emit code to emit a complaint if any of the vbits are 1. */
      /* complainIfUndefined(mce, atom); */
//   } else {
      /* Do a cloned version of the Put that refers to the shadow
         area. */
      IRRegArray* new_descr
         = mkIRRegArray( descr->base + mce->layout->total_sizeB,
                         tyS, descr->nElems);
      stmt( 'V', mce, IRStmt_PutI( mkIRPutI(new_descr, ix, bias, vatom) ));

//   }
}


/* Return an expression which contains the V bits corresponding to the
   given GET (passed in in pieces).
*/
static
IRExpr* shadow_GET ( MCEnv* mce, Int offset, IRType ty ) //1270
{
   IRType tyS = shadowTypeV(ty);
   tl_assert(ty != Ity_I1);

   // Taintgrind: Let's keep the vbits regardless
//   if (isAlwaysDefd(mce, offset, sizeofIRType(ty))) {
      /* Always defined, return all zeroes of the relevant type */
//      return definedOfType(tyS);
//   } else {
      /* return a cloned version of the Get that refers to the shadow
         area. */
      /* FIXME: this isn't an atom! */
      return IRExpr_Get( offset + mce->layout->total_sizeB, tyS );
//   }
}


/* Return an expression which contains the V bits corresponding to the
   given GETI (passed in in pieces).
*/
static
IRExpr* shadow_GETI ( MCEnv* mce,
                      IRRegArray* descr, IRAtom* ix, Int bias )
{
   IRType ty   = descr->elemTy;
   IRType tyS  = shadowTypeV(ty);
//   Int arrSize = descr->nElems * sizeofIRType(ty);

   tl_assert(ty != Ity_I1);
   tl_assert(isOriginalAtom(mce,ix));

   // Taintgrind: Let's keep the vbits regardless
//   if (isAlwaysDefd(mce, descr->base, arrSize)) {
      /* Always defined, return all zeroes of the relevant type */
//      return definedOfType(tyS);
//   } else {
      /* return a cloned version of the Get that refers to the shadow
         area. */
      IRRegArray* new_descr
         = mkIRRegArray( descr->base + mce->layout->total_sizeB,
                         tyS, descr->nElems);
      return IRExpr_GetI( new_descr, ix, bias );
//   }
}


/*------------------------------------------------------------*/
/*--- Generating approximations for unknown operations,    ---*/
/*--- using lazy-propagate semantics                       ---*/
/*------------------------------------------------------------*/

/* Lazy propagation of undefinedness from two values, resulting in the
   specified shadow type.
*/
static
IRAtom* mkLazy2 ( MCEnv* mce, IRType finalVty, IRAtom* va1, IRAtom* va2 ) //1322
{
   IRAtom* at;
   IRType t1 = typeOfIRExpr(mce->sb->tyenv, va1);
   IRType t2 = typeOfIRExpr(mce->sb->tyenv, va2);
   tl_assert(isShadowAtom(mce,va1));
   tl_assert(isShadowAtom(mce,va2));

   /* The general case is inefficient because PCast is an expensive
      operation.  Here are some special cases which use PCast only
      once rather than twice. */

   /* I64 x I64 -> I64 */
   if (t1 == Ity_I64 && t2 == Ity_I64 && finalVty == Ity_I64) {
      if (0) VG_(printf)("mkLazy2: I64 x I64 -> I64\n");
      at = mkUifU(mce, Ity_I64, va1, va2);
      at = mkPCastTo(mce, Ity_I64, at);
      return at;
   }

   /* I64 x I64 -> I32 */
   if (t1 == Ity_I64 && t2 == Ity_I64 && finalVty == Ity_I32) {
      if (0) VG_(printf)("mkLazy2: I64 x I64 -> I32\n");
      at = mkUifU(mce, Ity_I64, va1, va2);
      at = mkPCastTo(mce, Ity_I32, at);
      return at;
   }

   if (0) {
      VG_(printf)("mkLazy2 ");
      ppIRType(t1);
      VG_(printf)("_");
      ppIRType(t2);
      VG_(printf)("_");
      ppIRType(finalVty);
      VG_(printf)("\n");
   }

   /* General case: force everything via 32-bit intermediaries. */
   at = mkPCastTo(mce, Ity_I32, va1);
   at = mkUifU(mce, Ity_I32, at, mkPCastTo(mce, Ity_I32, va2));
   at = mkPCastTo(mce, finalVty, at);
   return at;
}


/* 3-arg version of the above. */
static
IRAtom* mkLazy3 ( MCEnv* mce, IRType finalVty,
                  IRAtom* va1, IRAtom* va2, IRAtom* va3 )
{
   IRAtom* at;
   IRType t1 = typeOfIRExpr(mce->sb->tyenv, va1);
   IRType t2 = typeOfIRExpr(mce->sb->tyenv, va2);
   IRType t3 = typeOfIRExpr(mce->sb->tyenv, va3);
   tl_assert(isShadowAtom(mce,va1));
   tl_assert(isShadowAtom(mce,va2));
   tl_assert(isShadowAtom(mce,va3));

   /* The general case is inefficient because PCast is an expensive
      operation.  Here are some special cases which use PCast only
      twice rather than three times. */

   /* I32 x I64 x I64 -> I64 */
   /* Standard FP idiom: rm x FParg1 x FParg2 -> FPresult */
   if (t1 == Ity_I32 && t2 == Ity_I64 && t3 == Ity_I64
       && finalVty == Ity_I64) {
      if (0) VG_(printf)("mkLazy3: I32 x I64 x I64 -> I64\n");
      /* Widen 1st arg to I64.  Since 1st arg is typically a rounding
         mode indication which is fully defined, this should get
         folded out later. */
      at = mkPCastTo(mce, Ity_I64, va1);
      /* Now fold in 2nd and 3rd args. */
      at = mkUifU(mce, Ity_I64, at, va2);
      at = mkUifU(mce, Ity_I64, at, va3);
      /* and PCast once again. */
      at = mkPCastTo(mce, Ity_I64, at);
      return at;
   }

   /* I32 x I8 x I64 -> I64 */
   if (t1 == Ity_I32 && t2 == Ity_I8 && t3 == Ity_I64
       && finalVty == Ity_I64) {
      if (0) VG_(printf)("mkLazy3: I32 x I8 x I64 -> I64\n");
      /* Widen 1st and 2nd args to I64.  Since 1st arg is typically a
       * rounding mode indication which is fully defined, this should
       * get folded out later.
      */
      IRAtom* at1 = mkPCastTo(mce, Ity_I64, va1);
      IRAtom* at2 = mkPCastTo(mce, Ity_I64, va2);
      at = mkUifU(mce, Ity_I64, at1, at2);  // UifU(PCast(va1), PCast(va2))
      at = mkUifU(mce, Ity_I64, at, va3);
      /* and PCast once again. */
      at = mkPCastTo(mce, Ity_I64, at);
      return at;
   }

   /* I32 x I64 x I64 -> I32 */
   if (t1 == Ity_I32 && t2 == Ity_I64 && t3 == Ity_I64
       && finalVty == Ity_I32) {
      if (0) VG_(printf)("mkLazy3: I32 x I64 x I64 -> I64\n");
      at = mkPCastTo(mce, Ity_I64, va1);
      at = mkUifU(mce, Ity_I64, at, va2);
      at = mkUifU(mce, Ity_I64, at, va3);
      at = mkPCastTo(mce, Ity_I32, at);
      return at;
   }

   /* I32 x I32 x I32 -> I32 */
   /* 32-bit FP idiom, as (eg) happens on ARM */
   if (t1 == Ity_I32 && t2 == Ity_I32 && t3 == Ity_I32
       && finalVty == Ity_I32) {
      if (0) VG_(printf)("mkLazy3: I32 x I32 x I32 -> I32\n");
      at = va1;
      at = mkUifU(mce, Ity_I32, at, va2);
      at = mkUifU(mce, Ity_I32, at, va3);
      at = mkPCastTo(mce, Ity_I32, at);
      return at;
   }

   /* I32 x I128 x I128 -> I128 */
   /* Standard FP idiom: rm x FParg1 x FParg2 -> FPresult */
   if (t1 == Ity_I32 && t2 == Ity_I128 && t3 == Ity_I128
       && finalVty == Ity_I128) {
      if (0) VG_(printf)("mkLazy3: I32 x I128 x I128 -> I128\n");
      /* Widen 1st arg to I128.  Since 1st arg is typically a rounding
         mode indication which is fully defined, this should get
         folded out later. */
      at = mkPCastTo(mce, Ity_I128, va1);
      /* Now fold in 2nd and 3rd args. */
      at = mkUifU(mce, Ity_I128, at, va2);
      at = mkUifU(mce, Ity_I128, at, va3);
      /* and PCast once again. */
      at = mkPCastTo(mce, Ity_I128, at);
      return at;
   }

   /* I32 x I8 x I128 -> I128 */
   /* Standard FP idiom: rm x FParg1 x FParg2 -> FPresult */
   if (t1 == Ity_I32 && t2 == Ity_I8 && t3 == Ity_I128
       && finalVty == Ity_I128) {
      if (0) VG_(printf)("mkLazy3: I32 x I8 x I128 -> I128\n");
      /* Use I64 as an intermediate type, which means PCasting all 3
         args to I64 to start with. 1st arg is typically a rounding
         mode indication which is fully defined, so we hope that it
         will get folded out later. */
      IRAtom* at1 = mkPCastTo(mce, Ity_I64, va1);
      IRAtom* at2 = mkPCastTo(mce, Ity_I64, va2);
      IRAtom* at3 = mkPCastTo(mce, Ity_I64, va3);
      /* Now UifU all three together. */
      at = mkUifU(mce, Ity_I64, at1, at2);  // UifU(PCast(va1), PCast(va2))
      at = mkUifU(mce, Ity_I64, at, at3);   // ... `UifU` PCast(va3)
      /* and PCast once again. */
      at = mkPCastTo(mce, Ity_I128, at);
      return at;
   }
   if (1) {
      VG_(printf)("mkLazy3: ");
      ppIRType(t1);
      VG_(printf)(" x ");
      ppIRType(t2);
      VG_(printf)(" x ");
      ppIRType(t3);
      VG_(printf)(" -> ");
      ppIRType(finalVty);
      VG_(printf)("\n");
   }

   tl_assert(0);
   /* General case: force everything via 32-bit intermediaries. */
   /*
   at = mkPCastTo(mce, Ity_I32, va1);
   at = mkUifU(mce, Ity_I32, at, mkPCastTo(mce, Ity_I32, va2));
   at = mkUifU(mce, Ity_I32, at, mkPCastTo(mce, Ity_I32, va3));
   at = mkPCastTo(mce, finalVty, at);
   return at;
   */
}


/* 4-arg version of the above. */
static
IRAtom* mkLazy4 ( MCEnv* mce, IRType finalVty,
                  IRAtom* va1, IRAtom* va2, IRAtom* va3, IRAtom* va4 )
{
   IRAtom* at;
   IRType t1 = typeOfIRExpr(mce->sb->tyenv, va1);
   IRType t2 = typeOfIRExpr(mce->sb->tyenv, va2);
   IRType t3 = typeOfIRExpr(mce->sb->tyenv, va3);
   IRType t4 = typeOfIRExpr(mce->sb->tyenv, va4);
   tl_assert(isShadowAtom(mce,va1));
   tl_assert(isShadowAtom(mce,va2));
   tl_assert(isShadowAtom(mce,va3));
   tl_assert(isShadowAtom(mce,va4));

   /* The general case is inefficient because PCast is an expensive
      operation.  Here are some special cases which use PCast only
      twice rather than three times. */

   /* I32 x I64 x I64 x I64 -> I64 */
   /* Standard FP idiom: rm x FParg1 x FParg2 x FParg3 -> FPresult */
   if (t1 == Ity_I32 && t2 == Ity_I64 && t3 == Ity_I64 && t4 == Ity_I64
       && finalVty == Ity_I64) {
      if (0) VG_(printf)("mkLazy4: I32 x I64 x I64 x I64 -> I64\n");
      /* Widen 1st arg to I64.  Since 1st arg is typically a rounding
         mode indication which is fully defined, this should get
         folded out later. */
      at = mkPCastTo(mce, Ity_I64, va1);
      /* Now fold in 2nd, 3rd, 4th args. */
      at = mkUifU(mce, Ity_I64, at, va2);
      at = mkUifU(mce, Ity_I64, at, va3);
      at = mkUifU(mce, Ity_I64, at, va4);
      /* and PCast once again. */
      at = mkPCastTo(mce, Ity_I64, at);
      return at;
   }
   /* I32 x I32 x I32 x I32 -> I32 */
   /* Standard FP idiom: rm x FParg1 x FParg2 x FParg3 -> FPresult */
   if (t1 == Ity_I32 && t2 == Ity_I32 && t3 == Ity_I32 && t4 == Ity_I32
       && finalVty == Ity_I32) {
      if (0) VG_(printf)("mkLazy4: I32 x I32 x I32 x I32 -> I32\n");
      at = va1;
      /* Now fold in 2nd, 3rd, 4th args. */
      at = mkUifU(mce, Ity_I32, at, va2);
      at = mkUifU(mce, Ity_I32, at, va3);
      at = mkUifU(mce, Ity_I32, at, va4);
      at = mkPCastTo(mce, Ity_I32, at);
      return at;
   }

   if (1) {
      VG_(printf)("mkLazy4: ");
      ppIRType(t1);
      VG_(printf)(" x ");
      ppIRType(t2);
      VG_(printf)(" x ");
      ppIRType(t3);
      VG_(printf)(" x ");
      ppIRType(t4);
      VG_(printf)(" -> ");
      ppIRType(finalVty);
      VG_(printf)("\n");
   }

   tl_assert(0);
}


/* Do the lazy propagation game from a null-terminated vector of
   atoms.  This is presumably the arguments to a helper call, so the
   IRCallee info is also supplied in order that we can know which
   arguments should be ignored (via the .mcx_mask field).
*/
static
IRAtom* mkLazyN ( MCEnv* mce,
                  IRAtom** exprvec, IRType finalVtype, IRCallee* cee )
{
   Int     i;
   IRAtom* here;
   IRAtom* curr;
   IRType  mergeTy;
   IRType  mergeTy64 = True;

   /* Decide on the type of the merge intermediary.  If all relevant
      args are I64, then it's I64.  In all other circumstances, use
      I32. */
   for (i = 0; exprvec[i]; i++) {
      tl_assert(i < 32);
      tl_assert(isOriginalAtom(mce, exprvec[i]));
      if (cee->mcx_mask & (1<<i))
         continue;
      if (typeOfIRExpr(mce->sb->tyenv, exprvec[i]) != Ity_I64)
         mergeTy64 = False;
   }

   mergeTy = mergeTy64  ? Ity_I64  : Ity_I32;
   curr    = definedOfType(mergeTy);

   for (i = 0; exprvec[i]; i++) {
      tl_assert(i < 32);
      tl_assert(isOriginalAtom(mce, exprvec[i]));
      /* Only take notice of this arg if the callee's mc-exclusion
         mask does not say it is to be excluded. */
      if (cee->mcx_mask & (1<<i)) {
         /* the arg is to be excluded from definedness checking.  Do
            nothing. */
         if (0) VG_(printf)("excluding %s(%d)\n", cee->name, i);
      } else {
         /* calculate the arg's definedness, and pessimistically merge
            it in. */
         here = mkPCastTo( mce, mergeTy, atom2vbits(mce, exprvec[i]) );
         curr = mergeTy64
                   ? mkUifU64(mce, here, curr)
                   : mkUifU32(mce, here, curr);
      }
   }
   return mkPCastTo(mce, finalVtype, curr );
}


/*------------------------------------------------------------*/
/*--- Generating expensive sequences for exact carry-chain ---*/
/*--- propagation in add/sub and related operations.       ---*/
/*------------------------------------------------------------*/

static
IRAtom* expensiveAddSub ( MCEnv*  mce,
                          Bool    add,
                          IRType  ty,
                          IRAtom* qaa, IRAtom* qbb,
                          IRAtom* aa,  IRAtom* bb )
{
   IRAtom *a_min, *b_min, *a_max, *b_max;
   IROp   opAND, opOR, opXOR, opNOT, opADD, opSUB;

   tl_assert(isShadowAtom(mce,qaa));
   tl_assert(isShadowAtom(mce,qbb));
   tl_assert(isOriginalAtom(mce,aa));
   tl_assert(isOriginalAtom(mce,bb));
   tl_assert(sameKindedAtoms(qaa,aa));
   tl_assert(sameKindedAtoms(qbb,bb));

   switch (ty) {
      case Ity_I32:
         opAND = Iop_And32;
         opOR  = Iop_Or32;
         opXOR = Iop_Xor32;
         opNOT = Iop_Not32;
         opADD = Iop_Add32;
         opSUB = Iop_Sub32;
         break;
      case Ity_I64:
         opAND = Iop_And64;
         opOR  = Iop_Or64;
         opXOR = Iop_Xor64;
         opNOT = Iop_Not64;
         opADD = Iop_Add64;
         opSUB = Iop_Sub64;
         break;
      default:
         VG_(tool_panic)("expensiveAddSub");
   }

   // a_min = aa & ~qaa
   a_min = assignNew('V', mce,ty,
                     binop(opAND, aa,
                                  assignNew('V', mce,ty, unop(opNOT, qaa))));

   // b_min = bb & ~qbb
   b_min = assignNew('V', mce,ty,
                     binop(opAND, bb,
                                  assignNew('V', mce,ty, unop(opNOT, qbb))));

   // a_max = aa | qaa
   a_max = assignNew('V', mce,ty, binop(opOR, aa, qaa));

   // b_max = bb | qbb
   b_max = assignNew('V', mce,ty, binop(opOR, bb, qbb));

   if (add) {
      // result = (qaa | qbb) | ((a_min + b_min) ^ (a_max + b_max))
      return
      assignNew('V', mce,ty,
         binop( opOR,
                assignNew('V', mce,ty, binop(opOR, qaa, qbb)),
                assignNew('V', mce,ty,
                   binop( opXOR,
                          assignNew('V', mce,ty, binop(opADD, a_min, b_min)),
                          assignNew('V', mce,ty, binop(opADD, a_max, b_max))
                   )
                )
         )
      );
   } else {
      // result = (qaa | qbb) | ((a_min - b_max) ^ (a_max + b_min))
      return
      assignNew('V', mce,ty,
         binop( opOR,
                assignNew('V', mce,ty, binop(opOR, qaa, qbb)),
                assignNew('V', mce,ty,
                   binop( opXOR,
                          assignNew('V', mce,ty, binop(opSUB, a_min, b_max)),
                          assignNew('V', mce,ty, binop(opSUB, a_max, b_min))
                   )
                )
         )
      );
   }

}

static
IRAtom* expensiveCountTrailingZeroes ( MCEnv* mce, IROp czop,
                                       IRAtom* atom, IRAtom* vatom )
{
   IRType ty;
   IROp xorOp, subOp, andOp;
   IRExpr *one;
   IRAtom *improver, *improved;
   tl_assert(isShadowAtom(mce,vatom));
   tl_assert(isOriginalAtom(mce,atom));
   tl_assert(sameKindedAtoms(atom,vatom));

   switch (czop) {
      case Iop_Ctz32:
         ty = Ity_I32;
         xorOp = Iop_Xor32;
         subOp = Iop_Sub32;
         andOp = Iop_And32;
         one = mkU32(1);
         break;
      case Iop_Ctz64:
         ty = Ity_I64;
         xorOp = Iop_Xor64;
         subOp = Iop_Sub64;
         andOp = Iop_And64;
         one = mkU64(1);
         break;
      default:
         ppIROp(czop);
         VG_(tool_panic)("memcheck:expensiveCountTrailingZeroes");
   }

   // improver = atom ^ (atom - 1)
   //
   // That is, improver has its low ctz(atom) bits equal to one;
   // higher bits (if any) equal to zero.
   improver = assignNew('V', mce,ty,
                        binop(xorOp,
                              atom,
                              assignNew('V', mce, ty,
                                        binop(subOp, atom, one))));

   // improved = vatom & improver
   //
   // That is, treat any V bits above the first ctz(atom) bits as
   // "defined".
   improved = assignNew('V', mce, ty,
                        binop(andOp, vatom, improver));

   // Return pessimizing cast of improved.
   return mkPCastTo(mce, ty, improved);
}


/*------------------------------------------------------------*/
/*--- Scalar shifts.                                       ---*/
/*------------------------------------------------------------*/
static IRAtom* scalarShift ( MCEnv*  mce,
                             IRType  ty,
                             IROp    original_op,
                             IRAtom* qaa, IRAtom* qbb,
                             IRAtom* aa,  IRAtom* bb )
{
   tl_assert(isShadowAtom(mce,qaa));
   tl_assert(isShadowAtom(mce,qbb));
   tl_assert(isOriginalAtom(mce,aa));
   tl_assert(isOriginalAtom(mce,bb));
   tl_assert(sameKindedAtoms(qaa,aa));
   tl_assert(sameKindedAtoms(qbb,bb));
   return
      assignNew(
         'V', mce, ty,
         mkUifU( mce, ty,
                 assignNew('V', mce, ty, binop(original_op, qaa, bb)),
                 mkPCastTo(mce, ty, qbb)
         )
   );
}


/*------------------------------------------------------------*/
/*--- Helpers for dealing with vector primops.             ---*/
/*------------------------------------------------------------*/

/* Vector pessimisation -- pessimise within each lane individually. */

static IRAtom* mkPCast8x16 ( MCEnv* mce, IRAtom* at ) //1688
{
   return assignNew('V', mce, Ity_V128, unop(Iop_CmpNEZ8x16, at));
}

static IRAtom* mkPCast16x8 ( MCEnv* mce, IRAtom* at )
{
   return assignNew('V', mce, Ity_V128, unop(Iop_CmpNEZ16x8, at));
}

static IRAtom* mkPCast32x4 ( MCEnv* mce, IRAtom* at )
{
   return assignNew('V', mce, Ity_V128, unop(Iop_CmpNEZ32x4, at));
}

static IRAtom* mkPCast64x2 ( MCEnv* mce, IRAtom* at )
{
   return assignNew('V', mce, Ity_V128, unop(Iop_CmpNEZ64x2, at));
}

static IRAtom* mkPCast64x4 ( MCEnv* mce, IRAtom* at )
{
   return assignNew('V', mce, Ity_V256, unop(Iop_CmpNEZ64x4, at));
}

static IRAtom* mkPCast32x8 ( MCEnv* mce, IRAtom* at )
{
   return assignNew('V', mce, Ity_V256, unop(Iop_CmpNEZ32x8, at));
}

static IRAtom* mkPCast32x2 ( MCEnv* mce, IRAtom* at )
{
   return assignNew('V', mce, Ity_I64, unop(Iop_CmpNEZ32x2, at));
}

static IRAtom* mkPCast16x16 ( MCEnv* mce, IRAtom* at )
{
   return assignNew('V', mce, Ity_V256, unop(Iop_CmpNEZ16x16, at));
}

static IRAtom* mkPCast16x4 ( MCEnv* mce, IRAtom* at )
{
   return assignNew('V', mce, Ity_I64, unop(Iop_CmpNEZ16x4, at));
}

static IRAtom* mkPCast8x32 ( MCEnv* mce, IRAtom* at )
{
   return assignNew('V', mce, Ity_V256, unop(Iop_CmpNEZ8x32, at));
}

static IRAtom* mkPCast8x8 ( MCEnv* mce, IRAtom* at )
{
   return assignNew('V', mce, Ity_I64, unop(Iop_CmpNEZ8x8, at));
}

static IRAtom* mkPCast16x2 ( MCEnv* mce, IRAtom* at )
{
   return assignNew('V', mce, Ity_I32, unop(Iop_CmpNEZ16x2, at));
}

static IRAtom* mkPCast8x4 ( MCEnv* mce, IRAtom* at )
{
   return assignNew('V', mce, Ity_I32, unop(Iop_CmpNEZ8x4, at));
}

/* Here's a simple scheme capable of handling ops derived from SSE1
   code and while only generating ops that can be efficiently
   implemented in SSE1. */
static
IRAtom* binary32Fx4 ( MCEnv* mce, IRAtom* vatomX, IRAtom* vatomY ) //1761
{
   IRAtom* at;
   tl_assert(isShadowAtom(mce, vatomX));
   tl_assert(isShadowAtom(mce, vatomY));
   at = mkUifUV128(mce, vatomX, vatomY);
   at = assignNew('V', mce, Ity_V128, mkPCast32x4(mce, at));
   return at;
}

static
IRAtom* unary32Fx4 ( MCEnv* mce, IRAtom* vatomX )
{
   IRAtom* at;
   tl_assert(isShadowAtom(mce, vatomX));
   at = assignNew('V', mce, Ity_V128, mkPCast32x4(mce, vatomX));
   return at;
}

static
IRAtom* binary32F0x4 ( MCEnv* mce, IRAtom* vatomX, IRAtom* vatomY )
{
   IRAtom* at;
   tl_assert(isShadowAtom(mce, vatomX));
   tl_assert(isShadowAtom(mce, vatomY));
   at = mkUifUV128(mce, vatomX, vatomY);
   at = assignNew('V', mce, Ity_I32, unop(Iop_V128to32, at));
   at = mkPCastTo(mce, Ity_I32, at);
   at = assignNew('V', mce, Ity_V128, binop(Iop_SetV128lo32, vatomX, at));
   return at;
}

static
IRAtom* unary32F0x4 ( MCEnv* mce, IRAtom* vatomX )
{
   IRAtom* at;
   tl_assert(isShadowAtom(mce, vatomX));
   at = assignNew('V', mce, Ity_I32, unop(Iop_V128to32, vatomX));
   at = mkPCastTo(mce, Ity_I32, at);
   at = assignNew('V', mce, Ity_V128, binop(Iop_SetV128lo32, vatomX, at));
   return at;
}

/* --- ... and ... 64Fx2 versions of the same ... --- */

static
IRAtom* binary64Fx2 ( MCEnv* mce, IRAtom* vatomX, IRAtom* vatomY ) //1807
{
   IRAtom* at;
   tl_assert(isShadowAtom(mce, vatomX));
   tl_assert(isShadowAtom(mce, vatomY));
   at = mkUifUV128(mce, vatomX, vatomY);
   at = assignNew('V', mce, Ity_V128, mkPCast64x2(mce, at));
   return at;
}

static
IRAtom* unary64Fx2 ( MCEnv* mce, IRAtom* vatomX )
{
   IRAtom* at;
   tl_assert(isShadowAtom(mce, vatomX));
   at = assignNew('V', mce, Ity_V128, mkPCast64x2(mce, vatomX));
   return at;
}

static
IRAtom* binary64F0x2 ( MCEnv* mce, IRAtom* vatomX, IRAtom* vatomY )
{
   IRAtom* at;
   tl_assert(isShadowAtom(mce, vatomX));
   tl_assert(isShadowAtom(mce, vatomY));
   at = mkUifUV128(mce, vatomX, vatomY);
   at = assignNew('V', mce, Ity_I64, unop(Iop_V128to64, at));
   at = mkPCastTo(mce, Ity_I64, at);
   at = assignNew('V', mce, Ity_V128, binop(Iop_SetV128lo64, vatomX, at));
   return at;
}

static
IRAtom* unary64F0x2 ( MCEnv* mce, IRAtom* vatomX )
{
   IRAtom* at;
   tl_assert(isShadowAtom(mce, vatomX));
   at = assignNew('V', mce, Ity_I64, unop(Iop_V128to64, vatomX));
   at = mkPCastTo(mce, Ity_I64, at);
   at = assignNew('V', mce, Ity_V128, binop(Iop_SetV128lo64, vatomX, at));
   return at;
}

/* --- --- ... and ... 32Fx2 versions of the same --- --- */

static
IRAtom* binary32Fx2 ( MCEnv* mce, IRAtom* vatomX, IRAtom* vatomY )
{
   IRAtom* at;
   tl_assert(isShadowAtom(mce, vatomX));
   tl_assert(isShadowAtom(mce, vatomY));
   at = mkUifU64(mce, vatomX, vatomY);
   at = assignNew('V', mce, Ity_I64, mkPCast32x2(mce, at));
   return at;
}

static
IRAtom* unary32Fx2 ( MCEnv* mce, IRAtom* vatomX )
{
   IRAtom* at;
   tl_assert(isShadowAtom(mce, vatomX));
   at = assignNew('V', mce, Ity_I64, mkPCast32x2(mce, vatomX));
   return at;
}

/* --- ... and ... 64Fx4 versions of the same ... --- */

static
IRAtom* binary64Fx4 ( MCEnv* mce, IRAtom* vatomX, IRAtom* vatomY )
{
   IRAtom* at;
   tl_assert(isShadowAtom(mce, vatomX));
   tl_assert(isShadowAtom(mce, vatomY));
   at = mkUifUV256(mce, vatomX, vatomY);
   at = assignNew('V', mce, Ity_V256, mkPCast64x4(mce, at));
   return at;
}

static
IRAtom* unary64Fx4 ( MCEnv* mce, IRAtom* vatomX )
{
   IRAtom* at;
   tl_assert(isShadowAtom(mce, vatomX));
   at = assignNew('V', mce, Ity_V256, mkPCast64x4(mce, vatomX));
   return at;
}

/* --- ... and ... 32Fx8 versions of the same ... --- */

static
IRAtom* binary32Fx8 ( MCEnv* mce, IRAtom* vatomX, IRAtom* vatomY )
{
   IRAtom* at;
   tl_assert(isShadowAtom(mce, vatomX));
   tl_assert(isShadowAtom(mce, vatomY));
   at = mkUifUV256(mce, vatomX, vatomY);
   at = assignNew('V', mce, Ity_V256, mkPCast32x8(mce, at));
   return at;
}

static
IRAtom* unary32Fx8 ( MCEnv* mce, IRAtom* vatomX )
{
   IRAtom* at;
   tl_assert(isShadowAtom(mce, vatomX));
   at = assignNew('V', mce, Ity_V256, mkPCast32x8(mce, vatomX));
   return at;
}

/* --- 64Fx2 binary FP ops, with rounding mode --- */

static
IRAtom* binary64Fx2_w_rm ( MCEnv* mce, IRAtom* vRM,
                                       IRAtom* vatomX, IRAtom* vatomY )
{
   /* This is the same as binary64Fx2, except that we subsequently
      pessimise vRM (definedness of the rounding mode), widen to 128
      bits and UifU it into the result.  As with the scalar cases, if
      the RM is a constant then it is defined and so this extra bit
      will get constant-folded out later. */
   // "do" the vector args
   IRAtom* t1 = binary64Fx2(mce, vatomX, vatomY);
   // PCast the RM, and widen it to 128 bits
   IRAtom* t2 = mkPCastTo(mce, Ity_V128, vRM);
   // Roll it into the result
   t1 = mkUifUV128(mce, t1, t2);
   return t1;
}

/* --- ... and ... 32Fx4 versions of the same --- */

static
IRAtom* binary32Fx4_w_rm ( MCEnv* mce, IRAtom* vRM,
                                       IRAtom* vatomX, IRAtom* vatomY )
{
   IRAtom* t1 = binary32Fx4(mce, vatomX, vatomY);
   // PCast the RM, and widen it to 128 bits
   IRAtom* t2 = mkPCastTo(mce, Ity_V128, vRM);
   // Roll it into the result
   t1 = mkUifUV128(mce, t1, t2);
   return t1;
}

/* --- ... and ... 64Fx4 versions of the same --- */

static
IRAtom* binary64Fx4_w_rm ( MCEnv* mce, IRAtom* vRM,
                                       IRAtom* vatomX, IRAtom* vatomY )
{
   IRAtom* t1 = binary64Fx4(mce, vatomX, vatomY);
   // PCast the RM, and widen it to 256 bits
   IRAtom* t2 = mkPCastTo(mce, Ity_V256, vRM);
   // Roll it into the result
   t1 = mkUifUV256(mce, t1, t2);
   return t1;
}

static
IRAtom* binary32Fx8_w_rm ( MCEnv* mce, IRAtom* vRM,
                                       IRAtom* vatomX, IRAtom* vatomY )
{
   IRAtom* t1 = binary32Fx8(mce, vatomX, vatomY);
   // PCast the RM, and widen it to 256 bits
   IRAtom* t2 = mkPCastTo(mce, Ity_V256, vRM);
   // Roll it into the result
   t1 = mkUifUV256(mce, t1, t2);
   return t1;
}


/* --- --- Vector saturated narrowing --- --- */
static
IROp vanillaNarrowingOpOfShape ( IROp qnarrowOp )
{
   switch (qnarrowOp) {
      /* Binary: (128, 128) -> 128 */
      case Iop_QNarrowBin16Sto8Ux16:
      case Iop_QNarrowBin16Sto8Sx16:
      case Iop_QNarrowBin16Uto8Ux16:
         return Iop_NarrowBin16to8x16;
      case Iop_QNarrowBin32Sto16Ux8:
      case Iop_QNarrowBin32Sto16Sx8:
      case Iop_QNarrowBin32Uto16Ux8:
         return Iop_NarrowBin32to16x8;
      /* Binary: (64, 64) -> 64 */
      case Iop_QNarrowBin32Sto16Sx4:
         return Iop_NarrowBin32to16x4;
      case Iop_QNarrowBin16Sto8Ux8:
      case Iop_QNarrowBin16Sto8Sx8:
         return Iop_NarrowBin16to8x8;
      /* Unary: 128 -> 64 */
      case Iop_QNarrowUn64Uto32Ux2:
      case Iop_QNarrowUn64Sto32Sx2:
      case Iop_QNarrowUn64Sto32Ux2:
         return Iop_NarrowUn64to32x2;
      case Iop_QNarrowUn32Uto16Ux4:
      case Iop_QNarrowUn32Sto16Sx4:
      case Iop_QNarrowUn32Sto16Ux4:
         return Iop_NarrowUn32to16x4;
      case Iop_QNarrowUn16Uto8Ux8:
      case Iop_QNarrowUn16Sto8Sx8:
      case Iop_QNarrowUn16Sto8Ux8:
         return Iop_NarrowUn16to8x8;
      default:
         ppIROp(qnarrowOp);
         VG_(tool_panic)("vanillaNarrowOpOfShape");
   }
}

static
IRAtom* vectorNarrowBinV128 ( MCEnv* mce, IROp narrow_op,
                              IRAtom* vatom1, IRAtom* vatom2)
{
   IRAtom *at1, *at2, *at3;
   IRAtom* (*pcast)( MCEnv*, IRAtom* );
   switch (narrow_op) {
      case Iop_QNarrowBin32Sto16Sx8: pcast = mkPCast32x4; break;
      case Iop_QNarrowBin32Uto16Ux8: pcast = mkPCast32x4; break;
      case Iop_QNarrowBin32Sto16Ux8: pcast = mkPCast32x4; break;
      case Iop_QNarrowBin16Sto8Sx16: pcast = mkPCast16x8; break;
      case Iop_QNarrowBin16Uto8Ux16: pcast = mkPCast16x8; break;
      case Iop_QNarrowBin16Sto8Ux16: pcast = mkPCast16x8; break;
      default: VG_(tool_panic)("vectorNarrowBinV128");
   }
   IROp vanilla_narrow = vanillaNarrowingOpOfShape(narrow_op);
   tl_assert(isShadowAtom(mce,vatom1));
   tl_assert(isShadowAtom(mce,vatom2));
   at1 = assignNew('V', mce, Ity_V128, pcast(mce, vatom1));
   at2 = assignNew('V', mce, Ity_V128, pcast(mce, vatom2));
   at3 = assignNew('V', mce, Ity_V128, binop(vanilla_narrow, at1, at2));
   return at3;
}

static
IRAtom* vectorNarrowBin64 ( MCEnv* mce, IROp narrow_op,
                            IRAtom* vatom1, IRAtom* vatom2)
{
   IRAtom *at1, *at2, *at3;
   IRAtom* (*pcast)( MCEnv*, IRAtom* );
   switch (narrow_op) {
      case Iop_QNarrowBin32Sto16Sx4: pcast = mkPCast32x2; break;
      case Iop_QNarrowBin16Sto8Sx8:  pcast = mkPCast16x4; break;
      case Iop_QNarrowBin16Sto8Ux8:  pcast = mkPCast16x4; break;
      default: VG_(tool_panic)("vectorNarrowBin64");
   }
   IROp vanilla_narrow = vanillaNarrowingOpOfShape(narrow_op);
   tl_assert(isShadowAtom(mce,vatom1));
   tl_assert(isShadowAtom(mce,vatom2));
   at1 = assignNew('V', mce, Ity_I64, pcast(mce, vatom1));
   at2 = assignNew('V', mce, Ity_I64, pcast(mce, vatom2));
   at3 = assignNew('V', mce, Ity_I64, binop(vanilla_narrow, at1, at2));
   return at3;
}

static
IRAtom* vectorNarrowUnV128 ( MCEnv* mce, IROp narrow_op,
                             IRAtom* vatom1)
{
   IRAtom *at1, *at2;
   IRAtom* (*pcast)( MCEnv*, IRAtom* );
   tl_assert(isShadowAtom(mce,vatom1));
   /* For vanilla narrowing (non-saturating), we can just apply
      the op directly to the V bits. */
   switch (narrow_op) {
      case Iop_NarrowUn16to8x8:
      case Iop_NarrowUn32to16x4:
      case Iop_NarrowUn64to32x2:
         at1 = assignNew('V', mce, Ity_I64, unop(narrow_op, vatom1));
         return at1;
      default:
         break; /* Do Plan B */
   }
   /* Plan B: for ops that involve a saturation operation on the args,
      we must PCast before the vanilla narrow. */
   switch (narrow_op) {
      case Iop_QNarrowUn16Sto8Sx8:  pcast = mkPCast16x8; break;
      case Iop_QNarrowUn16Sto8Ux8:  pcast = mkPCast16x8; break;
      case Iop_QNarrowUn16Uto8Ux8:  pcast = mkPCast16x8; break;
      case Iop_QNarrowUn32Sto16Sx4: pcast = mkPCast32x4; break;
      case Iop_QNarrowUn32Sto16Ux4: pcast = mkPCast32x4; break;
      case Iop_QNarrowUn32Uto16Ux4: pcast = mkPCast32x4; break;
      case Iop_QNarrowUn64Sto32Sx2: pcast = mkPCast64x2; break;
      case Iop_QNarrowUn64Sto32Ux2: pcast = mkPCast64x2; break;
      case Iop_QNarrowUn64Uto32Ux2: pcast = mkPCast64x2; break;
      default: VG_(tool_panic)("vectorNarrowUnV128");
   }
   IROp vanilla_narrow = vanillaNarrowingOpOfShape(narrow_op);
   at1 = assignNew('V', mce, Ity_V128, pcast(mce, vatom1));
   at2 = assignNew('V', mce, Ity_I64, unop(vanilla_narrow, at1));
   return at2;
}

static
IRAtom* vectorWidenI64 ( MCEnv* mce, IROp longen_op,
                         IRAtom* vatom1)
{
   IRAtom *at1, *at2;
   IRAtom* (*pcast)( MCEnv*, IRAtom* );
   switch (longen_op) {
      case Iop_Widen8Uto16x8:  pcast = mkPCast16x8; break;
      case Iop_Widen8Sto16x8:  pcast = mkPCast16x8; break;
      case Iop_Widen16Uto32x4: pcast = mkPCast32x4; break;
      case Iop_Widen16Sto32x4: pcast = mkPCast32x4; break;
      case Iop_Widen32Uto64x2: pcast = mkPCast64x2; break;
      case Iop_Widen32Sto64x2: pcast = mkPCast64x2; break;
      default: VG_(tool_panic)("vectorWidenI64");
   }
   tl_assert(isShadowAtom(mce,vatom1));
   at1 = assignNew('V', mce, Ity_V128, unop(longen_op, vatom1));
   at2 = assignNew('V', mce, Ity_V128, pcast(mce, at1));
   return at2;
}


/* --- --- Vector integer arithmetic --- --- */

/* Simple ... UifU the args and per-lane pessimise the results. */

/* --- V256-bit versions --- */

static
IRAtom* binary8Ix32 ( MCEnv* mce, IRAtom* vatom1, IRAtom* vatom2 )
{
   IRAtom* at;
   at = mkUifUV256(mce, vatom1, vatom2);
   at = mkPCast8x32(mce, at);
   return at;
}

static
IRAtom* binary16Ix16 ( MCEnv* mce, IRAtom* vatom1, IRAtom* vatom2 )
{
   IRAtom* at;
   at = mkUifUV256(mce, vatom1, vatom2);
   at = mkPCast16x16(mce, at);
   return at;
}

static
IRAtom* binary32Ix8 ( MCEnv* mce, IRAtom* vatom1, IRAtom* vatom2 )
{
   IRAtom* at;
   at = mkUifUV256(mce, vatom1, vatom2);
   at = mkPCast32x8(mce, at);
   return at;
}

static
IRAtom* binary64Ix4 ( MCEnv* mce, IRAtom* vatom1, IRAtom* vatom2 )
{
   IRAtom* at;
   at = mkUifUV256(mce, vatom1, vatom2);
   at = mkPCast64x4(mce, at);
   return at;
}

/* --- V128-bit versions --- */

static
IRAtom* binary8Ix16 ( MCEnv* mce, IRAtom* vatom1, IRAtom* vatom2 ) //1927
{
   IRAtom* at;
   at = mkUifUV128(mce, vatom1, vatom2);
   at = mkPCast8x16(mce, at);
   return at;
}

static
IRAtom* binary16Ix8 ( MCEnv* mce, IRAtom* vatom1, IRAtom* vatom2 )
{
   IRAtom* at;
   at = mkUifUV128(mce, vatom1, vatom2);
   at = mkPCast16x8(mce, at);
   return at;
}

static
IRAtom* binary32Ix4 ( MCEnv* mce, IRAtom* vatom1, IRAtom* vatom2 )
{
   IRAtom* at;
   at = mkUifUV128(mce, vatom1, vatom2);
   at = mkPCast32x4(mce, at);
   return at;
}

static
IRAtom* binary64Ix2 ( MCEnv* mce, IRAtom* vatom1, IRAtom* vatom2 )
{
   IRAtom* at;
   at = mkUifUV128(mce, vatom1, vatom2);
   at = mkPCast64x2(mce, at);
   return at;
}

/* --- 64-bit versions --- */

static
IRAtom* binary8Ix8 ( MCEnv* mce, IRAtom* vatom1, IRAtom* vatom2 )
{
   IRAtom* at;
   at = mkUifU64(mce, vatom1, vatom2);
   at = mkPCast8x8(mce, at);
   return at;
}

static
IRAtom* binary16Ix4 ( MCEnv* mce, IRAtom* vatom1, IRAtom* vatom2 )
{
   IRAtom* at;
   at = mkUifU64(mce, vatom1, vatom2);
   at = mkPCast16x4(mce, at);
   return at;
}

static
IRAtom* binary32Ix2 ( MCEnv* mce, IRAtom* vatom1, IRAtom* vatom2 )
{
   IRAtom* at;
   at = mkUifU64(mce, vatom1, vatom2);
   at = mkPCast32x2(mce, at);
   return at;
}

static
IRAtom* binary64Ix1 ( MCEnv* mce, IRAtom* vatom1, IRAtom* vatom2 )
{
   IRAtom* at;
   at = mkUifU64(mce, vatom1, vatom2);
   at = mkPCastTo(mce, Ity_I64, at);
   return at;
}

/* --- 32-bit versions --- */

static
IRAtom* binary8Ix4 ( MCEnv* mce, IRAtom* vatom1, IRAtom* vatom2 )
{
   IRAtom* at;
   at = mkUifU32(mce, vatom1, vatom2);
   at = mkPCast8x4(mce, at);
   return at;
}

static
IRAtom* binary16Ix2 ( MCEnv* mce, IRAtom* vatom1, IRAtom* vatom2 )
{
   IRAtom* at;
   at = mkUifU32(mce, vatom1, vatom2);
   at = mkPCast16x2(mce, at);
   return at;
}


/*------------------------------------------------------------*/
/*--- Generate shadow values from all kinds of IRExprs.    ---*/
/*------------------------------------------------------------*/

static
IRAtom* expr2vbits_Qop ( MCEnv* mce, //1997
                         IROp op,
                         IRAtom* atom1, IRAtom* atom2,
                         IRAtom* atom3, IRAtom* atom4 )
{
   IRAtom* vatom1 = atom2vbits( mce, atom1 );
   IRAtom* vatom2 = atom2vbits( mce, atom2 );
   IRAtom* vatom3 = atom2vbits( mce, atom3 );
   IRAtom* vatom4 = atom2vbits( mce, atom4 );

   tl_assert(isOriginalAtom(mce,atom1));
   tl_assert(isOriginalAtom(mce,atom2));
   tl_assert(isOriginalAtom(mce,atom3));
   tl_assert(isOriginalAtom(mce,atom4));
   tl_assert(isShadowAtom(mce,vatom1));
   tl_assert(isShadowAtom(mce,vatom2));
   tl_assert(isShadowAtom(mce,vatom3));
   tl_assert(isShadowAtom(mce,vatom4));
   tl_assert(sameKindedAtoms(atom1,vatom1));
   tl_assert(sameKindedAtoms(atom2,vatom2));
   tl_assert(sameKindedAtoms(atom3,vatom3));
   tl_assert(sameKindedAtoms(atom4,vatom4));
   switch (op) {
      case Iop_MAddF64:
      case Iop_MAddF64r32:
      case Iop_MSubF64:
      case Iop_MSubF64r32:
         /* I32(rm) x F64 x F64 x F64 -> F64 */
         return mkLazy4(mce, Ity_I64, vatom1, vatom2, vatom3, vatom4);

      case Iop_MAddF32:
      case Iop_MSubF32:
         /* I32(rm) x F32 x F32 x F32 -> F32 */
         return mkLazy4(mce, Ity_I32, vatom1, vatom2, vatom3, vatom4);

      /* V256-bit data-steering */
      case Iop_64x4toV256:
         return assignNew('V', mce, Ity_V256,
                          IRExpr_Qop(op, vatom1, vatom2, vatom3, vatom4));

      default:
         ppIROp(op);
         VG_(tool_panic)("tnt_translate.c:expr2vbits_Qop");
   }
}


static
IRAtom* expr2vbits_Triop ( MCEnv* mce,
                           IROp op,
                           IRAtom* atom1, IRAtom* atom2, IRAtom* atom3 )
{
   IRAtom* vatom1 = atom2vbits( mce, atom1 );
   IRAtom* vatom2 = atom2vbits( mce, atom2 );
   IRAtom* vatom3 = atom2vbits( mce, atom3 );

   tl_assert(isOriginalAtom(mce,atom1));
   tl_assert(isOriginalAtom(mce,atom2));
   tl_assert(isOriginalAtom(mce,atom3));
   tl_assert(isShadowAtom(mce,vatom1));
   tl_assert(isShadowAtom(mce,vatom2));
   tl_assert(isShadowAtom(mce,vatom3));
   tl_assert(sameKindedAtoms(atom1,vatom1));
   tl_assert(sameKindedAtoms(atom2,vatom2));
   tl_assert(sameKindedAtoms(atom3,vatom3));
   switch (op) {
      case Iop_AddF128:
      case Iop_AddD128:
      case Iop_SubF128:
      case Iop_SubD128:
      case Iop_MulF128:
      case Iop_MulD128:
      case Iop_DivF128:
      case Iop_DivD128:
      case Iop_QuantizeD128:
         /* I32(rm) x F128/D128 x F128/D128 -> F128/D128 */
         return mkLazy3(mce, Ity_I128, vatom1, vatom2, vatom3);
      case Iop_AddF64:
      case Iop_AddD64:
      case Iop_AddF64r32:
      case Iop_SubF64:
      case Iop_SubD64:
      case Iop_SubF64r32:
      case Iop_MulF64:
      case Iop_MulD64:
      case Iop_MulF64r32:
      case Iop_DivF64:
      case Iop_DivD64:
      case Iop_DivF64r32:
      case Iop_ScaleF64:
      case Iop_Yl2xF64:
      case Iop_Yl2xp1F64:
      case Iop_AtanF64:
      case Iop_PRemF64:
      case Iop_PRem1F64:
      case Iop_QuantizeD64:
         /* I32(rm) x F64 x F64 -> F64 */
         return mkLazy3(mce, Ity_I64, vatom1, vatom2, vatom3);
      case Iop_PRemC3210F64:
      case Iop_PRem1C3210F64:
         /* I32(rm) x F64 x F64 -> I32 */
         return mkLazy3(mce, Ity_I32, vatom1, vatom2, vatom3);
      case Iop_AddF32:
      case Iop_SubF32:
      case Iop_MulF32:
      case Iop_DivF32:
         /* I32(rm) x F32 x F32 -> I32 */
         return mkLazy3(mce, Ity_I32, vatom1, vatom2, vatom3);
      case Iop_SignificanceRoundD64:
         /* IRRoundingMode(I32) x I8 x D64 -> D64 */
         return mkLazy3(mce, Ity_I64, vatom1, vatom2, vatom3);
      case Iop_SignificanceRoundD128:
         /* IRRoundingMode(I32) x I8 x D128 -> D128 */
         return mkLazy3(mce, Ity_I128, vatom1, vatom2, vatom3);
      case Iop_SliceV128:
         //complainIfUndefined(mce, atom3, NULL);
         return assignNew('V', mce, Ity_V128, triop(op, vatom1, vatom2, atom3));
      case Iop_Slice64:
         //complainIfUndefined(mce, atom3, NULL);
         return assignNew('V', mce, Ity_I64, triop(op, vatom1, vatom2, atom3));
      case Iop_SetElem8x8:
      case Iop_SetElem16x4:
      case Iop_SetElem32x2:
         //complainIfUndefined(mce, atom2, NULL);
         return assignNew('V', mce, Ity_I64, triop(op, vatom1, atom2, vatom3));
      /* BCDIops */
      case Iop_BCDAdd:
      case Iop_BCDSub:
         //complainIfUndefined(mce, atom3, NULL);
         return assignNew('V', mce, Ity_V128, triop(op, vatom1, vatom2, atom3));

      /* Vector FP with rounding mode as the first arg */
      case Iop_Add64Fx2:
      case Iop_Sub64Fx2:
      case Iop_Mul64Fx2:
      case Iop_Div64Fx2:
         return binary64Fx2_w_rm(mce, vatom1, vatom2, vatom3);

      case Iop_Add32Fx4:
      case Iop_Sub32Fx4:
      case Iop_Mul32Fx4:
      case Iop_Div32Fx4:
        return binary32Fx4_w_rm(mce, vatom1, vatom2, vatom3);

      case Iop_Add64Fx4:
      case Iop_Sub64Fx4:
      case Iop_Mul64Fx4:
      case Iop_Div64Fx4:
         return binary64Fx4_w_rm(mce, vatom1, vatom2, vatom3);

      case Iop_Add32Fx8:
      case Iop_Sub32Fx8:
      case Iop_Mul32Fx8:
      case Iop_Div32Fx8:
         return binary32Fx8_w_rm(mce, vatom1, vatom2, vatom3);

      default:
         ppIROp(op);
         VG_(tool_panic)("tnt_translate.c:expr2vbits_Triop");
   }
}

static 
IRAtom* expr2vbits_Binop ( MCEnv* mce,
                           IROp op,
                           IRAtom* atom1, IRAtom* atom2 )
{
   IRType  and_or_ty;
   IRAtom* (*uifu)    (MCEnv*, IRAtom*, IRAtom*);
   IRAtom* (*difd)    (MCEnv*, IRAtom*, IRAtom*);
   IRAtom* (*improve) (MCEnv*, IRAtom*, IRAtom*);

   IRAtom* vatom1 = expr2vbits( mce, atom1 );
   IRAtom* vatom2 = expr2vbits( mce, atom2 );

   tl_assert(isOriginalAtom(mce,atom1));
   tl_assert(isOriginalAtom(mce,atom2));
   tl_assert(isShadowAtom(mce,vatom1));
   tl_assert(isShadowAtom(mce,vatom2));
   tl_assert(sameKindedAtoms(atom1,vatom1));
   tl_assert(sameKindedAtoms(atom2,vatom2));
   switch (op) {

      /* 32-bit SIMD */

      case Iop_Add16x2:
      case Iop_HAdd16Ux2:
      case Iop_HAdd16Sx2:
      case Iop_Sub16x2:
      case Iop_HSub16Ux2:
      case Iop_HSub16Sx2:
      case Iop_QAdd16Sx2:
      case Iop_QSub16Sx2:
      case Iop_QSub16Ux2:
      case Iop_QAdd16Ux2:
         return binary16Ix2(mce, vatom1, vatom2);

      case Iop_Add8x4:
      case Iop_HAdd8Ux4:
      case Iop_HAdd8Sx4:
      case Iop_Sub8x4:
      case Iop_HSub8Ux4:
      case Iop_HSub8Sx4:
      case Iop_QSub8Ux4:
      case Iop_QAdd8Ux4:
      case Iop_QSub8Sx4:
      case Iop_QAdd8Sx4:
         return binary8Ix4(mce, vatom1, vatom2);

      /* 64-bit SIMD */

      case Iop_ShrN8x8:
      case Iop_ShrN16x4:
      case Iop_ShrN32x2:
      case Iop_SarN8x8:
      case Iop_SarN16x4:
      case Iop_SarN32x2:
      case Iop_ShlN16x4:
      case Iop_ShlN32x2:
      case Iop_ShlN8x8:
         /* Same scheme as with all other shifts. */
         //complainIfUndefined(mce, atom2, NULL);
         return assignNew('V', mce, Ity_I64, binop(op, vatom1, atom2));

      case Iop_QNarrowBin32Sto16Sx4:
      case Iop_QNarrowBin16Sto8Sx8:
      case Iop_QNarrowBin16Sto8Ux8:
         return vectorNarrowBin64(mce, op, vatom1, vatom2);

      case Iop_Min8Ux8:
      case Iop_Min8Sx8:
      case Iop_Max8Ux8:
      case Iop_Max8Sx8:
      case Iop_Avg8Ux8:
      case Iop_QSub8Sx8:
      case Iop_QSub8Ux8:
      case Iop_Sub8x8:
      case Iop_CmpGT8Sx8:
      case Iop_CmpGT8Ux8:
      case Iop_CmpEQ8x8:
      case Iop_QAdd8Sx8:
      case Iop_QAdd8Ux8:
      case Iop_QSal8x8:
      case Iop_QShl8x8:
      case Iop_Add8x8:
      case Iop_Mul8x8:
      case Iop_PolynomialMul8x8:
         return binary8Ix8(mce, vatom1, vatom2);

      case Iop_Min16Sx4:
      case Iop_Min16Ux4:
      case Iop_Max16Sx4:
      case Iop_Max16Ux4:
      case Iop_Avg16Ux4:
      case Iop_QSub16Ux4:
      case Iop_QSub16Sx4:
      case Iop_Sub16x4:
      case Iop_Mul16x4:
      case Iop_MulHi16Sx4:
      case Iop_MulHi16Ux4:
      case Iop_CmpGT16Sx4:
      case Iop_CmpGT16Ux4:
      case Iop_CmpEQ16x4:
      case Iop_QAdd16Sx4:
      case Iop_QAdd16Ux4:
      case Iop_QSal16x4:
      case Iop_QShl16x4:
      case Iop_Add16x4:
      case Iop_QDMulHi16Sx4:
      case Iop_QRDMulHi16Sx4:
         return binary16Ix4(mce, vatom1, vatom2);

      case Iop_Sub32x2:
      case Iop_Mul32x2:
      case Iop_Max32Sx2:
      case Iop_Max32Ux2:
      case Iop_Min32Sx2:
      case Iop_Min32Ux2:
      case Iop_CmpGT32Sx2:
      case Iop_CmpGT32Ux2:
      case Iop_CmpEQ32x2:
      case Iop_Add32x2:
      case Iop_QAdd32Ux2:
      case Iop_QAdd32Sx2:
      case Iop_QSub32Ux2:
      case Iop_QSub32Sx2:
      case Iop_QSal32x2:
      case Iop_QShl32x2:
      case Iop_QDMulHi32Sx2:
      case Iop_QRDMulHi32Sx2:
         return binary32Ix2(mce, vatom1, vatom2);

      case Iop_QSub64Ux1:
      case Iop_QSub64Sx1:
      case Iop_QAdd64Ux1:
      case Iop_QAdd64Sx1:
      case Iop_QSal64x1:
      case Iop_QShl64x1:
      case Iop_Sal64x1:
         return binary64Ix1(mce, vatom1, vatom2);

      case Iop_QShlNsatSU8x8:
      case Iop_QShlNsatUU8x8:
      case Iop_QShlNsatSS8x8:
         //complainIfUndefined(mce, atom2, NULL);
         return mkPCast8x8(mce, vatom1);

      case Iop_QShlNsatSU16x4:
      case Iop_QShlNsatUU16x4:
      case Iop_QShlNsatSS16x4:
         //complainIfUndefined(mce, atom2, NULL);
         return mkPCast16x4(mce, vatom1);

      case Iop_QShlNsatSU32x2:
      case Iop_QShlNsatUU32x2:
      case Iop_QShlNsatSS32x2:
         //complainIfUndefined(mce, atom2, NULL);
         return mkPCast32x2(mce, vatom1);

      case Iop_QShlNsatSU64x1:
      case Iop_QShlNsatUU64x1:
      case Iop_QShlNsatSS64x1:
         //complainIfUndefined(mce, atom2, NULL);
         return mkPCast32x2(mce, vatom1);

      case Iop_PwMax32Sx2:
      case Iop_PwMax32Ux2:
      case Iop_PwMin32Sx2:
      case Iop_PwMin32Ux2:
      case Iop_PwMax32Fx2:
      case Iop_PwMin32Fx2:
         return assignNew('V', mce, Ity_I64,
                          binop(Iop_PwMax32Ux2, 
                                mkPCast32x2(mce, vatom1),
                                mkPCast32x2(mce, vatom2)));

      case Iop_PwMax16Sx4:
      case Iop_PwMax16Ux4:
      case Iop_PwMin16Sx4:
      case Iop_PwMin16Ux4:
         return assignNew('V', mce, Ity_I64,
                          binop(Iop_PwMax16Ux4,
                                mkPCast16x4(mce, vatom1),
                                mkPCast16x4(mce, vatom2)));

      case Iop_PwMax8Sx8:
      case Iop_PwMax8Ux8:
      case Iop_PwMin8Sx8:
      case Iop_PwMin8Ux8:
         return assignNew('V', mce, Ity_I64,
                          binop(Iop_PwMax8Ux8,
                                mkPCast8x8(mce, vatom1),
                                mkPCast8x8(mce, vatom2)));

      case Iop_PwAdd32x2:
      case Iop_PwAdd32Fx2:
         return mkPCast32x2(mce,
               assignNew('V', mce, Ity_I64,
                         binop(Iop_PwAdd32x2,
                               mkPCast32x2(mce, vatom1),
                               mkPCast32x2(mce, vatom2))));

      case Iop_PwAdd16x4:
         return mkPCast16x4(mce,
               assignNew('V', mce, Ity_I64,
                         binop(op, mkPCast16x4(mce, vatom1),
                                   mkPCast16x4(mce, vatom2))));

      case Iop_PwAdd8x8:
         return mkPCast8x8(mce,
               assignNew('V', mce, Ity_I64,
                         binop(op, mkPCast8x8(mce, vatom1),
                                   mkPCast8x8(mce, vatom2))));

      case Iop_Shl8x8:
      case Iop_Shr8x8:
      case Iop_Sar8x8:
      case Iop_Sal8x8:
         return mkUifU64(mce,
                   assignNew('V', mce, Ity_I64, binop(op, vatom1, atom2)),
                   mkPCast8x8(mce,vatom2)
                );

      case Iop_Shl16x4:
      case Iop_Shr16x4:
      case Iop_Sar16x4:
      case Iop_Sal16x4:
         return mkUifU64(mce,
                   assignNew('V', mce, Ity_I64, binop(op, vatom1, atom2)),
                   mkPCast16x4(mce,vatom2)
                );

      case Iop_Shl32x2:
      case Iop_Shr32x2:
      case Iop_Sar32x2:
      case Iop_Sal32x2:
         return mkUifU64(mce,
                   assignNew('V', mce, Ity_I64, binop(op, vatom1, atom2)),
                   mkPCast32x2(mce,vatom2)
                );

      /* 64-bit data-steering */
      case Iop_InterleaveLO32x2:
      case Iop_InterleaveLO16x4:
      case Iop_InterleaveLO8x8:
      case Iop_InterleaveHI32x2:
      case Iop_InterleaveHI16x4:
      case Iop_InterleaveHI8x8:
      case Iop_CatOddLanes8x8:
      case Iop_CatEvenLanes8x8:
      case Iop_CatOddLanes16x4:
      case Iop_CatEvenLanes16x4:
      case Iop_InterleaveOddLanes8x8:
      case Iop_InterleaveEvenLanes8x8:
      case Iop_InterleaveOddLanes16x4:
      case Iop_InterleaveEvenLanes16x4:
         return assignNew('V', mce, Ity_I64, binop(op, vatom1, vatom2));

      case Iop_GetElem8x8:
         //complainIfUndefined(mce, atom2, NULL);
         return assignNew('V', mce, Ity_I8, binop(op, vatom1, atom2));
      case Iop_GetElem16x4:
         //complainIfUndefined(mce, atom2, NULL);
         return assignNew('V', mce, Ity_I16, binop(op, vatom1, atom2));
      case Iop_GetElem32x2:
         //complainIfUndefined(mce, atom2, NULL);
         return assignNew('V', mce, Ity_I32, binop(op, vatom1, atom2));

      /* Perm8x8: rearrange values in left arg using steering values
        from right arg.  So rearrange the vbits in the same way but
        pessimise wrt steering values. */
      case Iop_Perm8x8:
         return mkUifU64(
                   mce,
                   assignNew('V', mce, Ity_I64, binop(op, vatom1, atom2)),
                   mkPCast8x8(mce, vatom2)
                );

      /* V128-bit SIMD */

      case Iop_ShrN8x16:
      case Iop_ShrN16x8:
      case Iop_ShrN32x4:
      case Iop_ShrN64x2:
      case Iop_SarN8x16:
      case Iop_SarN16x8:
      case Iop_SarN32x4:
      case Iop_SarN64x2:
      case Iop_ShlN8x16:
      case Iop_ShlN16x8:
      case Iop_ShlN32x4:
      case Iop_ShlN64x2:
         /* Same scheme as with all other shifts.  Note: 22 Oct 05:
            this is wrong now, scalar shifts are done properly lazily.
            Vector shifts should be fixed too. */
         //complainIfUndefined(mce, atom2, NULL);
         return assignNew('V', mce, Ity_V128, binop(op, vatom1, atom2));

      /* V x V shifts/rotates are done using the standard lazy scheme. */
      case Iop_Shl8x16:
      case Iop_Shr8x16:
      case Iop_Sar8x16:
      case Iop_Sal8x16:
      case Iop_Rol8x16:
         return mkUifUV128(mce,
                   assignNew('V', mce, Ity_V128, binop(op, vatom1, atom2)),
                   mkPCast8x16(mce,vatom2)
                );

      case Iop_Shl16x8:
      case Iop_Shr16x8:
      case Iop_Sar16x8:
      case Iop_Sal16x8:
      case Iop_Rol16x8:
         return mkUifUV128(mce,
                   assignNew('V', mce, Ity_V128, binop(op, vatom1, atom2)),
                   mkPCast16x8(mce,vatom2)
                );

      case Iop_Shl32x4:
      case Iop_Shr32x4:
      case Iop_Sar32x4:
      case Iop_Sal32x4:
      case Iop_Rol32x4:
      case Iop_Rol64x2:
         return mkUifUV128(mce,
                   assignNew('V', mce, Ity_V128, binop(op, vatom1, atom2)),
                   mkPCast32x4(mce,vatom2)
                );

      case Iop_Shl64x2:
      case Iop_Shr64x2:
      case Iop_Sar64x2:
      case Iop_Sal64x2:
         return mkUifUV128(mce,
                   assignNew('V', mce, Ity_V128, binop(op, vatom1, atom2)),
                   mkPCast64x2(mce,vatom2)
                );

      case Iop_F32ToFixed32Ux4_RZ:
      case Iop_F32ToFixed32Sx4_RZ:
      case Iop_Fixed32UToF32x4_RN:
      case Iop_Fixed32SToF32x4_RN:
         //complainIfUndefined(mce, atom2, NULL);
         return mkPCast32x4(mce, vatom1);

      case Iop_F32ToFixed32Ux2_RZ:
      case Iop_F32ToFixed32Sx2_RZ:
      case Iop_Fixed32UToF32x2_RN:
      case Iop_Fixed32SToF32x2_RN:
         //complainIfUndefined(mce, atom2, NULL);
         return mkPCast32x2(mce, vatom1);

      case Iop_QSub8Ux16:
      case Iop_QSub8Sx16:
      case Iop_Sub8x16:
      case Iop_Min8Ux16:
      case Iop_Min8Sx16:
      case Iop_Max8Ux16:
      case Iop_Max8Sx16:
      case Iop_CmpGT8Sx16:
      case Iop_CmpGT8Ux16:
      case Iop_CmpEQ8x16:
      case Iop_Avg8Ux16:
      case Iop_Avg8Sx16:
      case Iop_QAdd8Ux16:
      case Iop_QAdd8Sx16:
      case Iop_QSal8x16:
      case Iop_QShl8x16:
      case Iop_Add8x16:
      case Iop_Mul8x16:
      case Iop_PolynomialMul8x16:
      case Iop_PolynomialMulAdd8x16:
         return binary8Ix16(mce, vatom1, vatom2);

      case Iop_QSub16Ux8:
      case Iop_QSub16Sx8:
      case Iop_Sub16x8:
      case Iop_Mul16x8:
      case Iop_MulHi16Sx8:
      case Iop_MulHi16Ux8:
      case Iop_Min16Sx8:
      case Iop_Min16Ux8:
      case Iop_Max16Sx8:
      case Iop_Max16Ux8:
      case Iop_CmpGT16Sx8:
      case Iop_CmpGT16Ux8:
      case Iop_CmpEQ16x8:
      case Iop_Avg16Ux8:
      case Iop_Avg16Sx8:
      case Iop_QAdd16Ux8:
      case Iop_QAdd16Sx8:
      case Iop_QSal16x8:
      case Iop_QShl16x8:
      case Iop_Add16x8:
      case Iop_QDMulHi16Sx8:
      case Iop_QRDMulHi16Sx8:
      case Iop_PolynomialMulAdd16x8:
         return binary16Ix8(mce, vatom1, vatom2);

      case Iop_Sub32x4:
      case Iop_CmpGT32Sx4:
      case Iop_CmpGT32Ux4:
      case Iop_CmpEQ32x4:
      case Iop_QAdd32Sx4:
      case Iop_QAdd32Ux4:
      case Iop_QSub32Sx4:
      case Iop_QSub32Ux4:
      case Iop_QSal32x4:
      case Iop_QShl32x4:
      case Iop_Avg32Ux4:
      case Iop_Avg32Sx4:
      case Iop_Add32x4:
      case Iop_Max32Ux4:
      case Iop_Max32Sx4:
      case Iop_Min32Ux4:
      case Iop_Min32Sx4:
      case Iop_Mul32x4:
      case Iop_QDMulHi32Sx4:
      case Iop_QRDMulHi32Sx4:
      case Iop_PolynomialMulAdd32x4:
         return binary32Ix4(mce, vatom1, vatom2);

      case Iop_Sub64x2:
      case Iop_Add64x2:
      case Iop_Max64Sx2:
      case Iop_Max64Ux2:
      case Iop_Min64Sx2:
      case Iop_Min64Ux2:
      case Iop_CmpEQ64x2:
      case Iop_CmpGT64Sx2:
      case Iop_CmpGT64Ux2:
      case Iop_QSal64x2:
      case Iop_QShl64x2:
      case Iop_QAdd64Ux2:
      case Iop_QAdd64Sx2:
      case Iop_QSub64Ux2:
      case Iop_QSub64Sx2:
      case Iop_PolynomialMulAdd64x2:
      case Iop_CipherV128:
      case Iop_CipherLV128:
      case Iop_NCipherV128:
      case Iop_NCipherLV128:
        return binary64Ix2(mce, vatom1, vatom2);

      case Iop_QNarrowBin64Sto32Sx4:
      case Iop_QNarrowBin64Uto32Ux4:
      case Iop_QNarrowBin32Sto16Sx8:
      case Iop_QNarrowBin32Uto16Ux8:
      case Iop_QNarrowBin32Sto16Ux8:
      case Iop_QNarrowBin16Sto8Sx16:
      case Iop_QNarrowBin16Uto8Ux16:
      case Iop_QNarrowBin16Sto8Ux16:
         return vectorNarrowBinV128(mce, op, vatom1, vatom2);

      case Iop_Sub64Fx2:
      case Iop_Mul64Fx2:
      case Iop_Min64Fx2:
      case Iop_Max64Fx2:
      case Iop_Div64Fx2:
      case Iop_CmpLT64Fx2:
      case Iop_CmpLE64Fx2:
      case Iop_CmpEQ64Fx2:
      case Iop_CmpUN64Fx2:
      case Iop_Add64Fx2:
         return binary64Fx2(mce, vatom1, vatom2);      

      case Iop_Sub64F0x2:
      case Iop_Mul64F0x2:
      case Iop_Min64F0x2:
      case Iop_Max64F0x2:
      case Iop_Div64F0x2:
      case Iop_CmpLT64F0x2:
      case Iop_CmpLE64F0x2:
      case Iop_CmpEQ64F0x2:
      case Iop_CmpUN64F0x2:
      case Iop_Add64F0x2:
         return binary64F0x2(mce, vatom1, vatom2);      

      case Iop_Min32Fx4:
      case Iop_Max32Fx4:
      case Iop_CmpLT32Fx4:
      case Iop_CmpLE32Fx4:
      case Iop_CmpEQ32Fx4:
      case Iop_CmpUN32Fx4:
      case Iop_CmpGT32Fx4:
      case Iop_CmpGE32Fx4:
      case Iop_RecipStep32Fx4:
      case Iop_RSqrtStep32Fx4:
         return binary32Fx4(mce, vatom1, vatom2);      

      case Iop_Sub32Fx2:
      case Iop_Mul32Fx2:
      case Iop_Min32Fx2:
      case Iop_Max32Fx2:
      case Iop_CmpEQ32Fx2:
      case Iop_CmpGT32Fx2:
      case Iop_CmpGE32Fx2:
      case Iop_Add32Fx2:
      case Iop_RecipStep32Fx2:
      case Iop_RSqrtStep32Fx2:
         return binary32Fx2(mce, vatom1, vatom2);      

      case Iop_Sub32F0x4:
      case Iop_Mul32F0x4:
      case Iop_Min32F0x4:
      case Iop_Max32F0x4:
      case Iop_Div32F0x4:
      case Iop_CmpLT32F0x4:
      case Iop_CmpLE32F0x4:
      case Iop_CmpEQ32F0x4:
      case Iop_CmpUN32F0x4:
      case Iop_Add32F0x4:
         return binary32F0x4(mce, vatom1, vatom2);      

      case Iop_QShlNsatSU8x16:
      case Iop_QShlNsatUU8x16:
      case Iop_QShlNsatSS8x16:
         //complainIfUndefined(mce, atom2, NULL);
         return mkPCast8x16(mce, vatom1);

      case Iop_QShlNsatSU16x8:
      case Iop_QShlNsatUU16x8:
      case Iop_QShlNsatSS16x8:
         //complainIfUndefined(mce, atom2, NULL);
         return mkPCast16x8(mce, vatom1);

      case Iop_QShlNsatSU32x4:
      case Iop_QShlNsatUU32x4:
      case Iop_QShlNsatSS32x4:
         //complainIfUndefined(mce, atom2, NULL);
         return mkPCast32x4(mce, vatom1);

      case Iop_QShlNsatSU64x2:
      case Iop_QShlNsatUU64x2:
      case Iop_QShlNsatSS64x2:
         //complainIfUndefined(mce, atom2, NULL);
         return mkPCast32x4(mce, vatom1);

      /* Q-and-Qshift-by-imm-and-narrow of the form (V128, I8) -> V128.
         To make this simpler, do the following:
         * complain if the shift amount (the I8) is undefined
         * pcast each lane at the wide width
         * truncate each lane to half width
         * pcast the resulting 64-bit value to a single bit and use
           that as the least significant bit of the upper half of the
           result. */
      case Iop_QandQShrNnarrow64Uto32Ux2:
      case Iop_QandQSarNnarrow64Sto32Sx2:
      case Iop_QandQSarNnarrow64Sto32Ux2:
      case Iop_QandQRShrNnarrow64Uto32Ux2:
      case Iop_QandQRSarNnarrow64Sto32Sx2:
      case Iop_QandQRSarNnarrow64Sto32Ux2:
      case Iop_QandQShrNnarrow32Uto16Ux4:
      case Iop_QandQSarNnarrow32Sto16Sx4:
      case Iop_QandQSarNnarrow32Sto16Ux4:
      case Iop_QandQRShrNnarrow32Uto16Ux4:
      case Iop_QandQRSarNnarrow32Sto16Sx4:
      case Iop_QandQRSarNnarrow32Sto16Ux4:
      case Iop_QandQShrNnarrow16Uto8Ux8:
      case Iop_QandQSarNnarrow16Sto8Sx8:
      case Iop_QandQSarNnarrow16Sto8Ux8:
      case Iop_QandQRShrNnarrow16Uto8Ux8:
      case Iop_QandQRSarNnarrow16Sto8Sx8:
      case Iop_QandQRSarNnarrow16Sto8Ux8:
      {
         IRAtom* (*fnPessim) (MCEnv*, IRAtom*) = NULL;
         IROp opNarrow = Iop_INVALID;
         switch (op) {
            case Iop_QandQShrNnarrow64Uto32Ux2:
            case Iop_QandQSarNnarrow64Sto32Sx2:
            case Iop_QandQSarNnarrow64Sto32Ux2:
            case Iop_QandQRShrNnarrow64Uto32Ux2:
            case Iop_QandQRSarNnarrow64Sto32Sx2:
            case Iop_QandQRSarNnarrow64Sto32Ux2:
               fnPessim = mkPCast64x2;
               opNarrow = Iop_NarrowUn64to32x2;
               break;
            case Iop_QandQShrNnarrow32Uto16Ux4:
            case Iop_QandQSarNnarrow32Sto16Sx4:
            case Iop_QandQSarNnarrow32Sto16Ux4:
            case Iop_QandQRShrNnarrow32Uto16Ux4:
            case Iop_QandQRSarNnarrow32Sto16Sx4:
            case Iop_QandQRSarNnarrow32Sto16Ux4:
               fnPessim = mkPCast32x4;
               opNarrow = Iop_NarrowUn32to16x4;
               break;
            case Iop_QandQShrNnarrow16Uto8Ux8:
            case Iop_QandQSarNnarrow16Sto8Sx8:
            case Iop_QandQSarNnarrow16Sto8Ux8:
            case Iop_QandQRShrNnarrow16Uto8Ux8:
            case Iop_QandQRSarNnarrow16Sto8Sx8:
            case Iop_QandQRSarNnarrow16Sto8Ux8:
               fnPessim = mkPCast16x8;
               opNarrow = Iop_NarrowUn16to8x8;
               break;
            default:
               tl_assert(0);
         }
         //complainIfUndefined(mce, atom2, NULL);
         // Pessimised shift result
         IRAtom* shV
            = fnPessim(mce, vatom1);
         // Narrowed, pessimised shift result
         IRAtom* shVnarrowed
            = assignNew('V', mce, Ity_I64, unop(opNarrow, shV));
         // Generates: Def--(63)--Def PCast-to-I1(narrowed)
         IRAtom* qV = mkPCastXXtoXXlsb(mce, shVnarrowed, Ity_I64);
         // and assemble the result
         return assignNew('V', mce, Ity_V128,
                          binop(Iop_64HLtoV128, qV, shVnarrowed));
      }

      case Iop_Mull32Sx2:
      case Iop_Mull32Ux2:
      case Iop_QDMull32Sx2:
         return vectorWidenI64(mce, Iop_Widen32Sto64x2,
                                    mkUifU64(mce, vatom1, vatom2));

      case Iop_Mull16Sx4:
      case Iop_Mull16Ux4:
      case Iop_QDMull16Sx4:
         return vectorWidenI64(mce, Iop_Widen16Sto32x4,
                                    mkUifU64(mce, vatom1, vatom2));

      case Iop_Mull8Sx8:
      case Iop_Mull8Ux8:
      case Iop_PolynomialMull8x8:
         return vectorWidenI64(mce, Iop_Widen8Sto16x8,
                                    mkUifU64(mce, vatom1, vatom2));

      case Iop_PwAdd32x4:
         return mkPCast32x4(mce,
               assignNew('V', mce, Ity_V128, binop(op, mkPCast32x4(mce, vatom1),
                     mkPCast32x4(mce, vatom2))));

      case Iop_PwAdd16x8:
         return mkPCast16x8(mce,
               assignNew('V', mce, Ity_V128, binop(op, mkPCast16x8(mce, vatom1),
                     mkPCast16x8(mce, vatom2))));

      case Iop_PwAdd8x16:
         return mkPCast8x16(mce,
               assignNew('V', mce, Ity_V128, binop(op, mkPCast8x16(mce, vatom1),
                     mkPCast8x16(mce, vatom2))));

      /* V128-bit data-steering */
      case Iop_SetV128lo32:
      case Iop_SetV128lo64:
      case Iop_64HLtoV128:
      case Iop_InterleaveLO64x2:
      case Iop_InterleaveLO32x4:
      case Iop_InterleaveLO16x8:
      case Iop_InterleaveLO8x16:
      case Iop_InterleaveHI64x2:
      case Iop_InterleaveHI32x4:
      case Iop_InterleaveHI16x8:
      case Iop_InterleaveHI8x16:
      case Iop_CatOddLanes8x16:
      case Iop_CatOddLanes16x8:
      case Iop_CatOddLanes32x4:
      case Iop_CatEvenLanes8x16:
      case Iop_CatEvenLanes16x8:
      case Iop_CatEvenLanes32x4:
      case Iop_InterleaveOddLanes8x16:
      case Iop_InterleaveOddLanes16x8:
      case Iop_InterleaveOddLanes32x4:
      case Iop_InterleaveEvenLanes8x16:
      case Iop_InterleaveEvenLanes16x8:
      case Iop_InterleaveEvenLanes32x4:
         return assignNew('V', mce, Ity_V128, binop(op, vatom1, vatom2));

      case Iop_GetElem8x16:
         //complainIfUndefined(mce, atom2, NULL);
         return assignNew('V', mce, Ity_I8, binop(op, vatom1, atom2));
      case Iop_GetElem16x8:
         //complainIfUndefined(mce, atom2, NULL);
         return assignNew('V', mce, Ity_I16, binop(op, vatom1, atom2));
      case Iop_GetElem32x4:
         //complainIfUndefined(mce, atom2, NULL);
         return assignNew('V', mce, Ity_I32, binop(op, vatom1, atom2));
      case Iop_GetElem64x2:
         //complainIfUndefined(mce, atom2, NULL);
         return assignNew('V', mce, Ity_I64, binop(op, vatom1, atom2));

     /* Perm8x16: rearrange values in left arg using steering values
        from right arg.  So rearrange the vbits in the same way but
        pessimise wrt steering values.  Perm32x4 ditto. */
      case Iop_Perm8x16:
         return mkUifUV128(
                   mce,
                   assignNew('V', mce, Ity_V128, binop(op, vatom1, atom2)),
                   mkPCast8x16(mce, vatom2)
                );
      case Iop_Perm32x4:
         return mkUifUV128(
                   mce,
                   assignNew('V', mce, Ity_V128, binop(op, vatom1, atom2)),
                   mkPCast32x4(mce, vatom2)
                );

     /* These two take the lower half of each 16-bit lane, sign/zero
        extend it to 32, and multiply together, producing a 32x4
        result (and implicitly ignoring half the operand bits).  So
        treat it as a bunch of independent 16x8 operations, but then
        do 32-bit shifts left-right to copy the lower half results
        (which are all 0s or all 1s due to PCasting in binary16Ix8)
        into the upper half of each result lane. */
      case Iop_MullEven16Ux8:
      case Iop_MullEven16Sx8: {
         IRAtom* at;
         at = binary16Ix8(mce,vatom1,vatom2);
         at = assignNew('V', mce, Ity_V128, binop(Iop_ShlN32x4, at, mkU8(16)));
         at = assignNew('V', mce, Ity_V128, binop(Iop_SarN32x4, at, mkU8(16)));
	 return at;
      }

      /* Same deal as Iop_MullEven16{S,U}x8 */
      case Iop_MullEven8Ux16:
      case Iop_MullEven8Sx16: {
         IRAtom* at;
         at = binary8Ix16(mce,vatom1,vatom2);
         at = assignNew('V', mce, Ity_V128, binop(Iop_ShlN16x8, at, mkU8(8)));
         at = assignNew('V', mce, Ity_V128, binop(Iop_SarN16x8, at, mkU8(8)));
	 return at;
      }

      /* Same deal as Iop_MullEven16{S,U}x8 */
      case Iop_MullEven32Ux4:
      case Iop_MullEven32Sx4: {
         IRAtom* at;
         at = binary32Ix4(mce,vatom1,vatom2);
         at = assignNew('V', mce, Ity_V128, binop(Iop_ShlN64x2, at, mkU8(32)));
         at = assignNew('V', mce, Ity_V128, binop(Iop_SarN64x2, at, mkU8(32)));
         return at;
      }

      /* narrow 2xV128 into 1xV128, hi half from left arg, in a 2 x
         32x4 -> 16x8 laneage, discarding the upper half of each lane.
         Simply apply same op to the V bits, since this really no more
         than a data steering operation. */
      case Iop_NarrowBin32to16x8: 
      case Iop_NarrowBin16to8x16: 
      case Iop_NarrowBin64to32x4:
         return assignNew('V', mce, Ity_V128, 
                                    binop(op, vatom1, vatom2));

      case Iop_ShrV128:
      case Iop_ShlV128:
         /* Same scheme as with all other shifts.  Note: 10 Nov 05:
            this is wrong now, scalar shifts are done properly lazily.
            Vector shifts should be fixed too. */
         //complainIfUndefined(mce, atom2, NULL);
         return assignNew('V', mce, Ity_V128, binop(op, vatom1, atom2));

      /* SHA Iops */
      case Iop_SHA256:
      case Iop_SHA512:
         //complainIfUndefined(mce, atom2, NULL);
         return assignNew('V', mce, Ity_V128, binop(op, vatom1, atom2));

      /* I128-bit data-steering */
      case Iop_64HLto128:
         return assignNew('V', mce, Ity_I128, binop(op, vatom1, vatom2));

      /* V256-bit SIMD */

      case Iop_Add64Fx4:
      case Iop_Sub64Fx4:
      case Iop_Mul64Fx4:
      case Iop_Div64Fx4:
      case Iop_Max64Fx4:
      case Iop_Min64Fx4:
         return binary64Fx4(mce, vatom1, vatom2);

      case Iop_Add32Fx8:
      case Iop_Sub32Fx8:
      case Iop_Mul32Fx8:
      case Iop_Div32Fx8:
      case Iop_Max32Fx8:
      case Iop_Min32Fx8:
         return binary32Fx8(mce, vatom1, vatom2);

      /* V256-bit data-steering */
      case Iop_V128HLtoV256:
         return assignNew('V', mce, Ity_V256, binop(op, vatom1, vatom2));

      /* Scalar floating point */

      case Iop_F32toI64S:
      case Iop_F32toI64U:
         /* I32(rm) x F32 -> I64 */
         return mkLazy2(mce, Ity_I64, vatom1, vatom2);

      case Iop_I64StoF32:
         /* I32(rm) x I64 -> F32 */
         return mkLazy2(mce, Ity_I32, vatom1, vatom2);

      case Iop_RoundF64toInt:
      case Iop_RoundF64toF32:
      case Iop_F64toI64S:
      case Iop_F64toI64U:
      case Iop_I64StoF64:
      case Iop_I64UtoF64:
      case Iop_SinF64:
      case Iop_CosF64:
      case Iop_TanF64:
      case Iop_2xm1F64:
      case Iop_SqrtF64:
         /* I32(rm) x I64/F64 -> I64/F64 */
         return mkLazy2(mce, Ity_I64, vatom1, vatom2);

      case Iop_ShlD64:
      case Iop_ShrD64:
      case Iop_RoundD64toInt:
         /* I32(rm) x D64 -> D64 */
         return mkLazy2(mce, Ity_I64, vatom1, vatom2);

      case Iop_ShlD128:
      case Iop_ShrD128:
      case Iop_RoundD128toInt:
         /* I32(rm) x D128 -> D128 */
         return mkLazy2(mce, Ity_I128, vatom1, vatom2);

      case Iop_D64toI64S:
      case Iop_D64toI64U:
      case Iop_I64StoD64:
      case Iop_I64UtoD64:
         /* I32(rm) x I64/D64 -> D64/I64 */
         return mkLazy2(mce, Ity_I64, vatom1, vatom2);

      case Iop_F32toD32:
      case Iop_F64toD32:
      case Iop_F128toD32:
      case Iop_D32toF32:
      case Iop_D64toF32:
      case Iop_D128toF32:
         /* I32(rm) x F32/F64/F128/D32/D64/D128 -> D32/F32 */
         return mkLazy2(mce, Ity_I32, vatom1, vatom2);

      case Iop_F32toD64:
      case Iop_F64toD64:
      case Iop_F128toD64:
      case Iop_D32toF64:
      case Iop_D64toF64:
      case Iop_D128toF64:
         /* I32(rm) x F32/F64/F128/D32/D64/D128 -> D64/F64 */
         return mkLazy2(mce, Ity_I64, vatom1, vatom2);

      case Iop_F32toD128:
      case Iop_F64toD128:
      case Iop_F128toD128:
      case Iop_D32toF128:
      case Iop_D64toF128:
      case Iop_D128toF128:
         /* I32(rm) x F32/F64/F128/D32/D64/D128 -> D128/F128 */
         return mkLazy2(mce, Ity_I128, vatom1, vatom2);

      case Iop_RoundF32toInt:
      case Iop_SqrtF32:
         /* I32(rm) x I32/F32 -> I32/F32 */
         return mkLazy2(mce, Ity_I32, vatom1, vatom2);

      case Iop_SqrtF128:
         /* I32(rm) x F128 -> F128 */
         return mkLazy2(mce, Ity_I128, vatom1, vatom2);

      case Iop_I32StoF32:
      case Iop_I32UtoF32:
      case Iop_F32toI32S:
      case Iop_F32toI32U:
         /* First arg is I32 (rounding mode), second is F32/I32 (data). */
         return mkLazy2(mce, Ity_I32, vatom1, vatom2);

      case Iop_F128toI32S: /* IRRoundingMode(I32) x F128 -> signed I32  */
      case Iop_F128toI32U: /* IRRoundingMode(I32) x F128 -> unsigned I32  */
      case Iop_F128toF32:  /* IRRoundingMode(I32) x F128 -> F32         */
      case Iop_D128toI32S: /* IRRoundingMode(I32) x D128 -> signed I32  */
      case Iop_D128toI32U: /* IRRoundingMode(I32) x D128 -> unsigned I32  */
         return mkLazy2(mce, Ity_I32, vatom1, vatom2);

      case Iop_F128toI64S: /* IRRoundingMode(I32) x F128 -> signed I64  */
      case Iop_F128toI64U: /* IRRoundingMode(I32) x F128 -> unsigned I64  */
      case Iop_F128toF64:  /* IRRoundingMode(I32) x F128 -> F64         */
      case Iop_D128toD64:  /* IRRoundingMode(I64) x D128 -> D64 */
      case Iop_D128toI64S: /* IRRoundingMode(I64) x D128 -> signed I64  */
      case Iop_D128toI64U: /* IRRoundingMode(I32) x D128 -> unsigned I64  */
         return mkLazy2(mce, Ity_I64, vatom1, vatom2);

      case Iop_F64HLtoF128:
      case Iop_D64HLtoD128:
         return assignNew('V', mce, Ity_I128,
                          binop(Iop_64HLto128, vatom1, vatom2));

      case Iop_F64toI32U:
      case Iop_F64toI32S:
      case Iop_F64toF32:
      case Iop_I64UtoF32:
      case Iop_D64toI32U:
      case Iop_D64toI32S:
         /* First arg is I32 (rounding mode), second is F64/D64 (data). */
         return mkLazy2(mce, Ity_I32, vatom1, vatom2);

      case Iop_D64toD32:
         /* First arg is I32 (rounding mode), second is D64 (data). */
         return mkLazy2(mce, Ity_I32, vatom1, vatom2);

      case Iop_F64toI16S:
         /* First arg is I32 (rounding mode), second is F64 (data). */
         return mkLazy2(mce, Ity_I16, vatom1, vatom2);

      case Iop_InsertExpD64:
         /*  I64 x I64 -> D64 */
         return mkLazy2(mce, Ity_I64, vatom1, vatom2);

      case Iop_InsertExpD128:
         /*  I64 x I128 -> D128 */
         return mkLazy2(mce, Ity_I128, vatom1, vatom2);

      case Iop_CmpF32:
      case Iop_CmpF64:
      case Iop_CmpF128:
      case Iop_CmpD64:
      case Iop_CmpD128:
      case Iop_CmpExpD64:
      case Iop_CmpExpD128:
         return mkLazy2(mce, Ity_I32, vatom1, vatom2);

      /* non-FP after here */

      case Iop_DivModU64to32:
      case Iop_DivModS64to32:
         return mkLazy2(mce, Ity_I64, vatom1, vatom2);

      case Iop_DivModU128to64:
      case Iop_DivModS128to64:
         return mkLazy2(mce, Ity_I128, vatom1, vatom2);

      case Iop_8HLto16:
         return assignNew('V', mce, Ity_I16, binop(op, vatom1, vatom2));
      case Iop_16HLto32:
         return assignNew('V', mce, Ity_I32, binop(op, vatom1, vatom2));
      case Iop_32HLto64:
         return assignNew('V', mce, Ity_I64, binop(op, vatom1, vatom2));

      case Iop_DivModS64to64:
      case Iop_MullS64:
      case Iop_MullU64: {
         IRAtom* vLo64 = mkLeft64(mce, mkUifU64(mce, vatom1,vatom2));
         IRAtom* vHi64 = mkPCastTo(mce, Ity_I64, vLo64);
         return assignNew('V', mce, Ity_I128,
                          binop(Iop_64HLto128, vHi64, vLo64));
      }

      case Iop_MullS32:
      case Iop_MullU32: {
         IRAtom* vLo32 = mkLeft32(mce, mkUifU32(mce, vatom1,vatom2));
         IRAtom* vHi32 = mkPCastTo(mce, Ity_I32, vLo32);
         return assignNew('V', mce, Ity_I64,
                          binop(Iop_32HLto64, vHi32, vLo32));
      }

      case Iop_MullS16:
      case Iop_MullU16: {
         IRAtom* vLo16 = mkLeft16(mce, mkUifU16(mce, vatom1,vatom2));
         IRAtom* vHi16 = mkPCastTo(mce, Ity_I16, vLo16);
         return assignNew('V', mce, Ity_I32,
                          binop(Iop_16HLto32, vHi16, vLo16));
      }

      case Iop_MullS8:
      case Iop_MullU8: {
         IRAtom* vLo8 = mkLeft8(mce, mkUifU8(mce, vatom1,vatom2));
         IRAtom* vHi8 = mkPCastTo(mce, Ity_I8, vLo8);
         return assignNew('V', mce, Ity_I16, binop(Iop_8HLto16, vHi8, vLo8));
      }

      case Iop_Sad8Ux4: /* maybe we could do better?  ftm, do mkLazy2. */
      case Iop_DivS32:
      case Iop_DivU32:
      case Iop_DivU32E:
      case Iop_DivS32E:
      case Iop_QAdd32S: /* could probably do better */
      case Iop_QSub32S: /* could probably do better */
         return mkLazy2(mce, Ity_I32, vatom1, vatom2);

      case Iop_DivS64:
      case Iop_DivU64:
      case Iop_DivS64E:
      case Iop_DivU64E:
         return mkLazy2(mce, Ity_I64, vatom1, vatom2);

      case Iop_Add32:
         if (mce->bogusLiterals || mce->useLLVMworkarounds)
            return expensiveAddSub(mce,True,Ity_I32, 
                                   vatom1,vatom2, atom1,atom2);
         else
            goto cheap_AddSub32;
      case Iop_Sub32:
         if (mce->bogusLiterals)
            return expensiveAddSub(mce,False,Ity_I32, 
                                   vatom1,vatom2, atom1,atom2);
         else
            goto cheap_AddSub32;

      cheap_AddSub32:
      case Iop_Mul32:
         return mkLeft32(mce, mkUifU32(mce, vatom1,vatom2));

      case Iop_CmpORD32S:
      case Iop_CmpORD32U:
      case Iop_CmpORD64S:
      case Iop_CmpORD64U:
         return doCmpORD(mce, op, vatom1,vatom2, atom1,atom2);

      case Iop_Add64:
         if (mce->bogusLiterals || mce->useLLVMworkarounds)
            return expensiveAddSub(mce,True,Ity_I64, 
                                   vatom1,vatom2, atom1,atom2);
         else
            goto cheap_AddSub64;
      case Iop_Sub64:
         if (mce->bogusLiterals)
            return expensiveAddSub(mce,False,Ity_I64, 
                                   vatom1,vatom2, atom1,atom2);
         else
            goto cheap_AddSub64;

      cheap_AddSub64:
      case Iop_Mul64:
         return mkLeft64(mce, mkUifU64(mce, vatom1,vatom2));

      case Iop_Mul16:
      case Iop_Add16:
      case Iop_Sub16:
         return mkLeft16(mce, mkUifU16(mce, vatom1,vatom2));

      case Iop_Mul8:
      case Iop_Sub8:
      case Iop_Add8:
         return mkLeft8(mce, mkUifU8(mce, vatom1,vatom2));

      case Iop_CmpEQ64: 
      case Iop_CmpNE64:
         if (mce->bogusLiterals)
            goto expensive_cmp64;
         else
            goto cheap_cmp64;

      expensive_cmp64:
      case Iop_ExpCmpNE64:
         return expensiveCmpEQorNE(mce,Ity_I64, vatom1,vatom2, atom1,atom2 );

      cheap_cmp64:
      case Iop_CmpLE64S: case Iop_CmpLE64U: 
      case Iop_CmpLT64U: case Iop_CmpLT64S:
         return mkPCastTo(mce, Ity_I1, mkUifU64(mce, vatom1,vatom2));

      case Iop_CmpEQ32: 
      case Iop_CmpNE32:
         if (mce->bogusLiterals)
            goto expensive_cmp32;
         else
            goto cheap_cmp32;

      expensive_cmp32:
      case Iop_ExpCmpNE32:
         return expensiveCmpEQorNE(mce,Ity_I32, vatom1,vatom2, atom1,atom2 );

      cheap_cmp32:
      case Iop_CmpLE32S: case Iop_CmpLE32U: 
      case Iop_CmpLT32U: case Iop_CmpLT32S:
         return mkPCastTo(mce, Ity_I1, mkUifU32(mce, vatom1,vatom2));

      case Iop_CmpEQ16: case Iop_CmpNE16:
         return mkPCastTo(mce, Ity_I1, mkUifU16(mce, vatom1,vatom2));

      case Iop_ExpCmpNE16:
         return expensiveCmpEQorNE(mce,Ity_I16, vatom1,vatom2, atom1,atom2 );

      case Iop_CmpEQ8: case Iop_CmpNE8:
         return mkPCastTo(mce, Ity_I1, mkUifU8(mce, vatom1,vatom2));

      case Iop_CasCmpEQ8:  case Iop_CasCmpNE8:
      case Iop_CasCmpEQ16: case Iop_CasCmpNE16:
      case Iop_CasCmpEQ32: case Iop_CasCmpNE32:
      case Iop_CasCmpEQ64: case Iop_CasCmpNE64:
         /* Just say these all produce a defined result, regardless
            of their arguments.  See COMMENT_ON_CasCmpEQ in this file. */
         return assignNew('V', mce, Ity_I1, definedOfType(Ity_I1));

      case Iop_Shl64: case Iop_Shr64: case Iop_Sar64:
         return scalarShift( mce, Ity_I64, op, vatom1,vatom2, atom1,atom2 );

      case Iop_Shl32: case Iop_Shr32: case Iop_Sar32:
         return scalarShift( mce, Ity_I32, op, vatom1,vatom2, atom1,atom2 );

      case Iop_Shl16: case Iop_Shr16: case Iop_Sar16:
         return scalarShift( mce, Ity_I16, op, vatom1,vatom2, atom1,atom2 );

      case Iop_Shl8: case Iop_Shr8: case Iop_Sar8:
         return scalarShift( mce, Ity_I8, op, vatom1,vatom2, atom1,atom2 );

      case Iop_AndV256:
         uifu = mkUifUV256; difd = mkDifDV256; 
         and_or_ty = Ity_V256; improve = mkImproveANDV256; goto do_And_Or;
      case Iop_AndV128:
         uifu = mkUifUV128; difd = mkDifDV128; 
         and_or_ty = Ity_V128; improve = mkImproveANDV128; goto do_And_Or;
      case Iop_And64:
         uifu = mkUifU64; difd = mkDifD64; 
         and_or_ty = Ity_I64; improve = mkImproveAND64; goto do_And_Or;
      case Iop_And32:
         uifu = mkUifU32; difd = mkDifD32; 
         and_or_ty = Ity_I32; improve = mkImproveAND32; goto do_And_Or;
      case Iop_And16:
         uifu = mkUifU16; difd = mkDifD16; 
         and_or_ty = Ity_I16; improve = mkImproveAND16; goto do_And_Or;
      case Iop_And8:
         uifu = mkUifU8; difd = mkDifD8; 
         and_or_ty = Ity_I8; improve = mkImproveAND8; goto do_And_Or;

      case Iop_OrV256:
         uifu = mkUifUV256; difd = mkDifDV256; 
         and_or_ty = Ity_V256; improve = mkImproveORV256; goto do_And_Or;
      case Iop_OrV128:
         uifu = mkUifUV128; difd = mkDifDV128; 
         and_or_ty = Ity_V128; improve = mkImproveORV128; goto do_And_Or;
      case Iop_Or64:
         uifu = mkUifU64; difd = mkDifD64; 
         and_or_ty = Ity_I64; improve = mkImproveOR64; goto do_And_Or;
      case Iop_Or32:
         uifu = mkUifU32; difd = mkDifD32; 
         and_or_ty = Ity_I32; improve = mkImproveOR32; goto do_And_Or;
      case Iop_Or16:
         uifu = mkUifU16; difd = mkDifD16; 
         and_or_ty = Ity_I16; improve = mkImproveOR16; goto do_And_Or;
      case Iop_Or8:
         uifu = mkUifU8; difd = mkDifD8; 
         and_or_ty = Ity_I8; improve = mkImproveOR8; goto do_And_Or;

      do_And_Or:
         return
         assignNew(
            'V', mce, 
            and_or_ty,
            difd(mce, uifu(mce, vatom1, vatom2),
                      difd(mce, improve(mce, atom1, vatom1),
                                improve(mce, atom2, vatom2) ) ) );

      case Iop_Xor8:
         return mkUifU8(mce, vatom1, vatom2);
      case Iop_Xor16:
         return mkUifU16(mce, vatom1, vatom2);
      case Iop_Xor32:
         return mkUifU32(mce, vatom1, vatom2);
      case Iop_Xor64:
         return mkUifU64(mce, vatom1, vatom2);
      case Iop_XorV128:
         return mkUifUV128(mce, vatom1, vatom2);
      case Iop_XorV256:
         return mkUifUV256(mce, vatom1, vatom2);

      /* V256-bit SIMD */

      case Iop_ShrN16x16:
      case Iop_ShrN32x8:
      case Iop_ShrN64x4:
      case Iop_SarN16x16:
      case Iop_SarN32x8:
      case Iop_ShlN16x16:
      case Iop_ShlN32x8:
      case Iop_ShlN64x4:
         /* Same scheme as with all other shifts.  Note: 22 Oct 05:
            this is wrong now, scalar shifts are done properly lazily.
            Vector shifts should be fixed too. */
         //complainIfUndefined(mce, atom2, NULL);
         return assignNew('V', mce, Ity_V256, binop(op, vatom1, atom2));

      case Iop_QSub8Ux32:
      case Iop_QSub8Sx32:
      case Iop_Sub8x32:
      case Iop_Min8Ux32:
      case Iop_Min8Sx32:
      case Iop_Max8Ux32:
      case Iop_Max8Sx32:
      case Iop_CmpGT8Sx32:
      case Iop_CmpEQ8x32:
      case Iop_Avg8Ux32:
      case Iop_QAdd8Ux32:
      case Iop_QAdd8Sx32:
      case Iop_Add8x32:
         return binary8Ix32(mce, vatom1, vatom2);

      case Iop_QSub16Ux16:
      case Iop_QSub16Sx16:
      case Iop_Sub16x16:
      case Iop_Mul16x16:
      case Iop_MulHi16Sx16:
      case Iop_MulHi16Ux16:
      case Iop_Min16Sx16:
      case Iop_Min16Ux16:
      case Iop_Max16Sx16:
      case Iop_Max16Ux16:
      case Iop_CmpGT16Sx16:
      case Iop_CmpEQ16x16:
      case Iop_Avg16Ux16:
      case Iop_QAdd16Ux16:
      case Iop_QAdd16Sx16:
      case Iop_Add16x16:
         return binary16Ix16(mce, vatom1, vatom2);

      case Iop_Sub32x8:
      case Iop_CmpGT32Sx8:
      case Iop_CmpEQ32x8:
      case Iop_Add32x8:
      case Iop_Max32Ux8:
      case Iop_Max32Sx8:
      case Iop_Min32Ux8:
      case Iop_Min32Sx8:
      case Iop_Mul32x8:
         return binary32Ix8(mce, vatom1, vatom2);

      case Iop_Sub64x4:
      case Iop_Add64x4:
      case Iop_CmpEQ64x4:
      case Iop_CmpGT64Sx4:
         return binary64Ix4(mce, vatom1, vatom2);

     /* Perm32x8: rearrange values in left arg using steering values
        from right arg.  So rearrange the vbits in the same way but
        pessimise wrt steering values. */
      case Iop_Perm32x8:
         return mkUifUV256(
                   mce,
                   assignNew('V', mce, Ity_V256, binop(op, vatom1, atom2)),
                   mkPCast32x8(mce, vatom2)
                );

      default:
         ppIROp(op);
         VG_(tool_panic)("tnt_translate.c: expr2vbits_Binop");
   }
}




static 
IRExpr* expr2vbits_Unop ( MCEnv* mce, IROp op, IRAtom* atom )
{
   /* For the widening operations {8,16,32}{U,S}to{16,32,64}, the
      selection of shadow operation implicitly duplicates the logic in
      do_shadow_LoadG and should be kept in sync (in the very unlikely
      event that the interpretation of such widening ops changes in
      future).  See comment in do_shadow_LoadG. */
   IRAtom* vatom = expr2vbits( mce, atom );
   tl_assert(isOriginalAtom(mce,atom));
   switch (op) {

      case Iop_Sqrt64Fx2:
      case Iop_Abs64Fx2:
      case Iop_Neg64Fx2:
         return unary64Fx2(mce, vatom);

      case Iop_Sqrt64F0x2:
         return unary64F0x2(mce, vatom);

      case Iop_Sqrt32Fx8:
      case Iop_RSqrtEst32Fx8:
      case Iop_RecipEst32Fx8:
         return unary32Fx8(mce, vatom);

      case Iop_Sqrt64Fx4:
         return unary64Fx4(mce, vatom);

      case Iop_Sqrt32Fx4:
      case Iop_RecipEst32Fx4:
      case Iop_I32UtoFx4:
      case Iop_I32StoFx4:
      case Iop_QFtoI32Ux4_RZ:
      case Iop_QFtoI32Sx4_RZ:
      case Iop_RoundF32x4_RM:
      case Iop_RoundF32x4_RP:
      case Iop_RoundF32x4_RN:
      case Iop_RoundF32x4_RZ:
      case Iop_RecipEst32Ux4:
      case Iop_Abs32Fx4:
      case Iop_Neg32Fx4:
      case Iop_RSqrtEst32Fx4:
         return unary32Fx4(mce, vatom);

      case Iop_I32UtoFx2:
      case Iop_I32StoFx2:
      case Iop_RecipEst32Fx2:
      case Iop_RecipEst32Ux2:
      case Iop_Abs32Fx2:
      case Iop_Neg32Fx2:
      case Iop_RSqrtEst32Fx2:
         return unary32Fx2(mce, vatom);

      case Iop_Sqrt32F0x4:
      case Iop_RSqrtEst32F0x4:
      case Iop_RecipEst32F0x4:
         return unary32F0x4(mce, vatom);

      case Iop_32UtoV128:
      case Iop_64UtoV128:
      case Iop_Dup8x16:
      case Iop_Dup16x8:
      case Iop_Dup32x4:
      case Iop_Reverse1sIn8_x16:
      case Iop_Reverse8sIn16_x8:
      case Iop_Reverse8sIn32_x4:
      case Iop_Reverse16sIn32_x4:
      case Iop_Reverse8sIn64_x2:
      case Iop_Reverse16sIn64_x2:
      case Iop_Reverse32sIn64_x2:
      case Iop_V256toV128_1: case Iop_V256toV128_0:
      case Iop_ZeroHI64ofV128:
      case Iop_ZeroHI96ofV128:
      case Iop_ZeroHI112ofV128:
      case Iop_ZeroHI120ofV128:
         return assignNew('V', mce, Ity_V128, unop(op, vatom));

      case Iop_F128HItoF64:  /* F128 -> high half of F128 */
      case Iop_D128HItoD64:  /* D128 -> high half of D128 */
         return assignNew('V', mce, Ity_I64, unop(Iop_128HIto64, vatom));
      case Iop_F128LOtoF64:  /* F128 -> low  half of F128 */
      case Iop_D128LOtoD64:  /* D128 -> low  half of D128 */
         return assignNew('V', mce, Ity_I64, unop(Iop_128to64, vatom));

      case Iop_NegF128:
      case Iop_AbsF128:
         return mkPCastTo(mce, Ity_I128, vatom);

      case Iop_I32StoF128: /* signed I32 -> F128 */
      case Iop_I64StoF128: /* signed I64 -> F128 */
      case Iop_I32UtoF128: /* unsigned I32 -> F128 */
      case Iop_I64UtoF128: /* unsigned I64 -> F128 */
      case Iop_F32toF128:  /* F32 -> F128 */
      case Iop_F64toF128:  /* F64 -> F128 */
      case Iop_I32StoD128: /* signed I64 -> D128 */
      case Iop_I64StoD128: /* signed I64 -> D128 */
      case Iop_I32UtoD128: /* unsigned I32 -> D128 */
      case Iop_I64UtoD128: /* unsigned I64 -> D128 */
         return mkPCastTo(mce, Ity_I128, vatom);

      case Iop_F32toF64: 
      case Iop_I32StoF64:
      case Iop_I32UtoF64:
      case Iop_NegF64:
      case Iop_AbsF64:
      case Iop_RSqrtEst5GoodF64:
      case Iop_RoundF64toF64_NEAREST:
      case Iop_RoundF64toF64_NegINF:
      case Iop_RoundF64toF64_PosINF:
      case Iop_RoundF64toF64_ZERO:
      case Iop_Clz64:
      case Iop_D32toD64:
      case Iop_I32StoD64:
      case Iop_I32UtoD64:
      case Iop_ExtractExpD64:    /* D64  -> I64 */
      case Iop_ExtractExpD128:   /* D128 -> I64 */
      case Iop_ExtractSigD64:    /* D64  -> I64 */
      case Iop_ExtractSigD128:   /* D128 -> I64 */
      case Iop_DPBtoBCD:
      case Iop_BCDtoDPB:
         return mkPCastTo(mce, Ity_I64, vatom);

      case Iop_D64toD128:
         return mkPCastTo(mce, Ity_I128, vatom);

      case Iop_Clz32:
      case Iop_TruncF64asF32:
      case Iop_NegF32:
      case Iop_AbsF32:
         return mkPCastTo(mce, Ity_I32, vatom);

      case Iop_Ctz32:
      case Iop_Ctz64:
         return expensiveCountTrailingZeroes(mce, op, atom, vatom);

      case Iop_1Uto64:
      case Iop_1Sto64:
      case Iop_8Uto64:
      case Iop_8Sto64:
      case Iop_16Uto64:
      case Iop_16Sto64:
      case Iop_32Sto64:
      case Iop_32Uto64:
      case Iop_V128to64:
      case Iop_V128HIto64:
      case Iop_128HIto64:
      case Iop_128to64:
      case Iop_Dup8x8:
      case Iop_Dup16x4:
      case Iop_Dup32x2:
      case Iop_Reverse8sIn16_x4:
      case Iop_Reverse8sIn32_x2:
      case Iop_Reverse16sIn32_x2:
      case Iop_Reverse8sIn64_x1:
      case Iop_Reverse16sIn64_x1:
      case Iop_Reverse32sIn64_x1:
      case Iop_V256to64_0: case Iop_V256to64_1:
      case Iop_V256to64_2: case Iop_V256to64_3:
         return assignNew('V', mce, Ity_I64, unop(op, vatom));

      case Iop_64to32:
      case Iop_64HIto32:
      case Iop_1Uto32:
      case Iop_1Sto32:
      case Iop_8Uto32:
      case Iop_16Uto32:
      case Iop_16Sto32:
      case Iop_8Sto32:
      case Iop_V128to32:
         return assignNew('V', mce, Ity_I32, unop(op, vatom));

      case Iop_8Sto16:
      case Iop_8Uto16:
      case Iop_32to16:
      case Iop_32HIto16:
      case Iop_64to16:
      case Iop_GetMSBs8x16:
         return assignNew('V', mce, Ity_I16, unop(op, vatom));

      case Iop_1Uto8:
      case Iop_1Sto8:
      case Iop_16to8:
      case Iop_16HIto8:
      case Iop_32to8:
      case Iop_64to8:
      case Iop_GetMSBs8x8:
         return assignNew('V', mce, Ity_I8, unop(op, vatom));

      case Iop_32to1:
         return assignNew('V', mce, Ity_I1, unop(Iop_32to1, vatom));

      case Iop_64to1:
         return assignNew('V', mce, Ity_I1, unop(Iop_64to1, vatom));

      case Iop_ReinterpF64asI64:
      case Iop_ReinterpI64asF64:
      case Iop_ReinterpI32asF32:
      case Iop_ReinterpF32asI32:
      case Iop_ReinterpI64asD64:
      case Iop_ReinterpD64asI64:
      case Iop_NotV256:
      case Iop_NotV128:
      case Iop_Not64:
      case Iop_Not32:
      case Iop_Not16:
      case Iop_Not8:
      case Iop_Not1:
         return vatom;

      case Iop_CmpNEZ8x8:
      case Iop_Cnt8x8:
      case Iop_Clz8x8:
      case Iop_Cls8x8:
      case Iop_Abs8x8:
         return mkPCast8x8(mce, vatom);

      case Iop_CmpNEZ8x16:
      case Iop_Cnt8x16:
      case Iop_Clz8x16:
      case Iop_Cls8x16:
      case Iop_Abs8x16:
         return mkPCast8x16(mce, vatom);

      case Iop_CmpNEZ16x4:
      case Iop_Clz16x4:
      case Iop_Cls16x4:
      case Iop_Abs16x4:
         return mkPCast16x4(mce, vatom);

      case Iop_CmpNEZ16x8:
      case Iop_Clz16x8:
      case Iop_Cls16x8:
      case Iop_Abs16x8:
         return mkPCast16x8(mce, vatom);

      case Iop_CmpNEZ32x2:
      case Iop_Clz32x2:
      case Iop_Cls32x2:
      case Iop_FtoI32Ux2_RZ:
      case Iop_FtoI32Sx2_RZ:
      case Iop_Abs32x2:
         return mkPCast32x2(mce, vatom);

      case Iop_CmpNEZ32x4:
      case Iop_Clz32x4:
      case Iop_Cls32x4:
      case Iop_FtoI32Ux4_RZ:
      case Iop_FtoI32Sx4_RZ:
      case Iop_Abs32x4:
      case Iop_RSqrtEst32Ux4:
         return mkPCast32x4(mce, vatom);

      case Iop_CmpwNEZ32:
         return mkPCastTo(mce, Ity_I32, vatom);

      case Iop_CmpwNEZ64:
         return mkPCastTo(mce, Ity_I64, vatom);

      case Iop_CmpNEZ64x2:
      case Iop_CipherSV128:
      case Iop_Clz64x2:
      case Iop_Abs64x2:
         return mkPCast64x2(mce, vatom);

      case Iop_PwBitMtxXpose64x2:
         return assignNew('V', mce, Ity_V128, unop(op, vatom));

      case Iop_NarrowUn16to8x8:
      case Iop_NarrowUn32to16x4:
      case Iop_NarrowUn64to32x2:
      case Iop_QNarrowUn16Sto8Sx8:
      case Iop_QNarrowUn16Sto8Ux8:
      case Iop_QNarrowUn16Uto8Ux8:
      case Iop_QNarrowUn32Sto16Sx4:
      case Iop_QNarrowUn32Sto16Ux4:
      case Iop_QNarrowUn32Uto16Ux4:
      case Iop_QNarrowUn64Sto32Sx2:
      case Iop_QNarrowUn64Sto32Ux2:
      case Iop_QNarrowUn64Uto32Ux2:
         return vectorNarrowUnV128(mce, op, vatom);

      case Iop_Widen8Sto16x8:
      case Iop_Widen8Uto16x8:
      case Iop_Widen16Sto32x4:
      case Iop_Widen16Uto32x4:
      case Iop_Widen32Sto64x2:
      case Iop_Widen32Uto64x2:
         return vectorWidenI64(mce, op, vatom);

      case Iop_PwAddL32Ux2:
      case Iop_PwAddL32Sx2:
         return mkPCastTo(mce, Ity_I64,
               assignNew('V', mce, Ity_I64, unop(op, mkPCast32x2(mce, vatom))));

      case Iop_PwAddL16Ux4:
      case Iop_PwAddL16Sx4:
         return mkPCast32x2(mce,
               assignNew('V', mce, Ity_I64, unop(op, mkPCast16x4(mce, vatom))));

      case Iop_PwAddL8Ux8:
      case Iop_PwAddL8Sx8:
         return mkPCast16x4(mce,
               assignNew('V', mce, Ity_I64, unop(op, mkPCast8x8(mce, vatom))));

      case Iop_PwAddL32Ux4:
      case Iop_PwAddL32Sx4:
         return mkPCast64x2(mce,
               assignNew('V', mce, Ity_V128, unop(op, mkPCast32x4(mce, vatom))));

      case Iop_PwAddL16Ux8:
      case Iop_PwAddL16Sx8:
         return mkPCast32x4(mce,
               assignNew('V', mce, Ity_V128, unop(op, mkPCast16x8(mce, vatom))));

      case Iop_PwAddL8Ux16:
      case Iop_PwAddL8Sx16:
         return mkPCast16x8(mce,
               assignNew('V', mce, Ity_V128, unop(op, mkPCast8x16(mce, vatom))));

      case Iop_I64UtoF32:
      default:
         ppIROp(op);
         VG_(tool_panic)("memcheck:expr2vbits_Unop");
   }
}



/* Worker function; do not call directly. */
static
IRAtom* expr2vbits_Load_WRK ( MCEnv* mce,
                              IREndness end, IRType ty,
                              IRAtom* addr, UInt bias, IRAtom* guard )
{
   tl_assert(isOriginalAtom(mce,addr));
   tl_assert(end == Iend_LE || end == Iend_BE);

   /* First, emit a definedness test for the address.  This also sets
      the address (shadow) to 'defined' following the test. */
   //complainIfUndefined( mce, addr, guard );

   /* Now cook up a call to the relevant helper function, to read the
      data V bits from shadow memory. */
   ty = shadowTypeV(ty);

   void*        helper           = NULL;
   const HChar* hname            = NULL;
   Bool         ret_via_outparam = False;

   if (end == Iend_LE) {
      switch (ty) {
         case Ity_V256: helper = &TNT_(helperc_LOADV256le);
                        hname = "TNT_(helperc_LOADV256le)";
                        ret_via_outparam = True;
                        break;
         case Ity_V128: helper = &TNT_(helperc_LOADV128le);
                        hname = "TNT_(helperc_LOADV128le)";
                        ret_via_outparam = True;
                        break;
         case Ity_I64:  helper = &TNT_(helperc_LOADV64le);
                        hname = "TNT_(helperc_LOADV64le)";
                        break;
         case Ity_I32:  helper = &TNT_(helperc_LOADV32le);
                        hname = "TNT_(helperc_LOADV32le)";
                        break;
         case Ity_I16:  helper = &TNT_(helperc_LOADV16le);
                        hname = "TNT_(helperc_LOADV16le)";
                        break;
         case Ity_I8:   helper = &TNT_(helperc_LOADV8);
                        hname = "TNT_(helperc_LOADV8)";
                        break;
         default:       ppIRType(ty);
                        VG_(tool_panic)("tnt_translate.c:expr2vbits_Load_WRK(LE)");
      }
   } else {
      switch (ty) {
         case Ity_V256: helper = &TNT_(helperc_LOADV256be);
                        hname = "TNT_(helperc_LOADV256be)";
                        ret_via_outparam = True;
                        break;
         case Ity_V128: helper = &TNT_(helperc_LOADV128be);
                        hname = "TNT_(helperc_LOADV128be)";
                        ret_via_outparam = True;
                        break;
         case Ity_I64:  helper = &TNT_(helperc_LOADV64be);
                        hname = "TNT_(helperc_LOADV64be)";
                        break;
         case Ity_I32:  helper = &TNT_(helperc_LOADV32be);
                        hname = "TNT_(helperc_LOADV32be)";
                        break;
         case Ity_I16:  helper = &TNT_(helperc_LOADV16be);
                        hname = "TNT_(helperc_LOADV16be)";
                        break;
         case Ity_I8:   helper = &TNT_(helperc_LOADV8);
                        hname = "TNT_(helperc_LOADV8)";
                        break;
         default:       ppIRType(ty);
                        VG_(tool_panic)("tnt_translate.c::expr2vbits_Load_WRK(BE)");
      }
   }

   tl_assert(helper);
   tl_assert(hname);

   /* Generate the actual address into addrAct. */
   IRAtom* addrAct;
   if (bias == 0) {
      addrAct = addr;
   } else {
      IROp    mkAdd;
      IRAtom* eBias;
      IRType  tyAddr  = mce->hWordTy;
      tl_assert( tyAddr == Ity_I32 || tyAddr == Ity_I64 );
      mkAdd   = tyAddr==Ity_I32 ? Iop_Add32 : Iop_Add64;
      eBias   = tyAddr==Ity_I32 ? mkU32(bias) : mkU64(bias);
      addrAct = assignNew('V', mce, tyAddr, binop(mkAdd, addr, eBias) );
   }

   /* We need to have a place to park the V bits we're just about to
      read. */
   IRTemp datavbits = newTemp(mce, ty, VSh);

   /* Here's the call. */
   IRDirty* di;
   if (ret_via_outparam) {
      di = unsafeIRDirty_1_N( datavbits,
                              2/*regparms*/,
                              hname, VG_(fnptr_to_fnentry)( helper ),
                              mkIRExprVec_2( IRExpr_VECRET(), addrAct ) );
   } else {
      di = unsafeIRDirty_1_N( datavbits,
                              1/*regparms*/,
                              hname, VG_(fnptr_to_fnentry)( helper ),
                              mkIRExprVec_1( addrAct ) );
   }

   setHelperAnns( mce, di );
   if (guard) {
      di->guard = guard;
      /* Ideally the didn't-happen return value here would be all-ones
         (all-undefined), so it'd be obvious if it got used
         inadvertantly.  We can get by with the IR-mandated default
         value (0b01 repeating, 0x55 etc) as that'll still look pretty
         undefined if it ever leaks out. */
   }
   stmt( 'V', mce, IRStmt_Dirty(di) );

   return mkexpr(datavbits);
}


static
IRAtom* expr2vbits_Load ( MCEnv* mce,
                          IREndness end, IRType ty,
                          IRAtom* addr, UInt bias,
                          IRAtom* guard )
{
   tl_assert(end == Iend_LE || end == Iend_BE);
   switch (shadowTypeV(ty)) {
      case Ity_I8:
      case Ity_I16:
      case Ity_I32:
      case Ity_I64:
      case Ity_V128:
      case Ity_V256:
         return expr2vbits_Load_WRK(mce, end, ty, addr, bias, guard);
      default:
         VG_(tool_panic)("expr2vbits_Load");
   }
}

static
IRAtom* expr2vbits_Load_guarded_General ( MCEnv* mce,
                                          IREndness end, IRType ty,
                                          IRAtom* addr, UInt bias,
                                          IRAtom* guard,
                                          IROp vwiden, IRAtom* valt )
{
   /* Sanity check the conversion operation, and also set TYWIDE. */
   IRType tyWide = Ity_INVALID;
   switch (vwiden) {
      case Iop_INVALID:
         tyWide = ty;
         break;
      case Iop_16Uto32: case Iop_16Sto32: case Iop_8Uto32: case Iop_8Sto32:
         tyWide = Ity_I32;
         break;
      default:
         VG_(tool_panic)("memcheck:expr2vbits_Load_guarded_General");
   }

   /* If the guard evaluates to True, this will hold the loaded V bits
      at TY.  If the guard evaluates to False, this will be all
      ones, meaning "all undefined", in which case we will have to
      replace it using an ITE below. */
   IRAtom* iftrue1
      = assignNew('V', mce, ty,
                  expr2vbits_Load(mce, end, ty, addr, bias, guard));
   /* Now (shadow-) widen the loaded V bits to the desired width.  In
      the guard-is-False case, the allowable widening operators will
      in the worst case (unsigned widening) at least leave the
      pre-widened part as being marked all-undefined, and in the best
      case (signed widening) mark the whole widened result as
      undefined.  Anyway, it doesn't matter really, since in this case
      we will replace said value with the default value |valt| using an
      ITE. */
   IRAtom* iftrue2
      = vwiden == Iop_INVALID
           ? iftrue1
           : assignNew('V', mce, tyWide, unop(vwiden, iftrue1));
   /* These are the V bits we will return if the load doesn't take
      place. */
   IRAtom* iffalse
      = valt;
   /* Prepare the cond for the ITE.  Convert a NULL cond into
      something that iropt knows how to fold out later. */
   IRAtom* cond
      = guard == NULL  ? mkU1(1)  : guard;
   /* And assemble the final result. */
   return assignNew('V', mce, tyWide, IRExpr_ITE(cond, iftrue2, iffalse));
}

static
IRAtom* expr2vbits_Load_guarded_Simple ( MCEnv* mce,
                                         IREndness end, IRType ty,
                                         IRAtom* addr, UInt bias,
                                         IRAtom *guard )
{
   return expr2vbits_Load_guarded_General(
             mce, end, ty, addr, bias, guard, Iop_INVALID, definedOfType(ty)
          );
}

static
IRAtom* expr2vbits_ITE ( MCEnv* mce, //2881
                         IRAtom* cond, IRAtom* iftrue, IRAtom* iffalse )
{
   IRAtom *vbitsC, *vbitsT, *vbitsF;
   IRType ty;
   /* Given ITE(cond,iftrue,iffalse), generate
         ITE(cond,iftrue#,iffalse#) `UifU` PCast(cond#)
      That is, steer the V bits like the originals, but trash the
      result if the steering value is undefined.  This gives
      lazy propagation. */
   tl_assert(isOriginalAtom(mce, cond));
   tl_assert(isOriginalAtom(mce, iftrue));
   tl_assert(isOriginalAtom(mce, iffalse));

   vbitsC = atom2vbits(mce, cond);
   vbitsT = atom2vbits(mce, iftrue);
   vbitsF = atom2vbits(mce, iffalse);
   ty = typeOfIRExpr(mce->sb->tyenv, vbitsT);

   return
      mkUifU(mce, ty, assignNew('V', mce, ty,
                                     IRExpr_ITE(cond, vbitsT, vbitsF)),
                      mkPCastTo(mce, ty, vbitsC) );
}


/* --------- This is the main expression-handling function. --------- */

static
IRExpr* expr2vbits ( MCEnv* mce, IRExpr* e ) //2909
{
   switch (e->tag) {
      case Iex_Get:
         return shadow_GET( mce, e->Iex.Get.offset, e->Iex.Get.ty );

      case Iex_GetI:
         return shadow_GETI( mce, e->Iex.GetI.descr,
                                  e->Iex.GetI.ix, e->Iex.GetI.bias );

      case Iex_RdTmp:
         return IRExpr_RdTmp( findShadowTmpV(mce, e->Iex.RdTmp.tmp) );

      case Iex_Const:
         return definedOfType(shadowTypeV(typeOfIRExpr(mce->sb->tyenv, e)));

      case Iex_Qop:
         return expr2vbits_Qop(
                   mce,
                   e->Iex.Qop.details->op,
                   e->Iex.Qop.details->arg1, e->Iex.Qop.details->arg2,
                   e->Iex.Qop.details->arg3, e->Iex.Qop.details->arg4
                );

     case Iex_Triop:
        return expr2vbits_Triop(
                   mce,
                   e->Iex.Triop.details->op,
                   e->Iex.Triop.details->arg1, e->Iex.Triop.details->arg2,
                   e->Iex.Triop.details->arg3
                );

      case Iex_Binop:
         return expr2vbits_Binop(
                   mce,
                   e->Iex.Binop.op,
                   e->Iex.Binop.arg1, e->Iex.Binop.arg2
                );

      case Iex_Unop:
         return expr2vbits_Unop( mce, e->Iex.Unop.op, e->Iex.Unop.arg );

      case Iex_Load:
         return expr2vbits_Load( mce, e->Iex.Load.end,
                                      e->Iex.Load.ty,
                                      e->Iex.Load.addr, 0/*addr bias*/,
                                      NULL/* guard == "always True"*/ );

      case Iex_CCall:
         return mkLazyN( mce, e->Iex.CCall.args,
                              e->Iex.CCall.retty,
                              e->Iex.CCall.cee );

      case Iex_ITE:
         return expr2vbits_ITE( mce, e->Iex.ITE.cond, e->Iex.ITE.iftrue,
                                     e->Iex.ITE.iffalse );

      default:
         VG_(printf)("\n");
         ppIRExpr(e);
         VG_(printf)("\n");
         VG_(tool_panic)("tnt_translate.c: expr2vbits: Unhandled expression");
   }
}

// Taintgrind: Same as expr2vbits, except only for Iex_RdTmp & Iex_Const
static
IRExpr* atom2vbits ( MCEnv* mce, IRAtom* atom )
{
   tl_assert(isIRAtom( atom ) );

   switch (atom->tag) {

      case Iex_RdTmp:
         return IRExpr_RdTmp( findShadowTmpV(mce, atom->Iex.RdTmp.tmp) );

      case Iex_Const:
         return definedOfType(shadowTypeV(typeOfIRExpr(mce->sb->tyenv, atom)));

      default:
         VG_(printf)("\n");
         ppIRExpr(atom);
         VG_(printf)("\n");
         VG_(tool_panic)("tnt_translate.c: atom2vbits: Unhandled expression");
   }
}

// Taintgrind: include checks for tainted RdTmp's
static
void do_shadow_WRTMP ( MCEnv* mce, IRStmt *clone, IRTemp tmp, IRExpr* expr )
{
   IRDirty* di2;

   stmt( 'C', mce, IRStmt_WrTmp( tmp, expr ) );

   assign( 'V', mce, findShadowTmpV( mce, tmp ), expr2vbits( mce, expr ) );

   if( expr->tag != Iex_Const ){
      di2 = create_dirty_WRTMP( mce, clone, tmp, expr );

      if( di2 != NULL )
         complainIfTainted( mce, IRExpr_RdTmp( tmp ), di2 );
   }
}

/*------------------------------------------------------------*/
/*--- Generate shadow stmts from all kinds of IRStmts.     ---*/
/*------------------------------------------------------------*/

/* Widen a value to the host word size. */

static
IRExpr* zwidenToHostWord ( MCEnv* mce, IRAtom* vatom )
{
   IRType ty, tyH;

   /* vatom is vbits-value and as such can only have a shadow type. */
   tl_assert(isShadowAtom(mce,vatom));

   ty  = typeOfIRExpr(mce->sb->tyenv, vatom);
   tyH = mce->hWordTy;

   if (tyH == Ity_I32) {
      switch (ty) {
         case Ity_I32:
            return vatom;
         case Ity_I16:
            return assignNew('V', mce, tyH, unop(Iop_16Uto32, vatom));
         case Ity_I8:
            return assignNew('V', mce, tyH, unop(Iop_8Uto32, vatom));
         default:
            goto unhandled;
      }
   } else
   if (tyH == Ity_I64) {
      switch (ty) {
         case Ity_I32:
            return assignNew('V', mce, tyH, unop(Iop_32Uto64, vatom));
         case Ity_I16:
            return assignNew('V', mce, tyH, unop(Iop_32Uto64,
                   assignNew('V', mce, Ity_I32, unop(Iop_16Uto32, vatom))));
         case Ity_I8:
            return assignNew('V', mce, tyH, unop(Iop_32Uto64,
                   assignNew('V', mce, Ity_I32, unop(Iop_8Uto32, vatom))));
         default:
            goto unhandled;
      }
   } else {
      goto unhandled;
   }
  unhandled:
   VG_(printf)("\nty = "); ppIRType(ty); VG_(printf)("\n");
   VG_(tool_panic)("zwidenToHostWord");
}


/* Generate a shadow store.  addr is always the original address atom.
   You can pass in either originals or V-bits for the data atom, but
   obviously not both.  guard :: Ity_I1 controls whether the store
   really happens; NULL means it unconditionally does.  Note that
   guard itself is not checked for definedness; the caller of this
   function must do that if necessary. */

static
void do_shadow_Store ( MCEnv* mce,
                       IRStmt *clone,
                       IREndness end,
                       IRAtom* addr, UInt bias,
                       IRAtom* data, IRAtom* vdata,
                       IRAtom* guard )
{
   IROp     mkAdd;
   IRType   ty, tyAddr;
   void*    helper = NULL;
   const HChar*   hname = NULL;
//   IRConst* c;
   IRDirty* di2;

   tyAddr = mce->hWordTy;
   mkAdd  = tyAddr==Ity_I32 ? Iop_Add32 : Iop_Add64;
   tl_assert( tyAddr == Ity_I32 || tyAddr == Ity_I64 );
   tl_assert( end == Iend_LE || end == Iend_BE );

   if (data) {
      tl_assert(!vdata);
      tl_assert(isOriginalAtom(mce, data));
      tl_assert(bias == 0);
      vdata = atom2vbits( mce, data );
   } else {
      tl_assert(vdata);
   }

   tl_assert(isOriginalAtom(mce,addr));
   tl_assert(isShadowAtom(mce,vdata));

   if (guard) {
      tl_assert(isOriginalAtom(mce, guard));
      tl_assert(typeOfIRExpr(mce->sb->tyenv, guard) == Ity_I1);
   }

   ty = typeOfIRExpr(mce->sb->tyenv, vdata);

   // If we're not doing undefined value checking, pretend that this value
   // is "all valid".  That lets Vex's optimiser remove some of the V bit
   // shadow computation ops that precede it.
   // Taintgrind: Taint away..
/*   if (TNT_(clo_tnt_level) == 1) {
      switch (ty) {
         case Ity_V128: // V128 weirdness
                        c = IRConst_V128(V_BITS16_UNTAINTED); break;
         case Ity_I64:  c = IRConst_U64 (V_BITS64_UNTAINTED); break;
         case Ity_I32:  c = IRConst_U32 (V_BITS32_UNTAINTED); break;
         case Ity_I16:  c = IRConst_U16 (V_BITS16_UNTAINTED); break;
         case Ity_I8:   c = IRConst_U8  (V_BITS8_UNTAINTED);  break;
         default:       VG_(tool_panic)("tnt_translate.c:do_shadow_Store(LE)");
      }
      vdata = IRExpr_Const( c );
   }*/

   /* First, emit a definedness test for the address.  This also sets
      the address (shadow) to 'defined' following the test. */
   // Taintgrind: What to do in the vdata case?
   //        vdata cases (CAS, Dirty) are handled by their resp. shadow routines
   if( data && clone ){
      di2 = create_dirty_STORE( mce, clone, end, 0/*resSC*/, addr, data );
      if ( di2 ) complainIfTainted( mce, addr, di2 );
   }

   /* Now decide which helper function to call to write the data V
      bits into shadow memory. */
   if (end == Iend_LE) {
      switch (ty) {
         case Ity_V256: /* we'll use the helper four times */
         case Ity_V128: /* we'll use the helper twice */
         case Ity_I64: helper = &TNT_(helperc_STOREV64le);
                       hname = "TNT_(helperc_STOREV64le)";
                       break;
         case Ity_I32: helper = &TNT_(helperc_STOREV32le);
                       hname = "TNT_(helperc_STOREV32le)";
                       break;
         case Ity_I16: helper = &TNT_(helperc_STOREV16le);
                       hname = "TNT_(helperc_STOREV16le)";
                       break;
         case Ity_I8:  helper = &TNT_(helperc_STOREV8);
                       hname = "TNT_(helperc_STOREV8)";
                       break;
         default:      VG_(tool_panic)("tnt_translate.c:do_shadow_Store(LE)");
      }
   } else {
      switch (ty) {
         case Ity_V128: /* we'll use the helper twice */
         case Ity_I64: helper = &TNT_(helperc_STOREV64be);
                       hname = "TNT_(helperc_STOREV64be)";
                       break;
         case Ity_I32: helper = &TNT_(helperc_STOREV32be);
                       hname = "TNT_(helperc_STOREV32be)";
                       break;
         case Ity_I16: helper = &TNT_(helperc_STOREV16be);
                       hname = "TNT_(helperc_STOREV16be)";
                       break;
         case Ity_I8:  helper = &TNT_(helperc_STOREV8);
                       hname = "TNT_(helperc_STOREV8)";
                       break;
         default:      VG_(tool_panic)("tnt_translate.c:do_shadow_Store(BE)");
      }
   }

   if (UNLIKELY(ty == Ity_V256)) {

      /* V256-bit case -- phrased in terms of 64 bit units (Qs), with
         Q3 being the most significant lane. */
      /* These are the offsets of the Qs in memory. */
      Int     offQ0, offQ1, offQ2, offQ3;

      /* Various bits for constructing the 4 lane helper calls */
      IRDirty *diQ0,    *diQ1,    *diQ2,    *diQ3;
      IRAtom  *addrQ0,  *addrQ1,  *addrQ2,  *addrQ3;
      IRAtom  *vdataQ0, *vdataQ1, *vdataQ2, *vdataQ3;
      IRAtom  *eBiasQ0, *eBiasQ1, *eBiasQ2, *eBiasQ3;

      if (end == Iend_LE) {
         offQ0 = 0; offQ1 = 8; offQ2 = 16; offQ3 = 24;
      } else {
         offQ3 = 0; offQ2 = 8; offQ1 = 16; offQ0 = 24;
      }

      eBiasQ0 = tyAddr==Ity_I32 ? mkU32(bias+offQ0) : mkU64(bias+offQ0);
      addrQ0  = assignNew('V', mce, tyAddr, binop(mkAdd, addr, eBiasQ0) );
      vdataQ0 = assignNew('V', mce, Ity_I64, unop(Iop_V256to64_0, vdata));
      diQ0    = unsafeIRDirty_0_N(
                   1/*regparms*/,
                   hname, VG_(fnptr_to_fnentry)( helper ),
                   mkIRExprVec_2( addrQ0, vdataQ0 )
                );

      eBiasQ1 = tyAddr==Ity_I32 ? mkU32(bias+offQ1) : mkU64(bias+offQ1);
      addrQ1  = assignNew('V', mce, tyAddr, binop(mkAdd, addr, eBiasQ1) );
      vdataQ1 = assignNew('V', mce, Ity_I64, unop(Iop_V256to64_1, vdata));
      diQ1    = unsafeIRDirty_0_N(
                   1/*regparms*/,
                   hname, VG_(fnptr_to_fnentry)( helper ),
                   mkIRExprVec_2( addrQ1, vdataQ1 )
                );

      eBiasQ2 = tyAddr==Ity_I32 ? mkU32(bias+offQ2) : mkU64(bias+offQ2);
      addrQ2  = assignNew('V', mce, tyAddr, binop(mkAdd, addr, eBiasQ2) );
      vdataQ2 = assignNew('V', mce, Ity_I64, unop(Iop_V256to64_2, vdata));
      diQ2    = unsafeIRDirty_0_N(
                   1/*regparms*/,
                   hname, VG_(fnptr_to_fnentry)( helper ),
                   mkIRExprVec_2( addrQ2, vdataQ2 )
                );

      eBiasQ3 = tyAddr==Ity_I32 ? mkU32(bias+offQ3) : mkU64(bias+offQ3);
      addrQ3  = assignNew('V', mce, tyAddr, binop(mkAdd, addr, eBiasQ3) );
      vdataQ3 = assignNew('V', mce, Ity_I64, unop(Iop_V256to64_3, vdata));
      diQ3    = unsafeIRDirty_0_N(
                   1/*regparms*/,
                   hname, VG_(fnptr_to_fnentry)( helper ),
                   mkIRExprVec_2( addrQ3, vdataQ3 )
                );
      if (guard)
         diQ0->guard = diQ1->guard = diQ2->guard = diQ3->guard = guard;

      setHelperAnns( mce, diQ0 );
      setHelperAnns( mce, diQ1 );
      setHelperAnns( mce, diQ2 );
      setHelperAnns( mce, diQ3 );
      stmt( 'V', mce, IRStmt_Dirty(diQ0) );
      stmt( 'V', mce, IRStmt_Dirty(diQ1) );
      stmt( 'V', mce, IRStmt_Dirty(diQ2) );
      stmt( 'V', mce, IRStmt_Dirty(diQ3) );

   }
   else if (UNLIKELY(ty == Ity_V128)) {

      /* V128-bit case */
      /* See comment in next clause re 64-bit regparms */
      /* also, need to be careful about endianness */

      Int     offLo64, offHi64;
      IRDirty *diLo64, *diHi64;
      IRAtom  *addrLo64, *addrHi64;
      IRAtom  *vdataLo64, *vdataHi64;
      IRAtom  *eBiasLo64, *eBiasHi64;

      if (end == Iend_LE) {
         offLo64 = 0;
         offHi64 = 8;
      } else {
         offLo64 = 8;
         offHi64 = 0;
      }

      eBiasLo64 = tyAddr==Ity_I32 ? mkU32(bias+offLo64) : mkU64(bias+offLo64);
      addrLo64  = assignNew('V', mce, tyAddr, binop(mkAdd, addr, eBiasLo64) );
      vdataLo64 = assignNew('V', mce, Ity_I64, unop(Iop_V128to64, vdata));
      diLo64    = unsafeIRDirty_0_N(
                     1/*regparms*/,
                     hname, VG_(fnptr_to_fnentry)( helper ),
                     mkIRExprVec_2( addrLo64, vdataLo64 )
                  );
      eBiasHi64 = tyAddr==Ity_I32 ? mkU32(bias+offHi64) : mkU64(bias+offHi64);
      addrHi64  = assignNew('V', mce, tyAddr, binop(mkAdd, addr, eBiasHi64) );
      vdataHi64 = assignNew('V', mce, Ity_I64, unop(Iop_V128HIto64, vdata));
      diHi64    = unsafeIRDirty_0_N(
                     1/*regparms*/,
                     hname, VG_(fnptr_to_fnentry)( helper ),
                     mkIRExprVec_2( addrHi64, vdataHi64 )
                  );
      if (guard) diLo64->guard = guard;
      if (guard) diHi64->guard = guard;
      setHelperAnns( mce, diLo64 );
      setHelperAnns( mce, diHi64 );
      stmt( 'V', mce, IRStmt_Dirty(diLo64) );
      stmt( 'V', mce, IRStmt_Dirty(diHi64) );

   } else {

      IRDirty *di;
      IRAtom  *addrAct;

      /* 8/16/32/64-bit cases */
      /* Generate the actual address into addrAct. */
      if (bias == 0) {
         addrAct = addr;
      } else {
         IRAtom* eBias   = tyAddr==Ity_I32 ? mkU32(bias) : mkU64(bias);
         addrAct = assignNew('V', mce, tyAddr, binop(mkAdd, addr, eBias));
      }

      if (ty == Ity_I64) {
         /* We can't do this with regparm 2 on 32-bit platforms, since
            the back ends aren't clever enough to handle 64-bit
            regparm args.  Therefore be different. */
         di = unsafeIRDirty_0_N(
                 1/*regparms*/,
                 hname, VG_(fnptr_to_fnentry)( helper ),
                 mkIRExprVec_2( addrAct, vdata )
              );
      } else {
         di = unsafeIRDirty_0_N(
                 2/*regparms*/,
                 hname, VG_(fnptr_to_fnentry)( helper ),
                 mkIRExprVec_2( addrAct,
                                zwidenToHostWord( mce, vdata ))
              );
      }
      if (guard) di->guard = guard;
      setHelperAnns( mce, di );
      stmt( 'V', mce, IRStmt_Dirty(di) );
   }
}


/* Do lazy pessimistic propagation through a dirty helper call, by
   looking at the annotations on it.  This is the most complex part of
   Memcheck. */

static IRType szToITy ( Int n )
{
   switch (n) {
      case 1: return Ity_I8;
      case 2: return Ity_I16;
      case 4: return Ity_I32;
      case 8: return Ity_I64;
      default: VG_(tool_panic)("tnt_translate.c: szToITy");
   }
}

static
void do_shadow_Dirty ( MCEnv* mce, IRDirty* d )
{
   Int       i, k, n, toDo, gSz, gOff;
   IRAtom    *src, *here, *curr;
   IRType    tySrc, tyDst;
   IRTemp    dst;
   IREndness end;

   IRDirty* di2;

   // Taintgrind: Like an IRStmt WrTmp, we need to execute the stmt
   //          before we can read the contents of d->tmp
   stmt('C', mce, IRStmt_Dirty( d ) );

   /* What's the native endianness?  We need to know this. */
#  if defined(VG_BIGENDIAN)
   end = Iend_BE;
#  elif defined(VG_LITTLEENDIAN)
   end = Iend_LE;
#  else
#    error "Unknown endianness"
#  endif

   /* First check the guard. */
   // complainIfUndefined(mce, d->guard);

   /* Now round up all inputs and PCast over them. */
   curr = definedOfType(Ity_I32);

   /* Inputs: unmasked args */
   for (i = 0; d->args[i]; i++) {
      IRAtom* arg = d->args[i];
      if (d->cee->mcx_mask & (1<<i)
           || UNLIKELY(is_IRExpr_VECRET_or_BBPTR(arg)) ) {
         /* ignore this arg */
      } else {
         here = mkPCastTo( mce, Ity_I32, atom2vbits(mce, arg) );
         curr = mkUifU32(mce, here, curr);
      }
   }

   /* Inputs: guest state that we read. */
   for (i = 0; i < d->nFxState; i++) {
      tl_assert(d->fxState[i].fx != Ifx_None);
      if (d->fxState[i].fx == Ifx_Write)
         continue;

      /* Enumerate the described state segments */
      for (k = 0; k < 1 + d->fxState[i].nRepeats; k++) {
         gOff = d->fxState[i].offset + k * d->fxState[i].repeatLen;
         gSz  = d->fxState[i].size;

         /* Ignore any sections marked as 'always defined'. */
         if (isAlwaysDefd(mce, gOff, gSz)) {
            if (0)
            VG_(printf)("tnt_translate: Dirty gst: ignored off %d, sz %d\n",
                        gOff, gSz);
            continue;
         }

         /* This state element is read or modified.  So we need to
            consider it.  If larger than 8 bytes, deal with it in
            8-byte chunks. */
         while (True) {
            tl_assert(gSz >= 0);
            if (gSz == 0) break;
            n = gSz <= 8 ? gSz : 8;
            /* update 'curr' with UifU of the state slice 
               gOff .. gOff+n-1 */
            tySrc = szToITy( n );

            /* Observe the guard expression. If it is false use an
               all-bits-defined bit pattern */
            IRAtom *cond, *iffalse, *iftrue;

            cond    = assignNew('V', mce, Ity_I1, d->guard);
            iftrue  = assignNew('V', mce, tySrc, shadow_GET(mce, gOff, tySrc));
            iffalse = assignNew('V', mce, tySrc, definedOfType(tySrc));
            src     = assignNew('V', mce, tySrc,
                                IRExpr_ITE(cond, iftrue, iffalse));

            here = mkPCastTo( mce, Ity_I32, src );
            curr = mkUifU32(mce, here, curr);
            gSz -= n;
            gOff += n;
         }
      }
   }

   /* Inputs: memory.  First set up some info needed regardless of
      whether we're doing reads or writes. */

   if (d->mFx != Ifx_None) {
      /* Because we may do multiple shadow loads/stores from the same
         base address, it's best to do a single test of its
         definedness right now.  Post-instrumentation optimisation
         should remove all but this test. */
      IRType tyAddr;
      tl_assert(d->mAddr);

      tyAddr = typeOfIRExpr(mce->sb->tyenv, d->mAddr);
      tl_assert(tyAddr == Ity_I32 || tyAddr == Ity_I64);
      tl_assert(tyAddr == mce->hWordTy); /* not really right */
   }

   /* Deal with memory inputs (reads or modifies) */
   if (d->mFx == Ifx_Read || d->mFx == Ifx_Modify) {
      toDo   = d->mSize;
      /* chew off 32-bit chunks.  We don't care about the endianness
         since it's all going to be condensed down to a single bit,
         but nevertheless choose an endianness which is hopefully
         native to the platform. */
      while (toDo >= 4) {
         here = mkPCastTo(
                   mce, Ity_I32,
                   expr2vbits_Load_guarded_Simple(
                      mce, end, Ity_I32, d->mAddr, d->mSize - toDo, d->guard )
                );
         curr = mkUifU32(mce, here, curr);
         toDo -= 4;
      }
      /* chew off 16-bit chunks */
      while (toDo >= 2) {
         here = mkPCastTo(
                   mce, Ity_I32,
                   expr2vbits_Load_guarded_Simple(
                      mce, end, Ity_I16, d->mAddr, d->mSize - toDo, d->guard )
                );
         curr = mkUifU32(mce, here, curr);
         toDo -= 2;
      }
      /* chew off the remaining 8-bit chunk, if any */
      if (toDo == 1) {
         here = mkPCastTo(
                   mce, Ity_I32,
                   expr2vbits_Load_guarded_Simple(
                      mce, end, Ity_I8, d->mAddr, d->mSize - toDo, d->guard )
                );
         curr = mkUifU32(mce, here, curr);
         toDo -= 1;
      }
      tl_assert(toDo == 0); /* also need to handle 1-byte excess */
   }

   /* Whew!  So curr is a 32-bit V-value summarising pessimistically
      all the inputs to the helper.  Now we need to re-distribute the
      results to all destinations. */

   /* Outputs: the destination temporary, if there is one. */
   if (d->tmp != IRTemp_INVALID) {
      dst   = findShadowTmpV(mce, d->tmp);
      tyDst = typeOfIRTemp(mce->sb->tyenv, d->tmp);
      assign( 'V', mce, dst, mkPCastTo( mce, tyDst, curr) );
   }

   /* Outputs: guest state that we write or modify. */
   for (i = 0; i < d->nFxState; i++) {
      tl_assert(d->fxState[i].fx != Ifx_None);
      if (d->fxState[i].fx == Ifx_Read)
         continue;

      /* Enumerate the described state segments */
      for (k = 0; k < 1 + d->fxState[i].nRepeats; k++) {
         gOff = d->fxState[i].offset + k * d->fxState[i].repeatLen;
         gSz  = d->fxState[i].size;

         /* Ignore any sections marked as 'always defined'. */
         if (isAlwaysDefd(mce, gOff, gSz))
            continue;

         /* This state element is written or modified.  So we need to
            consider it.  If larger than 8 bytes, deal with it in
            8-byte chunks. */
         while (True) {
            tl_assert(gSz >= 0);
            if (gSz == 0) break;
            n = gSz <= 8 ? gSz : 8;
            /* Write suitably-casted 'curr' to the state slice 
               gOff .. gOff+n-1 */
            tyDst = szToITy( n );
            do_shadow_PUT( mce, NULL /*clone*/, gOff,
                                NULL, /* original atom */
                                mkPCastTo( mce, tyDst, curr ), d->guard );
            gSz -= n;
            gOff += n;
         }
      }
   }

   /* Outputs: memory that we write or modify.  Same comments about
      endianness as above apply. */
   if (d->mFx == Ifx_Write || d->mFx == Ifx_Modify) {
      toDo   = d->mSize;
      /* chew off 32-bit chunks */
      while (toDo >= 4) {
         do_shadow_Store( mce, NULL/*clone*/, end, d->mAddr, d->mSize - toDo,
                          NULL, /* original data */
                          mkPCastTo( mce, Ity_I32, curr ),
                          NULL/*guard*/ );
         toDo -= 4;
      }
      /* chew off 16-bit chunks */
      while (toDo >= 2) {
         do_shadow_Store( mce, NULL/*clone*/, end, d->mAddr, d->mSize - toDo,
                          NULL, /* original data */
                          mkPCastTo( mce, Ity_I16, curr ),
                          NULL/*guard*/ );
         toDo -= 2;
      }
      tl_assert(toDo == 0); /* also need to handle 1-byte excess */
   }

   // Taintgrind: Check for taint
   di2 = create_dirty_DIRTY( mce, d );
   complainIfTainted(mce, NULL /*d->guard*/, di2);
}

/* We have an ABI hint telling us that [base .. base+len-1] is to
   become undefined ("writable").  Generate code to call a helper to
   notify the A/V bit machinery of this fact.

   We call
   void MC_(helperc_MAKE_STACK_UNINIT) ( Addr base, UWord len,
                                                    Addr nia );
*/
/*static
void do_AbiHint ( MCEnv* mce, IRExpr* base, Int len, IRExpr* nia )
{
   IRDirty* di;*/
   /* Minor optimisation: if not doing origin tracking, ignore the
      supplied nia and pass zero instead.  This is on the basis that
      MC_(helperc_MAKE_STACK_UNINIT) will ignore it anyway, and we can
      almost always generate a shorter instruction to put zero into a
      register than any other value. */

//   Taintgrind: We're not doing origin tracking
//   if (MC_(clo_mc_level) < 3)
//      nia = mkIRExpr_HWord(0);

//   di = unsafeIRDirty_0_N(
//           0/*regparms*/,
//           "MC_(helperc_MAKE_STACK_UNINIT)",
//           VG_(fnptr_to_fnentry)( &TNT_(helperc_MAKE_STACK_UNINIT) ),
//           mkIRExprVec_3( base, mkIRExpr_HWord( (UInt)len), nia )
//        );
//   stmt( 'V', mce, IRStmt_Dirty(di) );
//}


/* ------ Dealing with IRCAS (big and complex) ------ */ //3434

/* FWDS */
static void do_shadow_CAS_single ( MCEnv* mce, IRCAS* cas );
static void do_shadow_CAS_double ( MCEnv* mce, IRCAS* cas );

static
void do_shadow_CAS ( MCEnv* mce, IRCAS* cas )
{
   IRDirty* di2;

   /* Scheme is (both single- and double- cases):

      1. fetch data#,dataB (the proposed new value)

      2. fetch expd#,expdB (what we expect to see at the address)

      3. check definedness of address

      4. load old#,oldB from shadow memory; this also checks
         addressibility of the address

      5. the CAS itself

      6. compute "expected == old".  See COMMENT_ON_CasCmpEQ below.

      7. if "expected == old" (as computed by (6))
            store data#,dataB to shadow memory
   */
   if (cas->oldHi == IRTemp_INVALID) {
      do_shadow_CAS_single( mce, cas );
   } else {
      do_shadow_CAS_double( mce, cas );
   }

   // Taintgrind: Check for taint
   di2 = create_dirty_CAS( mce, cas );
   complainIfTainted( mce, NULL, di2 );
}

static void bind_shadow_tmp_to_orig ( UChar how,
                                      MCEnv* mce,
                                      IRAtom* orig, IRAtom* shadow )
{
   tl_assert(isOriginalAtom(mce, orig));
   tl_assert(isShadowAtom(mce, shadow));
   switch (orig->tag) {
      case Iex_Const:
         tl_assert(shadow->tag == Iex_Const);
         break;
      case Iex_RdTmp:
         tl_assert(shadow->tag == Iex_RdTmp);
         if (how == 'V') {
            assign('V', mce, findShadowTmpV(mce,orig->Iex.RdTmp.tmp),
                   shadow);
         }/* else {
            tl_assert(how == 'B');
            assign('B', mce, findShadowTmpB(mce,orig->Iex.RdTmp.tmp),
                   shadow);
         }*/ // Taintgrind: Not origin tracking
         break;
      default:
         tl_assert(0);
   }
}


static void do_shadow_CAS_single ( MCEnv* mce, IRCAS* cas )
{
   IRAtom *vdataLo = NULL/*, *bdataLo = NULL*/;
   IRAtom *vexpdLo = NULL/*, *bexpdLo = NULL*/;
   IRAtom *voldLo  = NULL/*, *boldLo  = NULL*/;
   IRAtom *expd_eq_old = NULL;
   IROp   opCasCmpEQ;
   //Int    elemSzB;
   IRType elemTy;
//   Bool   otrak = TNT_(clo_tnt_level) >= 3; /* a shorthand */

   /* single CAS */
   tl_assert(cas->oldHi == IRTemp_INVALID);
   tl_assert(cas->expdHi == NULL);
   tl_assert(cas->dataHi == NULL);

   elemTy = typeOfIRExpr(mce->sb->tyenv, cas->expdLo);
   switch (elemTy) {
      case Ity_I8:  /*elemSzB = 1;*/ opCasCmpEQ = Iop_CasCmpEQ8;  break;
      case Ity_I16: /*elemSzB = 2;*/ opCasCmpEQ = Iop_CasCmpEQ16; break;
      case Ity_I32: /*elemSzB = 4;*/ opCasCmpEQ = Iop_CasCmpEQ32; break;
      case Ity_I64: /*elemSzB = 8;*/ opCasCmpEQ = Iop_CasCmpEQ64; break;
      default: tl_assert(0); /* IR defn disallows any other types */
   }

   /* 1. fetch data# (the proposed new value) */
   tl_assert(isOriginalAtom(mce, cas->dataLo));
   vdataLo
      = assignNew('V', mce, elemTy, atom2vbits(mce, cas->dataLo));
   tl_assert(isShadowAtom(mce, vdataLo));

   // Taintgrind: Not tracking
/*   if (otrak) {
      bdataLo
         = assignNew('B', mce, Ity_I32, schemeE(mce, cas->dataLo));
      tl_assert(isShadowAtom(mce, bdataLo));
   }*/

   /* 2. fetch expected# (what we expect to see at the address) */
   tl_assert(isOriginalAtom(mce, cas->expdLo));
   vexpdLo
      = assignNew('V', mce, elemTy, atom2vbits(mce, cas->expdLo));
   tl_assert(isShadowAtom(mce, vexpdLo));

   // Taintgrind: Not tracking
//   if (otrak) {
//      bexpdLo
//         = assignNew('B', mce, Ity_I32, schemeE(mce, cas->expdLo));
//      tl_assert(isShadowAtom(mce, bexpdLo));
//   }

   /* 3. check definedness of address */
   /* 4. fetch old# from shadow memory; this also checks
         addressibility of the address */
   voldLo
      = assignNew(
           'V', mce, elemTy,
           expr2vbits_Load(
              mce,
              cas->end, elemTy, cas->addr, 0/*Addr bias*/,
              NULL/*always happens*/
        ));
   bind_shadow_tmp_to_orig('V', mce, mkexpr(cas->oldLo), voldLo);

   // Taintgrind: Not tracking
//   if (otrak) {
//      boldLo
//         = assignNew('B', mce, Ity_I32,
//                     gen_load_b(mce, elemSzB, cas->addr, 0/*addr bias*/));
//      bind_shadow_tmp_to_orig('B', mce, mkexpr(cas->oldLo), boldLo);
//   }

   /* 5. the CAS itself */
   stmt( 'C', mce, IRStmt_CAS(cas) );

   /* 6. compute "expected == old" */
   /* See COMMENT_ON_CasCmpEQ in this file background/rationale. */
   /* Note that 'C' is kinda faking it; it is indeed a non-shadow
      tree, but it's not copied from the input block. */
   expd_eq_old
      = assignNew('C', mce, Ity_I1,
                  binop(opCasCmpEQ, cas->expdLo, mkexpr(cas->oldLo)));

   /* 7. if "expected == old"
            store data# to shadow memory */

   do_shadow_Store( mce, NULL/*clone*/, cas->end, cas->addr, 0/*bias*/,
                    NULL/*data*/, vdataLo/*vdata*/,
                    expd_eq_old/*guard for store*/ );
   // Taintgrind: Not tracking
//   if (otrak) {
//      gen_store_b( mce, elemSzB, cas->addr, 0/*offset*/,
//                   bdataLo/*bdata*/,
//                   expd_eq_old/*guard for store*/ );
//   }
}


static void do_shadow_CAS_double ( MCEnv* mce, IRCAS* cas )
{
   IRAtom *vdataHi = NULL/*, *bdataHi = NULL*/;
   IRAtom *vdataLo = NULL/*, *bdataLo = NULL*/;
   IRAtom *vexpdHi = NULL/*, *bexpdHi = NULL*/;
   IRAtom *vexpdLo = NULL/*, *bexpdLo = NULL*/;
   IRAtom *voldHi  = NULL/*, *boldHi  = NULL*/;
   IRAtom *voldLo  = NULL/*, *boldLo  = NULL*/;
   IRAtom *xHi = NULL, *xLo = NULL, *xHL = NULL;
   IRAtom *expd_eq_old = NULL, *zero = NULL;
   IROp   opCasCmpEQ, opOr, opXor;
   Int    elemSzB, memOffsLo, memOffsHi;
   IRType elemTy;
//   Bool   otrak = TNT_(clo_tnt_level) >= 3; /* a shorthand */

   /* double CAS */
   tl_assert(cas->oldHi != IRTemp_INVALID);
   tl_assert(cas->expdHi != NULL);
   tl_assert(cas->dataHi != NULL);

   elemTy = typeOfIRExpr(mce->sb->tyenv, cas->expdLo);
   switch (elemTy) {
      case Ity_I8:
         opCasCmpEQ = Iop_CasCmpEQ8; opOr = Iop_Or8; opXor = Iop_Xor8;
         elemSzB = 1; zero = mkU8(0);
         break;
      case Ity_I16:
         opCasCmpEQ = Iop_CasCmpEQ16; opOr = Iop_Or16; opXor = Iop_Xor16;
         elemSzB = 2; zero = mkU16(0);
         break;
      case Ity_I32:
         opCasCmpEQ = Iop_CasCmpEQ32; opOr = Iop_Or32; opXor = Iop_Xor32;
         elemSzB = 4; zero = mkU32(0);
         break;
      case Ity_I64:
         opCasCmpEQ = Iop_CasCmpEQ64; opOr = Iop_Or64; opXor = Iop_Xor64;
         elemSzB = 8; zero = mkU64(0);
         break;
      default:
         tl_assert(0); /* IR defn disallows any other types */
   }

   /* 1. fetch data# (the proposed new value) */
   tl_assert(isOriginalAtom(mce, cas->dataHi));
   tl_assert(isOriginalAtom(mce, cas->dataLo));
   vdataHi
      = assignNew('V', mce, elemTy, atom2vbits(mce, cas->dataHi));
   vdataLo
      = assignNew('V', mce, elemTy, atom2vbits(mce, cas->dataLo));
   tl_assert(isShadowAtom(mce, vdataHi));
   tl_assert(isShadowAtom(mce, vdataLo));

   // Taintgrind: Not tracking
/*   if (otrak) {
      bdataHi
         = assignNew('B', mce, Ity_I32, schemeE(mce, cas->dataHi));
      bdataLo
         = assignNew('B', mce, Ity_I32, schemeE(mce, cas->dataLo));
      tl_assert(isShadowAtom(mce, bdataHi));
      tl_assert(isShadowAtom(mce, bdataLo));
   }
*/

   /* 2. fetch expected# (what we expect to see at the address) */
   tl_assert(isOriginalAtom(mce, cas->expdHi));
   tl_assert(isOriginalAtom(mce, cas->expdLo));
   vexpdHi
      = assignNew('V', mce, elemTy, atom2vbits(mce, cas->expdHi));
   vexpdLo
      = assignNew('V', mce, elemTy, atom2vbits(mce, cas->expdLo));
   tl_assert(isShadowAtom(mce, vexpdHi));
   tl_assert(isShadowAtom(mce, vexpdLo));

   // Taintgrind: Not tracking
/*   if (otrak) {
      bexpdHi
         = assignNew('B', mce, Ity_I32, schemeE(mce, cas->expdHi));
      bexpdLo
         = assignNew('B', mce, Ity_I32, schemeE(mce, cas->expdLo));
      tl_assert(isShadowAtom(mce, bexpdHi));
      tl_assert(isShadowAtom(mce, bexpdLo));
   }
*/

   /* 3. check definedness of address */
   /* 4. fetch old# from shadow memory; this also checks
         addressibility of the address */
   if (cas->end == Iend_LE) {
      memOffsLo = 0;
      memOffsHi = elemSzB;
   } else {
      tl_assert(cas->end == Iend_BE);
      memOffsLo = elemSzB;
      memOffsHi = 0;
   }
//   di2 = create_dirty_CAS_LD_ADDR( mce, cas );
   voldHi
      = assignNew(
           'V', mce, elemTy,
           expr2vbits_Load(
              mce,
              cas->end, elemTy, cas->addr, memOffsHi/*Addr bias*/,
              NULL/*always happens*/
        ));
//   di2 = create_dirty_CAS_LD_ADDR( mce, cas );
   voldLo
      = assignNew(
           'V', mce, elemTy,
           expr2vbits_Load(
              mce,
              cas->end, elemTy, cas->addr, memOffsLo/*Addr bias*/,
              NULL/*always happens*/
        ));
   bind_shadow_tmp_to_orig('V', mce, mkexpr(cas->oldHi), voldHi);
   bind_shadow_tmp_to_orig('V', mce, mkexpr(cas->oldLo), voldLo);

   // Taintgrind: Not tracking
//   if (otrak) {
//      boldHi
//         = assignNew('B', mce, Ity_I32,
//                     gen_load_b(mce, elemSzB, cas->addr,
//                                memOffsHi/*addr bias*/));
//      boldLo
//         = assignNew('B', mce, Ity_I32,
//                     gen_load_b(mce, elemSzB, cas->addr,
//                                memOffsLo/*addr bias*/));
//      bind_shadow_tmp_to_orig('B', mce, mkexpr(cas->oldHi), boldHi);
//      bind_shadow_tmp_to_orig('B', mce, mkexpr(cas->oldLo), boldLo);
//   }

   /* 5. the CAS itself */
   stmt( 'C', mce, IRStmt_CAS(cas) );

   /* 6. compute "expected == old" */
   /* See COMMENT_ON_CasCmpEQ in this file background/rationale. */
   /* Note that 'C' is kinda faking it; it is indeed a non-shadow
      tree, but it's not copied from the input block. */
   /*
      xHi = oldHi ^ expdHi;
      xLo = oldLo ^ expdLo;
      xHL = xHi | xLo;
      expd_eq_old = xHL == 0;
   */
   xHi = assignNew('C', mce, elemTy,
                   binop(opXor, cas->expdHi, mkexpr(cas->oldHi)));
   xLo = assignNew('C', mce, elemTy,
                   binop(opXor, cas->expdLo, mkexpr(cas->oldLo)));
   xHL = assignNew('C', mce, elemTy,
                   binop(opOr, xHi, xLo));
   expd_eq_old
      = assignNew('C', mce, Ity_I1,
                  binop(opCasCmpEQ, xHL, zero));

   /* 7. if "expected == old"
            store data# to shadow memory */
   do_shadow_Store( mce, NULL/*clone*/, cas->end, cas->addr, memOffsHi/*bias*/,
                    NULL/*data*/, vdataHi/*vdata*/,
                    expd_eq_old/*guard for store*/ );
   do_shadow_Store( mce, NULL/*clone*/, cas->end, cas->addr, memOffsLo/*bias*/,
                    NULL/*data*/, vdataLo/*vdata*/,
                    expd_eq_old/*guard for store*/ );
   // Taintgrind: Not tracking
//   if (otrak) {
//      gen_store_b( mce, elemSzB, cas->addr, memOffsHi/*offset*/,
//                   bdataHi/*bdata*/,
//                   expd_eq_old/*guard for store*/ );
//      gen_store_b( mce, elemSzB, cas->addr, memOffsLo/*offset*/,
//                   bdataLo/*bdata*/,
//                   expd_eq_old/*guard for store*/ );
//   }
}


/* ------ Dealing with LL/SC (not difficult) ------ */

static void do_shadow_LLSC ( MCEnv*    mce,
                             IREndness stEnd,
                             IRTemp    stResult,
                             IRExpr*   stAddr,
                             IRExpr*   stStoredata )
{
   /* In short: treat a load-linked like a normal load followed by an
      assignment of the loaded (shadow) data to the result temporary.
      Treat a store-conditional like a normal store, and mark the
      result temporary as defined. */
   IRType resTy  = typeOfIRTemp(mce->sb->tyenv, stResult);
   IRTemp resTmp = findShadowTmpV(mce, stResult);

   tl_assert(isIRAtom(stAddr));
   if (stStoredata)
      tl_assert(isIRAtom(stStoredata));

   if (stStoredata == NULL) {
      /* Load Linked */
      /* Just treat this as a normal load, followed by an assignment of
         the value to .result. */
      /* Stay sane */
      tl_assert(resTy == Ity_I64 || resTy == Ity_I32
                || resTy == Ity_I16 || resTy == Ity_I8);
      assign( 'V', mce, resTmp,
                   expr2vbits_Load(
                      mce, stEnd, resTy, stAddr, 0/*addr bias*/,
                      NULL/*always happens*/) );
   } else {
      /* Store Conditional */
      /* Stay sane */
      IRType dataTy = typeOfIRExpr(mce->sb->tyenv,
                                   stStoredata);
      tl_assert(dataTy == Ity_I64 || dataTy == Ity_I32
                || dataTy == Ity_I16 || dataTy == Ity_I8);
      do_shadow_Store( mce, NULL /*clone*/, stEnd,
                            stAddr, 0/* addr bias */,
                            stStoredata,
                            NULL /* shadow data */,
                            NULL/*guard*/ );
      /* This is a store conditional, so it writes to .result a value
         indicating whether or not the store succeeded.  Just claim
         this value is always defined.  In the PowerPC interpretation
         of store-conditional, definedness of the success indication
         depends on whether the address of the store matches the
         reservation address.  But we can't tell that here (and
         anyway, we're not being PowerPC-specific).  At least we are
         guaranteed that the definedness of the store address, and its
         addressibility, will be checked as per normal.  So it seems
         pretty safe to just say that the success indication is always
         defined.

         In schemeS, for origin tracking, we must correspondingly set
         a no-origin value for the origin shadow of .result.
      */
      tl_assert(resTy == Ity_I1);
      assign( 'V', mce, resTmp, definedOfType(resTy) );
   }
}


/* ---- Dealing with LoadG/StoreG (not entirely simple) ---- */

static void do_shadow_StoreG ( MCEnv* mce, IRStoreG* sg )
{
   //complainIfUndefined(mce, sg->guard, NULL);
   /* do_shadow_Store will generate code to check the definedness and
      validity of sg->addr, in the case where sg->guard evaluates to
      True at run-time. */
   do_shadow_Store( mce, NULL /*clone*/, sg->end,
                    sg->addr, 0/* addr bias */,
                    sg->data,
                    NULL /* shadow data */,
                    sg->guard );
}

static void do_shadow_LoadG ( MCEnv* mce, IRLoadG* lg )
{
   //complainIfUndefined(mce, lg->guard, NULL);
   /* expr2vbits_Load_guarded_General will generate code to check the
      definedness and validity of lg->addr, in the case where
      lg->guard evaluates to True at run-time. */

   /* Look at the LoadG's built-in conversion operation, to determine
      the source (actual loaded data) type, and the equivalent IROp.
      NOTE that implicitly we are taking a widening operation to be
      applied to original atoms and producing one that applies to V
      bits.  Since signed and unsigned widening are self-shadowing,
      this is a straight copy of the op (modulo swapping from the
      IRLoadGOp form to the IROp form).  Note also therefore that this
      implicitly duplicates the logic to do with said widening ops in
      expr2vbits_Unop.  See comment at the start of expr2vbits_Unop. */
   IROp   vwiden   = Iop_INVALID;
   IRType loadedTy = Ity_INVALID;
   switch (lg->cvt) {
      case ILGop_Ident32: loadedTy = Ity_I32; vwiden = Iop_INVALID; break;
      case ILGop_16Uto32: loadedTy = Ity_I16; vwiden = Iop_16Uto32; break;
      case ILGop_16Sto32: loadedTy = Ity_I16; vwiden = Iop_16Sto32; break;
      case ILGop_8Uto32:  loadedTy = Ity_I8;  vwiden = Iop_8Uto32;  break;
      case ILGop_8Sto32:  loadedTy = Ity_I8;  vwiden = Iop_8Sto32;  break;
      default: VG_(tool_panic)("do_shadow_LoadG");
   }

   IRAtom* vbits_alt
      = expr2vbits( mce, lg->alt );
   IRAtom* vbits_final
      = expr2vbits_Load_guarded_General(mce, lg->end, loadedTy,
                                        lg->addr, 0/*addr bias*/,
                                        lg->guard, vwiden, vbits_alt );
   /* And finally, bind the V bits to the destination temporary. */
   assign( 'V', mce, findShadowTmpV(mce, lg->dst), vbits_final );
}

/*------------------------------------------------------------*/
/*--- Main instrumentation routines                        ---*/
/*------------------------------------------------------------*/

//static void schemeS ( MCEnv* mce, IRStmt* st );

static Bool isBogusAtom ( IRAtom* at )
{
   ULong n = 0;
   IRConst* con;
   tl_assert(isIRAtom(at));
   if (at->tag == Iex_RdTmp)
      return False;
   tl_assert(at->tag == Iex_Const);
   con = at->Iex.Const.con;
   switch (con->tag) {
      case Ico_U1:   return False;
      case Ico_U8:   n = (ULong)con->Ico.U8; break;
      case Ico_U16:  n = (ULong)con->Ico.U16; break;
      case Ico_U32:  n = (ULong)con->Ico.U32; break;
      case Ico_U64:  n = (ULong)con->Ico.U64; break;
      case Ico_F64:  return False;
      case Ico_F64i: return False;
      case Ico_V128: return False;
      default: ppIRExpr(at); tl_assert(0);
   }
   /* VG_(printf)("%llx\n", n); */
   return (/*32*/    n == 0xFEFEFEFFULL
           /*32*/ || n == 0x80808080ULL
           /*32*/ || n == 0x7F7F7F7FULL
           /*64*/ || n == 0xFFFFFFFFFEFEFEFFULL
           /*64*/ || n == 0xFEFEFEFEFEFEFEFFULL
           /*64*/ || n == 0x0000000000008080ULL
           /*64*/ || n == 0x8080808080808080ULL
           /*64*/ || n == 0x0101010101010101ULL
          );
}

static Bool checkForBogusLiterals ( /*FLAT*/ IRStmt* st )
{
   Int      i;
   IRExpr*  e;
   IRDirty* d;
   IRCAS*   cas;
   switch (st->tag) {
      case Ist_WrTmp:
         e = st->Ist.WrTmp.data;
         switch (e->tag) {
            case Iex_Get:
            case Iex_RdTmp:
               return False;
            case Iex_Const:
               return isBogusAtom(e);
            case Iex_Unop:
               return isBogusAtom(e->Iex.Unop.arg);
            case Iex_GetI:
               return isBogusAtom(e->Iex.GetI.ix);
            case Iex_Binop:
               return isBogusAtom(e->Iex.Binop.arg1)
                      || isBogusAtom(e->Iex.Binop.arg2);
            case Iex_Triop:
               return isBogusAtom(e->Iex.Triop.details->arg1)
                      || isBogusAtom(e->Iex.Triop.details->arg2)
                      || isBogusAtom(e->Iex.Triop.details->arg3);
            case Iex_Qop:
               return isBogusAtom(e->Iex.Qop.details->arg1)
                      || isBogusAtom(e->Iex.Qop.details->arg2)
                      || isBogusAtom(e->Iex.Qop.details->arg3)
                      || isBogusAtom(e->Iex.Qop.details->arg4);
            case Iex_ITE:
               return isBogusAtom(e->Iex.ITE.cond)
                      || isBogusAtom(e->Iex.ITE.iftrue)
                      || isBogusAtom(e->Iex.ITE.iffalse);
            case Iex_Load:
               return isBogusAtom(e->Iex.Load.addr);
            case Iex_CCall:
               for (i = 0; e->Iex.CCall.args[i]; i++)
                  if (isBogusAtom(e->Iex.CCall.args[i]))
                     return True;
               return False;
            default:
               goto unhandled;
         }
      case Ist_Dirty:
         d = st->Ist.Dirty.details;
         for (i = 0; d->args[i]; i++) {
            IRAtom* atom = d->args[i];
            if (LIKELY(!is_IRExpr_VECRET_or_BBPTR(atom))) {
               if (isBogusAtom(atom))
                  return True;
            }

         }
         if (d->guard && isBogusAtom(d->guard))
            return True;
         if (d->mAddr && isBogusAtom(d->mAddr))
            return True;
         return False;
      case Ist_Put:
         return isBogusAtom(st->Ist.Put.data);
      case Ist_PutI:
         return isBogusAtom(st->Ist.PutI.details->ix)
                || isBogusAtom(st->Ist.PutI.details->data);
      case Ist_Store:
         return isBogusAtom(st->Ist.Store.addr)
                || isBogusAtom(st->Ist.Store.data);
      case Ist_StoreG: {
         IRStoreG* sg = st->Ist.StoreG.details;
         return isBogusAtom(sg->addr) || isBogusAtom(sg->data)
                || isBogusAtom(sg->guard);
      }
      case Ist_LoadG: {
         IRLoadG* lg = st->Ist.LoadG.details;
         return isBogusAtom(lg->addr) || isBogusAtom(lg->alt)
                || isBogusAtom(lg->guard);
      }
      case Ist_Exit:
         return isBogusAtom(st->Ist.Exit.guard);
      case Ist_AbiHint:
         return isBogusAtom(st->Ist.AbiHint.base)
                || isBogusAtom(st->Ist.AbiHint.nia);
      case Ist_NoOp:
      case Ist_IMark:
      case Ist_MBE:
         return False;
      case Ist_CAS:
         cas = st->Ist.CAS.details;
         return isBogusAtom(cas->addr)
                || (cas->expdHi ? isBogusAtom(cas->expdHi) : False)
                || isBogusAtom(cas->expdLo)
                || (cas->dataHi ? isBogusAtom(cas->dataHi) : False)
                || isBogusAtom(cas->dataLo);
      case Ist_LLSC:
         return isBogusAtom(st->Ist.LLSC.addr)
                || (st->Ist.LLSC.storedata
                       ? isBogusAtom(st->Ist.LLSC.storedata)
                       : False);
      default:
      unhandled:
         ppIRStmt(st);
         VG_(tool_panic)("tnt_translate.c: checkForBogusLiterals");
   }
}

/*-----------------------------------------------------------
  Taintgrind: Routines to create the IRDirty helpers that are 
  used during complainIfTainted. The IRDirty structure is 
  passed from TNT_(instrument) to its subroutines to 
  complainIfTainted as an extra argument.
-----------------------------------------------------------*/
Int extract_IRAtom( IRAtom* atom ){
//   tl_assert(isIRAtom(atom));

   if(atom->tag == Iex_RdTmp)
      return atom->Iex.RdTmp.tmp;
   else if(atom->tag == Iex_Const)
      return extract_IRConst( atom->Iex.Const.con );
   else
      // Taintgrind: Shouldn't reach here
      tl_assert(0);
}

Int extract_IRConst( IRConst* con ){
   switch(con->tag){
      case Ico_U1:
         return con->Ico.U1;
      case Ico_U8:
         return con->Ico.U8;
      case Ico_U16:
         return con->Ico.U16;
      case Ico_U32:
         return con->Ico.U32;
      case Ico_U64: // Taintgrind: Re-cast it and hope for the best
         return con->Ico.U64;
      case Ico_F64:
         return con->Ico.F64;
      case Ico_F64i:
         return con->Ico.F64i;
      case Ico_V128:
         return con->Ico.V128;
      default:
         ppIRConst(con);
         VG_(tool_panic)("tnt_translate.c: convert_IRConst");
   }
}

ULong extract_IRConst64( IRConst* con ){
   switch(con->tag){
      case Ico_U1:
         return con->Ico.U1;
      case Ico_U8:
         return con->Ico.U8;
      case Ico_U16:
         return con->Ico.U16;
      case Ico_U32:
         return con->Ico.U32;
      case Ico_U64:
         return con->Ico.U64;
      case Ico_F64:
         return con->Ico.F64;
      case Ico_F64i:
         return con->Ico.F64i;
      case Ico_V128:
         return con->Ico.V128;
      default:
         ppIRConst(con);
         VG_(tool_panic)("tnt_translate.c: convert_IRConst");
   }
}

static IRExpr* convert_Value( MCEnv* mce, IRAtom* value ){
   IRType ty = typeOfIRExpr(mce->sb->tyenv, value);
   IRType tyH = mce->hWordTy;
//   IRExpr* e;

   if(tyH == Ity_I32){
      switch( ty ){
      case Ity_I1:
         return assignNew( 'C', mce, tyH, unop(Iop_1Uto32, value) );
      case Ity_I8:
         return assignNew( 'C', mce, tyH, unop(Iop_8Uto32, value) );
      case Ity_I16:
         return assignNew( 'C', mce, tyH, unop(Iop_16Uto32, value) );
      case Ity_I32:
         return value;
      case Ity_I64:
         return assignNew( 'C', mce, tyH, unop(Iop_64to32, value) );
      case Ity_F32:
         return assignNew( 'C', mce, tyH, unop(Iop_ReinterpF32asI32, value) );
//         return assignNew( 'C', mce, Ity_I32, unop(Iop_F64toI32,
//                      assignNew( 'C', mce, Ity_I32, unop(Iop_F32toF64, value) ) ) );
      case Ity_F64:
         return assignNew( 'C', mce, tyH, unop(Iop_64to32, 
            assignNew( 'C', mce, Ity_I64, unop(Iop_ReinterpF64asI64, value) ) ) );
//         return assignNew( 'C', mce, Ity_I32, unop(Iop_F64toI32U, value) );
      case Ity_V128:
         return assignNew( 'C', mce, tyH, unop(Iop_V128to32, value) );
      default:
         ppIRType(ty);
         VG_(tool_panic)("tnt_translate.c: convert_Value");
      }
   }else if(tyH == Ity_I64){
      switch( ty ){
      case Ity_I1:
         return assignNew( 'C', mce, tyH, unop(Iop_1Uto64, value) );
      case Ity_I8:
         return assignNew( 'C', mce, tyH, unop(Iop_8Uto64, value) );
      case Ity_I16:
         return assignNew( 'C', mce, tyH, unop(Iop_16Uto64, value) );
      case Ity_I32:
         return assignNew( 'C', mce, tyH, unop(Iop_32Uto64, value) );
      case Ity_I64:
         return value;
      case Ity_I128:
         return assignNew( 'C', mce, tyH, unop(Iop_128to64, value) );
      case Ity_F32:
         return assignNew( 'C', mce, tyH, unop(Iop_ReinterpF64asI64, 
              assignNew( 'C', mce, Ity_F64, unop(Iop_F32toF64, value) ) ) );
      case Ity_F64:
         return assignNew( 'C', mce, tyH, unop(Iop_ReinterpF64asI64, value) );
      case Ity_V128:
         return assignNew( 'C', mce, tyH, unop(Iop_V128to64, value) );
      default:
         ppIRType(ty);
         VG_(tool_panic)("tnt_translate.c: convert_Value");
      }
   }else{
         ppIRType(tyH);
         VG_(tool_panic)("tnt_translate.c: convert_Value");
   }
}

IRDirty* create_dirty_PUT( MCEnv* mce, IRStmt *clone, Int offset, IRExpr* data ){
//         ppIRExpr output: PUT(<offset>) = data
   Int          nargs = 3;
   const HChar* nm;
   void*        fn;
   IRExpr**     args;

   if(data->tag == Iex_Const) return NULL;

   args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
                          convert_Value( mce, data ),
                          convert_Value( mce, atom2vbits( mce, data ) ) );

   if(mce->hWordTy == Ity_I32){
      fn    = &TNT_(h32_put);
      nm    = "TNT_(h32_put)";
   }else if(mce->hWordTy == Ity_I64){
      fn    = &TNT_(h64_put);
      nm    = "TNT_(h64_put)";
   }else
      VG_(tool_panic)("tnt_translate.c: create_dirty_PUT: Unknown type");

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_PUTI( MCEnv* mce, IRRegArray* descr, IRExpr* ix, Int bias, IRExpr* data ){
// ppIRExpr output: PUTI(<descr.base:descr.nElems:descr.elemTy>)[ix, bias] = data
   Int          nargs = 3;
   const HChar* nm;
   void*        fn;
   IRExpr**     args;

   if(data->tag == Iex_Const)
      return NULL;

   if(mce->hWordTy == Ity_I32){
      fn    = &TNT_(h32_puti);
      nm    = "TNT_(h32_puti)";

      // There are too many bits to fit into 64 bits
      // We choose: elemTy, ix, bias, data
      UInt tt1 = descr->elemTy << 16;
           tt1 |= extract_IRAtom( ix ) & 0xffff;
      UInt tt2 = bias << 16;
           tt2 |= extract_IRAtom( data ) & 0xffff;

      args  = mkIRExprVec_4( mkU32( tt1 ),
                             mkU32( tt2 ),
                             convert_Value( mce, data ),
                             convert_Value( mce, atom2vbits( mce, data ) ) );
   }else if(mce->hWordTy == Ity_I64){
      fn    = &TNT_(h64_puti);
      nm    = "TNT_(h64_puti)";

      ULong tt1 = (ULong)descr->base << 32;
            tt1 |= (ULong)descr->elemTy << 16;
            tt1 |= (ULong)descr->nElems & 0xffff;
      ULong tt2 = (ULong)extract_IRAtom( ix ) << 32;
            tt2 |= bias << 16;
            tt2 |= extract_IRAtom( data ) & 0xffff;

      args  = mkIRExprVec_4( mkU64( tt1 ),
                             mkU64( tt2 ),
                             convert_Value( mce, data ),
                             convert_Value( mce, atom2vbits( mce, data ) ) );
   }else
      VG_(tool_panic)("tnt_translate.c: create_dirty_PUTI: Unknown type");

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_STORE( MCEnv* mce, IRStmt *clone,
                             IREndness end, IRTemp resSC, 
                             IRExpr* addr, IRExpr* data ){
//         ppIRExpr output: ST<end>(<addr>) = <data>
   Int          nargs = 3;
   const HChar* nm;
   void*        fn;
   IRExpr**     args;

   if ( addr->tag == Iex_Const && data->tag == Iex_Const ) return NULL;

   args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
                          convert_Value( mce, data ),
                          convert_Value( mce, atom2vbits( mce, data ) ) );

   if(mce->hWordTy == Ity_I32){
      if ( addr->tag == Iex_RdTmp && data->tag == Iex_RdTmp ) {
         fn    = &TNT_(h32_store_tt);
         nm    = "TNT_(h32_store_tt)";
      } else if ( addr->tag == Iex_RdTmp && data->tag == Iex_Const ) {
         fn    = &TNT_(h32_store_tc);
         nm    = "TNT_(h32_store_tc)";
      } else if ( addr->tag == Iex_Const && data->tag == Iex_RdTmp ) {
         fn    = &TNT_(h32_store_ct);
         nm    = "TNT_(h32_store_ct)";
      } else {
         VG_(tool_panic)("tnt_translate.c: create_dirty_STORE: unk 32-bit cfg");
      }
   }else if(mce->hWordTy == Ity_I64){
      if ( addr->tag == Iex_RdTmp && data->tag == Iex_RdTmp ) {
         fn    = &TNT_(h64_store_tt);
         nm    = "TNT_(h64_store_tt)";
      } else if ( addr->tag == Iex_RdTmp && data->tag == Iex_Const ) {
         fn    = &TNT_(h64_store_tc);
         nm    = "TNT_(h64_store_tc)";
      } else if ( addr->tag == Iex_Const && data->tag == Iex_RdTmp ) {
         fn    = &TNT_(h64_store_ct);
         nm    = "TNT_(h64_store_ct)";
      } else {
         ppIRExpr(addr);
         ppIRExpr(data);
         VG_(tool_panic)("tnt_translate.c: create_dirty_STORE: unk 64-bit cfg");
      }
   }else
      VG_(tool_panic)("tnt_translate.c: create_dirty_STORE: Unknown platform");

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_CAS( MCEnv* mce, IRCAS* details ){
/* VEX/pub/libvex_ir.h
            ppIRStmt output:
               t<oldHi:oldLo> = CAS<end>(<addr> :: <expdHi:expdLo> -> <dataHi:dataLo>)
            eg
               t1 = CASle(t2 :: t3->Add32(t3,1))
               which denotes a 32-bit atomic increment
               of a value at address t2

typedef
   struct {
      IRTemp    oldHi;   old value of *addr is written here 
      IRTemp    oldLo;
      IREndness end;     endianness of the data in memory 
      IRExpr*   addr;    store address 
      IRExpr*   expdHi;  expected old value at *addr 
      IRExpr*   expdLo;
      IRExpr*   dataHi;  new value for *addr 
      IRExpr*   dataLo;
   }
   IRCAS;
*/
   Int      nargs = 3;
   const HChar*   nm;
   void*    fn;
   IRExpr** args;
   HChar*   aStr;

   tl_assert( details->oldHi == IRTemp_INVALID );
   tl_assert( isIRAtom(details->addr)   );
   tl_assert( isIRAtom(details->expdLo) );
   tl_assert( isIRAtom(details->dataLo) );

   aStr = (HChar*)VG_(malloc)( "create_dirty_CAS", sizeof(HChar)*128 );

   if( details->oldHi == IRTemp_INVALID )
      VG_(sprintf)( aStr, "0x%x 0x%x t%d = CAS 0x%x t%d", 
              Ist_CAS,
              details->oldHi, details->oldLo, details->end,
              extract_IRAtom( details->addr ) );
   else
      VG_(sprintf)( aStr, "0x%x t%d t%d = CAS 0x%x t%d", 
              Ist_CAS,
              details->oldHi, details->oldLo, details->end,
              extract_IRAtom( details->addr ) );

   if( details->expdHi == NULL )
      VG_(sprintf)( aStr, "%s 0x0", aStr );
   else if( details->expdHi->tag == Iex_RdTmp )
      VG_(sprintf)( aStr, "%s t%d", aStr, extract_IRAtom(details->expdHi) );
   else if( details->expdHi->tag == Iex_Const )
      VG_(sprintf)( aStr, "%s 0x%x", aStr, extract_IRAtom(details->expdHi) );

   if( details->expdLo->tag == Iex_RdTmp )
      VG_(sprintf)( aStr, "%s t%d", aStr, extract_IRAtom(details->expdLo) );
   else if( details->expdLo->tag == Iex_Const )
      VG_(sprintf)( aStr, "%s 0x%x", aStr, extract_IRAtom(details->expdLo) );
 
   if( details->dataHi == NULL )
      VG_(sprintf)( aStr, "%s 0x0", aStr );
   else if( details->dataHi->tag == Iex_RdTmp )
      VG_(sprintf)( aStr, "%s t%d", aStr, extract_IRAtom(details->dataHi) );
   else if( details->dataHi->tag == Iex_Const )
      VG_(sprintf)( aStr, "%s 0x%x", aStr, extract_IRAtom(details->dataHi) );

   if( details->dataLo->tag == Iex_RdTmp )
      VG_(sprintf)( aStr, "%s t%d", aStr, extract_IRAtom(details->dataLo) );
   else if( details->dataLo->tag == Iex_Const )
      VG_(sprintf)( aStr, "%s 0x%x", aStr, extract_IRAtom(details->dataLo) );

   if ( mce->hWordTy == Ity_I32 ) {
      fn    = &TNT_(h32_none);
      nm    = "TNT_(h32_none)";
   } else {
      fn    = &TNT_(h64_none);
      nm    = "TNT_(h64_none)";
   }

   args  = mkIRExprVec_3( mkIRExpr_HWord( (HWord)aStr ),
                          convert_Value( mce, IRExpr_RdTmp( details->oldLo ) ),
                          convert_Value( mce, atom2vbits( mce, IRExpr_RdTmp( details->oldLo ))));

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_DIRTY( MCEnv* mce, IRDirty* details ){
/*             ppIRStmt output:
               t<tmp> = DIRTY <guard> <effects>
                  ::: <callee>(<args>)
            eg.
               t1 = DIRTY t27 RdFX-gst(16,4) RdFX-gst(60,4)
                     ::: foo{0x380035f4}(t2)
typedef
   struct {
      // What to call, and details of args/results
      IRCallee* cee;    // where to call
      IRExpr*   guard;  // :: Ity_Bit.  Controls whether call happens
      IRExpr**  args;   // arg list, ends in NULL
      IRTemp    tmp;    // to assign result to, or IRTemp_INVALID if none

      // Mem effects; we allow only one R/W/M region to be stated
      IREffect  mFx;    // indicates memory effects, if any
      IRExpr*   mAddr;  // of access, or NULL if mFx==Ifx_None
      Int       mSize;  // of access, or zero if mFx==Ifx_None

      // Guest state effects; up to N allowed
      Bool needsBBP; // True => also pass guest state ptr to callee
      Int  nFxState; // must be 0 .. VEX_N_FXSTATE
      struct {
         IREffect fx;   // read, write or modify?  Ifx_None is invalid.
         Int      offset;
         Int      size;
      } fxState[VEX_N_FXSTATE];
   }
   IRDirty;
*/
   Int      nargs = 3;
   const HChar*   nm;
   void*    fn;
   IRExpr** args;
   Int      i, num_args = 0;
   HChar*   aStr;

   aStr = (HChar*)VG_(malloc)( "create_dirty_DIRTY", sizeof(HChar)*128 );

   if( details->tmp == IRTemp_INVALID )
      VG_(sprintf)( aStr, "0x%x", Ist_Dirty );
   else
      VG_(sprintf)( aStr, "0x%x t%d =", Ist_Dirty, details->tmp );

   if( details->guard->tag == Iex_RdTmp )
      VG_(sprintf)( aStr, "%s t%d DIRTY %s", aStr,
                    extract_IRAtom( details->guard ),
                    details->cee->name/*, (Int)details->cee->addr*/ );
   else if( details->guard->tag == Iex_Const )
      VG_(sprintf)( aStr, "%s 0x%x DIRTY %s", aStr,
                    extract_IRAtom( details->guard ),
                    details->cee->name/*, (Int)details->cee->addr*/ );

   for( i=0; details->args[i]; i++ ){
      if( details->args[i]->tag == Iex_Const )
         VG_(sprintf)( aStr, "%s 0x%x", aStr, extract_IRAtom( details->args[i] ) );
      else if( details->args[i]->tag == Iex_RdTmp ){
         VG_(sprintf)( aStr, "%s t%d", aStr, extract_IRAtom( details->args[i] ) );
         //arg_index[num_args++] = i;
      }
   }
   tl_assert( num_args <= 4 );

   nargs = 3;
   if ( mce->hWordTy == Ity_I32 ) {
      fn    = &TNT_(h32_none);
      nm    = "TNT_(h32_none)";
   } else {
      fn    = &TNT_(h64_none);
      nm    = "TNT_(h64_none)";
   }

   if( details->tmp == IRTemp_INVALID )
      args  = mkIRExprVec_3( mkIRExpr_HWord( (HWord)aStr ),
                             mkIRExpr_HWord( 0 ),
                             mkIRExpr_HWord( 0 ) );
   else
      args  = mkIRExprVec_3( mkIRExpr_HWord( (HWord)aStr ),
                             convert_Value( mce, IRExpr_RdTmp( details->tmp ) ),
                             convert_Value( mce, atom2vbits( mce, IRExpr_RdTmp( details->tmp))));

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_EXIT( MCEnv* mce, IRStmt *clone, IRExpr* guard, IRJumpKind jk, IRConst* dst ){
// ppIRStmt output:  if(<guard>) goto {<jk>} <dst>
   Int      nargs = 3;
   const HChar*   nm;
   void*    fn;
   IRExpr** args;

   //if(guard->tag == Iex_Const)        return NULL;

   args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
                          convert_Value( mce, guard ),
                          convert_Value( mce, atom2vbits( mce, guard ) ) );

   if(mce->hWordTy == Ity_I32 && guard->tag == Iex_Const){
      fn    = &TNT_(h32_exit_c);
      nm    = "TNT_(h32_exit_c)";
   }else if(mce->hWordTy == Ity_I32 && guard->tag == Iex_RdTmp){
      fn    = &TNT_(h32_exit_t);
      nm    = "TNT_(h32_exit_t)";
   }else if(mce->hWordTy == Ity_I64 && guard->tag == Iex_Const){
      fn    = &TNT_(h64_exit_c);
      nm    = "TNT_(h64_exit_c)";
   }else if(mce->hWordTy == Ity_I64 && guard->tag == Iex_RdTmp){
      fn    = &TNT_(h64_exit_t);
      nm    = "TNT_(h64_exit_t)";
   }else
      VG_(tool_panic)("tnt_translate.c: create_dirty_EXIT: Unknown platform");

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_NEXT( MCEnv* mce, IRExpr* next ){
// ppIRStmt output:  jmp <next>
   Int      nargs = 3;
   const HChar*   nm;
   void*    fn;
   IRExpr** args;

   // We need to track all BBs, for var run-time taint and values
   //if( next->tag == Iex_Const )       return NULL;
   IRExpr *clone = deepMallocIRExpr(next);

   args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
                          convert_Value( mce, next ),
                          convert_Value( mce, atom2vbits( mce, next ) ) );

   if(mce->hWordTy == Ity_I32 && next->tag == Iex_Const){
      fn    = &TNT_(h32_next_c);
      nm    = "TNT_(h32_next_c)";
   }else if(mce->hWordTy == Ity_I32 && next->tag == Iex_RdTmp){
      fn    = &TNT_(h32_next_t);
      nm    = "TNT_(h32_next_t)";
   }else if(mce->hWordTy == Ity_I64 && next->tag == Iex_Const){
      fn    = &TNT_(h64_next_c);
      nm    = "TNT_(h64_next_c)";
   }else if(mce->hWordTy == Ity_I64 && next->tag == Iex_RdTmp){
      fn    = &TNT_(h64_next_t);
      nm    = "TNT_(h64_next_t)";
   }else
      VG_(tool_panic)("tnt_translate.c: create_dirty_NEXT: Unknown platform");

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_WRTMP( MCEnv* mce, IRStmt *clone, IRTemp tmp, IRExpr* e ){
   //Int i;
   //Int num_args=0;

   //if( TNT_(clo_critical_ins_only) &&
   //   e->tag != Iex_Load )
   //   return NULL;

   switch( e->tag ){
      case Iex_Get:
         return create_dirty_GET( mce, clone, tmp, e->Iex.Get.offset, e->Iex.Get.ty );

      case Iex_GetI:
         return create_dirty_GETI( mce, clone, tmp, e->Iex.GetI.descr,
                                             e->Iex.GetI.ix,
                                             e->Iex.GetI.bias );

      case Iex_RdTmp:
         return create_dirty_RDTMP( mce, clone, tmp, e->Iex.RdTmp.tmp );

      case Iex_Qop:
         //if( e->Iex.Qop.details->arg1->tag == Iex_Const &&
         //    e->Iex.Qop.details->arg2->tag == Iex_Const &&
         //    e->Iex.Qop.details->arg3->tag == Iex_Const &&
         //    e->Iex.Qop.details->arg4->tag == Iex_Const &&
         //    TNT_(clo_tainted_ins_only) )
         //   return NULL;
         //else
            return create_dirty_QOP(
                   mce, clone, tmp,
                   e->Iex.Qop.details->op,
                   e->Iex.Qop.details->arg1, e->Iex.Qop.details->arg2,
                   e->Iex.Qop.details->arg3, e->Iex.Qop.details->arg4
                );

     case Iex_Triop:
         //if( e->Iex.Triop.details->arg1->tag == Iex_Const &&
         //    e->Iex.Triop.details->arg2->tag == Iex_Const &&
         //    e->Iex.Triop.details->arg3->tag == Iex_Const &&
         //    TNT_(clo_tainted_ins_only) )
         //   return NULL;
         //else
            return create_dirty_TRIOP(
                   mce, clone, tmp,
                   e->Iex.Triop.details->op,
                   e->Iex.Triop.details->arg1, e->Iex.Triop.details->arg2,
                   e->Iex.Triop.details->arg3
                );

      case Iex_Binop:
         //if( e->Iex.Binop.arg1->tag == Iex_Const &&
         //    e->Iex.Binop.arg2->tag == Iex_Const &&
         //    TNT_(clo_tainted_ins_only) )
         //   return NULL;
         //else
            return create_dirty_BINOP(
                   mce, clone, tmp,
                   e->Iex.Binop.op,
                   e->Iex.Binop.arg1, e->Iex.Binop.arg2
                );

      case Iex_Unop:
         //if( e->Iex.Unop.arg->tag == Iex_Const &&
         //    TNT_(clo_tainted_ins_only) )
         //   return NULL;
         //else
            return create_dirty_UNOP( mce, clone, tmp,
                                      e->Iex.Unop.op, e->Iex.Unop.arg );

      case Iex_Load:
         return create_dirty_LOAD( mce, clone, tmp, False /*isLL*/, e->Iex.Load.end,
                                   e->Iex.Load.ty,
                                   e->Iex.Load.addr );

      case Iex_CCall:
         //for(i=0; e->Iex.CCall.args[i]; i++)
         //   num_args++;

         //for(i=0; e->Iex.CCall.args[i]; i++){
         //   if(e->Iex.CCall.args[i]->tag != Iex_Const)
         //      break;
         //}
         //
         //if( i == num_args &&
         //    TNT_(clo_tainted_ins_only) )
         //   // All args are const
         //   return NULL;
         //else
            return create_dirty_CCALL( mce, clone, tmp, e->Iex.CCall.cee,
                                                 e->Iex.CCall.retty,
                                                 e->Iex.CCall.args );

      case Iex_ITE:
         return create_dirty_ITE( mce, clone, tmp,
               e->Iex.ITE.cond, e->Iex.ITE.iftrue,
                               e->Iex.ITE.iffalse );

      default:
         VG_(printf)("\n");
         ppIRExpr(e);
         VG_(printf)("\n");
         VG_(tool_panic)("tnt_translate.c: create_dirty_WRTMP: Unhandled expression");
   }
}

IRDirty *create_dirty_WRTMP_const( MCEnv *mce, IRStmt *clone, IRTemp tmp )
{
   Int      nargs = 3;
   const HChar*   nm;
   void*    fn;
   IRExpr** args;

   if ( mce->hWordTy == Ity_I32 ) {
      fn    = &TNT_(h32_wrtmp_c);
      nm    = "TNT_(h32_wrtmp_c)";
      args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
                       convert_Value( mce, IRExpr_RdTmp( tmp ) ),
                       mkU32( 0 ) );
   } else if ( mce->hWordTy == Ity_I64 ){
      fn    = &TNT_(h64_wrtmp_c);
      nm    = "TNT_(h64_wrtmp_c)";
      args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
                       convert_Value( mce, IRExpr_RdTmp( tmp ) ),
                       mkU64( 0 ) );
   }else
      VG_(tool_panic)("tnt_translate.c: create_dirty_WRTMP_const: Unknown platform");

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_GET( MCEnv* mce, IRStmt *clone, IRTemp tmp, Int offset, IRType ty ){
// ppIRStmt output: t<tmp> = GET(<offset>:<ty>)
   Int      nargs = 3;
   const HChar*   nm;
   void*    fn;
   IRExpr** args;

   args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
                          convert_Value( mce, IRExpr_RdTmp( tmp ) ),
                          convert_Value( mce, atom2vbits( mce, IRExpr_RdTmp(tmp) ) ) );

   if(mce->hWordTy == Ity_I32){
      fn    = &TNT_(h32_get);
      nm    = "TNT_(h32_get)";
   }else if(mce->hWordTy == Ity_I64){
      fn    = &TNT_(h64_get);
      nm    = "TNT_(h64_get)";
   }else
      VG_(tool_panic)("tnt_translate.c: create_dirty_GET: Unknown platform");

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_GETI( MCEnv* mce, IRStmt *clone, IRTemp tmp, IRRegArray* descr, IRExpr* ix, Int bias ){
// ppIRStmt output:  t<tmp> = GETI(<base>)[<ix>, <bias>]
   Int      nargs = 3;
   const HChar*   nm;
   void*    fn;
   IRExpr** args;

   args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
           convert_Value( mce, IRExpr_RdTmp( tmp ) ),
           convert_Value( mce, atom2vbits( mce, IRExpr_RdTmp( tmp ) ) ) );

   if(mce->hWordTy == Ity_I32){
      fn    = &TNT_(h32_geti);
      nm    = "TNT_(h32_geti)";
   } else {
      fn    = &TNT_(h64_geti);
      nm    = "TNT_(h64_geti)";
   }

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}


IRDirty* create_dirty_RDTMP( MCEnv* mce, IRStmt *clone, IRTemp tmp, IRTemp data ){
// ppIRStmt output:  t<tmp> = t<data>
   Int      nargs = 3;
   const HChar*   nm;
   void*    fn;
   IRExpr** args;

   args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
           convert_Value( mce, IRExpr_RdTmp( tmp ) ),
           convert_Value( mce, atom2vbits( mce, IRExpr_RdTmp( tmp ) ) ) );

   if(mce->hWordTy == Ity_I32){
      fn    = &TNT_(h32_rdtmp);
      nm    = "TNT_(h32_rdtmp)";
   }else if(mce->hWordTy == Ity_I64){
      fn    = &TNT_(h64_rdtmp);
      nm    = "TNT_(h64_rdtmp)";
   }else
      VG_(tool_panic)("tnt_translate.c: create_dirty_RDTMP: Unknown platform");

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_QOP( MCEnv* mce, IRStmt *clone, IRTemp tmp, IROp op,
                           IRExpr* arg1, IRExpr* arg2,
                           IRExpr* arg3, IRExpr* arg4 ){
// ppIRStmt output:  t<tmp> = op( arg1, arg2, arg3, arg4 )
   Int          nargs = 3;
   const HChar* nm;
   void*        fn;
   IRExpr**     args;
   
   args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
           convert_Value( mce, IRExpr_RdTmp( tmp ) ),
           convert_Value( mce, atom2vbits( mce, IRExpr_RdTmp( tmp ) ) ) );

   if ( mce->hWordTy == Ity_I32 ){
      fn       = &TNT_(h32_qop);
      nm       = "TNT_(h32_qop)";
   } else {
      fn       = &TNT_(h64_qop);
      nm       = "TNT_(h64_qop)";
   }

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_TRIOP( MCEnv* mce, IRStmt *clone, IRTemp tmp, IROp op,
                             IRExpr* arg1, IRExpr* arg2,
                             IRExpr* arg3 ){
// ppIRStmt output:  t<tmp> = op( arg1, arg2, arg3 )
   Int          nargs = 3;
   const HChar* nm;
   void*        fn;
   IRExpr**     args;
   
   args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
           convert_Value( mce, IRExpr_RdTmp( tmp ) ),
           convert_Value( mce, atom2vbits( mce, IRExpr_RdTmp( tmp ) ) ) );

   if ( mce->hWordTy == Ity_I32 ){
      fn       = &TNT_(h32_triop);
      nm       = "TNT_(h32_triop)";
   } else {
      fn       = &TNT_(h64_triop);
      nm       = "TNT_(h64_triop)";
   }

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_BINOP( MCEnv* mce, IRStmt *clone,
                             IRTemp tmp, IROp op,
                             IRExpr* arg1, IRExpr* arg2 ){
// ppIRStmt output:  t<tmp> = op( arg1, arg2 )
   Int      nargs = 3;
   const HChar*   nm;
   void*    fn;
   IRExpr** args;

   // Iop_INVALID = 0x1400
   //if ( arg1->tag == Iex_Const && arg2->tag == Iex_Const )  return NULL;
   if ( arg1->tag == Iex_Const && arg2->tag == Iex_Const )
      return create_dirty_WRTMP_const(mce, clone, tmp);
   
   args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
           convert_Value( mce, IRExpr_RdTmp( tmp ) ),
           convert_Value( mce, atom2vbits( mce, IRExpr_RdTmp( tmp ) ) ) );

   if ( mce->hWordTy == Ity_I32 ){
      if ( arg1->tag == Iex_RdTmp && arg2->tag == Iex_Const ) {
         fn       = &TNT_(h32_binop_tc);
         nm       = "TNT_(h32_binop_tc)";
      } else if ( arg1->tag == Iex_Const && arg2->tag == Iex_RdTmp ) {
         fn       = &TNT_(h32_binop_ct);
         nm       = "TNT_(h32_binop_ct)";
      } else {
         fn    = &TNT_(h32_binop_tt);
         nm    = "TNT_(h32_binop_tt)";
      }
   }else if( mce->hWordTy == Ity_I64 ){
      if ( arg1->tag == Iex_RdTmp && arg2->tag == Iex_Const ) {
         fn       = &TNT_(h64_binop_tc);
         nm       = "TNT_(h64_binop_tc)";
      } else if ( arg1->tag == Iex_Const && arg2->tag == Iex_RdTmp ) {
         fn       = &TNT_(h64_binop_ct);
         nm       = "TNT_(h64_binop_ct)";
      } else {
         fn    = &TNT_(h64_binop_tt);
         nm    = "TNT_(h64_binop_tt)";
      }
   }else
      VG_(tool_panic)("tnt_translate.c: create_dirty_BINOP: Unknown platform");

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_UNOP( MCEnv* mce, IRStmt *clone, IRTemp tmp, IROp op, IRExpr* arg ){
// ppIRStmt output:  t<tmp> = op( arg )
   Int      nargs = 3;
   const HChar*   nm;
   void*    fn;
   IRExpr** args;

   //if ( arg->tag == Iex_Const )  return NULL;
   if ( arg->tag == Iex_Const )
      return create_dirty_WRTMP_const(mce, clone, tmp);
   
   args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
                 convert_Value( mce, IRExpr_RdTmp( tmp ) ),
                 convert_Value( mce, atom2vbits( mce, IRExpr_RdTmp( tmp ) ) ) );
   if ( mce->hWordTy == Ity_I32 ) {
      fn    = &TNT_(h32_unop);
      nm    = "TNT_(h32_unop)";
   } else if ( mce->hWordTy == Ity_I64 ){
      fn    = &TNT_(h64_unop);
      nm    = "TNT_(h64_unop)";
   }else
      VG_(tool_panic)("tnt_translate.c: create_dirty_UNOP: Unknown platform");

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_LOAD( MCEnv* mce, IRStmt *clone, IRTemp tmp,
                            Bool isLL, IREndness end,
                            IRType ty, IRAtom* addr ){
//         ppIRExpr output: tmp = LD<end>:<ty>(<addr>), eg. t0 = LDle:I32(t1)
   Int      nargs = 3;
   const HChar*   nm;
   void*    fn;
   IRExpr** args;

   args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
           convert_Value( mce, IRExpr_RdTmp( tmp ) ),
           convert_Value( mce, atom2vbits( mce, IRExpr_RdTmp( tmp ) ) ) );

   if(mce->hWordTy == Ity_I32){
      if ( addr->tag == Iex_RdTmp ) {
         fn    = &TNT_(h32_load_t);
         nm    = "TNT_(h32_load_t)";
      } else {
         fn    = &TNT_(h32_load_c);
         nm    = "TNT_(h32_load_c)";
      }
   }else if(mce->hWordTy == Ity_I64){
      if ( addr->tag == Iex_RdTmp ) {
         fn    = &TNT_(h64_load_t);
         nm    = "TNT_(h64_load_t)";
      } else {
         fn    = &TNT_(h64_load_c);
         nm    = "TNT_(h64_load_c)";
      }
   }else
      VG_(tool_panic)("tnt_translate.c: create_dirty_LOAD: Unknown platform");

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_CCALL( MCEnv* mce, IRStmt *clone, IRTemp tmp,
                        IRCallee* cee, IRType retty, IRExpr** args ){
// ppIRStmt output: t<tmp> = CCALL <callee>:<retty>(<args>)
   Int          nargs = 3;
   const HChar* nm = "";
   void*        fn = (void *)0;
   IRExpr**     di_args;

   di_args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
              convert_Value( mce, IRExpr_RdTmp( tmp ) ),
              convert_Value( mce, atom2vbits( mce, IRExpr_RdTmp( tmp ) ) ) );

   if ( mce->hWordTy == Ity_I32 ) {
      fn    = &TNT_(h32_ccall);
      nm    = "TNT_(h32_ccall)";
   } else {
      fn    = &TNT_(h64_ccall);
      nm    = "TNT_(h64_ccall)";
   }

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), di_args );
}

IRDirty* create_dirty_ITE( MCEnv* mce, IRStmt *clone, IRTemp tmp,
                           IRExpr* cond, IRExpr* iftrue, IRExpr* iffalse ){
// ppIRStmt output: t<tmp> = ITE <cond> (<iftrue>, <iffalse>)
   Int      nargs = 3;
   const HChar*   nm;
   void*    fn;
   IRExpr** args;

   tl_assert( cond->tag != Iex_Const );

   args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
           convert_Value( mce, IRExpr_RdTmp( tmp ) ),
           convert_Value( mce, atom2vbits( mce, IRExpr_RdTmp( tmp ) ) ) );

   if(mce->hWordTy == Ity_I32){
      if ( iftrue->tag == Iex_RdTmp && iffalse->tag == Iex_Const ) {
         fn    = &TNT_(h32_ite_tc);
         nm    = "TNT_(h32_ite_tc)";
      } else if ( iftrue->tag == Iex_Const && iffalse->tag == Iex_RdTmp ) {
         fn    = &TNT_(h32_ite_ct);
         nm    = "TNT_(h32_ite_ct)";
      } else if ( iftrue->tag == Iex_RdTmp && iffalse->tag == Iex_RdTmp ) {
         fn    = &TNT_(h32_ite_tt);
         nm    = "TNT_(h32_ite_tt)";
      } else if ( iftrue->tag == Iex_Const && iffalse->tag == Iex_Const ) {
         fn    = &TNT_(h32_ite_cc);
         nm    = "TNT_(h32_ite_cc)";
      } else
         VG_(tool_panic)("tnt_translate.c: create_dirty_ITE: Unknown 32-bit mode");
   }else if(mce->hWordTy == Ity_I64){
      if ( iftrue->tag == Iex_RdTmp && iffalse->tag == Iex_Const ) {
         fn    = &TNT_(h64_ite_tc);
         nm    = "TNT_(h64_ite_tc)";
      } else if ( iftrue->tag == Iex_Const && iffalse->tag == Iex_RdTmp ) {
         fn    = &TNT_(h64_ite_ct);
         nm    = "TNT_(h64_ite_ct)";
      } else if ( iftrue->tag == Iex_RdTmp && iffalse->tag == Iex_RdTmp ) {
         fn    = &TNT_(h64_ite_tt);
         nm    = "TNT_(h64_ite_tt)";
      } else if ( iftrue->tag == Iex_Const && iffalse->tag == Iex_Const ) {
         fn    = &TNT_(h64_ite_cc);
         nm    = "TNT_(h64_ite_cc)";
      } else
         VG_(tool_panic)("tnt_translate.c: create_dirty_ITE: Unknown 64-bit mode");
   }else
      VG_(tool_panic)("tnt_translate.c: create_dirty_ITE: Unknown platform");

   return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_from_dirty( IRDirty* di_old ){
   Int      nargs = 0;
   Int      regparms = 0;
   const HChar*   nm;
   void*    fn;
   IRExpr** di_args;
   Int      i;

   for( i=0; di_old->args[i]; i++ )
      nargs++;

   regparms = nargs;
   if( regparms > 3 ) regparms = 3;

   switch( nargs ){
      case 0:
         di_args = mkIRExprVec_0();
         break;
      case 1:
         di_args = mkIRExprVec_1( di_old->args[0] );
         break;
      case 2:
         di_args = mkIRExprVec_2( di_old->args[0],
                                  di_old->args[1] );
         break;
      case 3:
         di_args = mkIRExprVec_3( di_old->args[0],
                                  di_old->args[1],
                                  di_old->args[2] );
         break;
      case 4:
         di_args = mkIRExprVec_4( di_old->args[0],
                                  di_old->args[1],
                                  di_old->args[2],
                                  di_old->args[3] );
         break;
      case 5:
         di_args = mkIRExprVec_5( di_old->args[0],
                                  di_old->args[1],
                                  di_old->args[2],
                                  di_old->args[3],
                                  di_old->args[4] );
         break;
      case 6:
         di_args = mkIRExprVec_6( di_old->args[0],
                                  di_old->args[1],
                                  di_old->args[2],
                                  di_old->args[3],
                                  di_old->args[4],
                                  di_old->args[5] );
         break;
      case 7:
         di_args = mkIRExprVec_7( di_old->args[0],
                                  di_old->args[1],
                                  di_old->args[2],
                                  di_old->args[3],
                                  di_old->args[4],
                                  di_old->args[5],
                                  di_old->args[6] );
         break;
      default:
         tl_assert(0);
   }

   fn    = di_old->cee->addr;
   nm    = di_old->cee->name;

   return unsafeIRDirty_0_N ( regparms, nm, VG_(fnptr_to_fnentry)( fn ), di_args );
}


IRSB* TNT_(instrument)( VgCallbackClosure* closure,
                        IRSB* sb_in,
                        VexGuestLayout* layout, 
                        VexGuestExtents* vge,
                        VexArchInfo* archinfo_host,
                        IRType gWordTy, IRType hWordTy )
{
   Bool    verboze = 0||False;
//   Bool    verboze = True;
   Bool    bogus;
   Int     i, j, first_stmt;
   IRStmt* st;
   MCEnv   mce;
   IRSB*   sb_out;

   // For get_ThreadState
//   ThreadId tid = closure->tid;
//   ThreadState *ts;

   // For get_StackTrace
#if 0
   Int n_ips;
   Addr ips[1];
#endif
   // For complainIfTainted
   IRDirty* di2;
#if 0
   // Check if instrumentation is turned on
   // i.e. have we read tainted bytes from a file?
   numBBs++;
   if( numBBs % 1000 == 0 ) {
      numBBs = 0;
      numKBBs++;
      //VG_(printf)("kBBs read: %d ", numKBBs);
   }

   if( TNT_(clo_after_kbb) != 0 && numKBBs < TNT_(clo_after_kbb) ){
      //if( numBBs % 1000 == 0 )
      //   VG_(printf)("Off\n");
      return sb_in;
   }
   if( TNT_(clo_before_kbb) != -1 && numKBBs > TNT_(clo_before_kbb) ){
      //if( numBBs % 1000 == 0 )
      //   VG_(printf)("Off\n");
      return sb_in;
   }
   //if( numBBs % 1000 == 0 )
   //   VG_(printf)("On\n");
#endif

   if (gWordTy != hWordTy) {
      /* We don't currently support this case. */
      VG_(tool_panic)("host/guest word size mismatch");
   }

   /* Check we're not completely nuts */
   tl_assert(sizeof(UWord)  == sizeof(void*));
   tl_assert(sizeof(Word)   == sizeof(void*));
   tl_assert(sizeof(Addr)   == sizeof(void*));
   tl_assert(sizeof(ULong)  == 8);
   tl_assert(sizeof(Long)   == 8);
   tl_assert(sizeof(Addr64) == 8);
   tl_assert(sizeof(UInt)   == 4);
   tl_assert(sizeof(Int)    == 4);


   // Print Register Contents
   // VEXThreadState struct reproduced from VEX/pub/libvex_guest_x86.h
/*
typedef
   struct {
      UInt  guest_EAX;          0
      UInt  guest_ECX;          4
      UInt  guest_EDX;          8
      UInt  guest_EBX;         12
      UInt  guest_ESP;         16
      UInt  guest_EBP;         20
      UInt  guest_ESI;         24
      UInt  guest_EDI;         28

         4-word thunk used to calculate O S Z A C P flags.
      UInt  guest_CC_OP;       32
      UInt  guest_CC_DEP1;
      UInt  guest_CC_DEP2;
      UInt  guest_CC_NDEP;     44
         The D flag is stored here, encoded as either -1 or +1
      UInt  guest_DFLAG;       48
         Bit 21 (ID) of eflags stored here, as either 0 or 1.
      UInt  guest_IDFLAG;      52
         Bit 18 (AC) of eflags stored here, as either 0 or 1.
      UInt  guest_ACFLAG;      56

         EIP
      UInt  guest_EIP;         60
      ...
   }
   VexGuestX86State;
*/

//   ts =  VG_(get_ThreadState) ( tid );

#if 0
   if(verboze){
      VG_(printf)( "Thread %d Context:\n", tid );
      VG_(printf)( "      0=0x%08x %01x 32=0x%08x %01x\n", ts->arch.vex.guest_EAX, get_vabits2(ts->arch.vex.guest_EAX), ts->arch.vex.guest_CC_OP, get_vabits2(ts->arch.vex.guest_CC_OP) );
      VG_(printf)( "      4=0x%08x %01x 36=0x%08x %01x\n", ts->arch.vex.guest_ECX, get_vabits2(ts->arch.vex.guest_ECX), ts->arch.vex.guest_CC_DEP1, get_vabits2(ts->arch.vex.guest_CC_DEP1) );
      VG_(printf)( "      8=0x%08x %01x 40=0x%08x %01x\n", ts->arch.vex.guest_EDX, get_vabits2(ts->arch.vex.guest_EDX), ts->arch.vex.guest_CC_DEP2, get_vabits2(ts->arch.vex.guest_CC_DEP2) );
      VG_(printf)( "     12=0x%08x %01x 44=0x%08x %01x\n", ts->arch.vex.guest_EBX, get_vabits2(ts->arch.vex.guest_EBX), ts->arch.vex.guest_CC_NDEP, get_vabits2(ts->arch.vex.guest_CC_NDEP) );
      VG_(printf)( "     16=0x%08x %01x 48=0x%08x %01x\n", ts->arch.vex.guest_ESP, get_vabits2(ts->arch.vex.guest_ESP), ts->arch.vex.guest_DFLAG, get_vabits2(ts->arch.vex.guest_DFLAG) );
      VG_(printf)( "     20=0x%08x %01x 52=0x%08x %01x\n", ts->arch.vex.guest_EBP, get_vabits2(ts->arch.vex.guest_EBP), ts->arch.vex.guest_IDFLAG, get_vabits2(ts->arch.vex.guest_IDFLAG) );
      VG_(printf)( "     24=0x%08x %01x 56=0x%08x %01x\n", ts->arch.vex.guest_ESI, get_vabits2(ts->arch.vex.guest_ESI), ts->arch.vex.guest_ACFLAG, get_vabits2(ts->arch.vex.guest_ACFLAG) );
      VG_(printf)( "     28=0x%08x %01x 60=0x%08x %01x\n", ts->arch.vex.guest_EDI, get_vabits2(ts->arch.vex.guest_EDI), ts->arch.vex.guest_EIP, get_vabits2(ts->arch.vex.guest_EIP) );
   }

   // Print Stack Trace
   if(0){
      n_ips = VG_(get_StackTrace)( tid, ips, 1,
                                   NULL/*array to dump SP values in*/,
                                   NULL/*array to dump FP values in*/,
                                   0/*first_ip_delta*/ );
      VG_(printf)( "     EIP=0x%08x\n", (Int)ips[0] );
   }
#endif
   /* Set up SB */
   sb_out = deepCopyIRSBExceptStmts(sb_in);

   /* Set up the running environment.  Both .sb and .tmpMap are
      modified as we go along.  Note that tmps are added to both
      .sb->tyenv and .tmpMap together, so the valid index-set for
      those two arrays should always be identical. */
   VG_(memset)(&mce, 0, sizeof(mce));
   mce.sb             = sb_out;
   mce.trace          = verboze;
   mce.layout         = layout;
   mce.hWordTy        = hWordTy;
   mce.bogusLiterals  = False;

   /* Do expensive interpretation for Iop_Add32 and Iop_Add64 on
      Darwin.  10.7 is mostly built with LLVM, which uses these for
      bitfield inserts, and we get a lot of false errors if the cheap
      interpretation is used, alas.  Could solve this much better if
      we knew which of such adds came from x86/amd64 LEA instructions,
      since these are the only ones really needing the expensive
      interpretation, but that would require some way to tag them in
      the _toIR.c front ends, which is a lot of faffing around.  So
      for now just use the slow and blunt-instrument solution. */
   mce.useLLVMworkarounds = False;
#  if defined(VGO_darwin)
   mce.useLLVMworkarounds = True;
#  endif

   mce.tmpMap = VG_(newXA)( VG_(malloc), "mc.TNT_(instrument).1", VG_(free),
                            sizeof(TempMapEnt));

   for (i = 0; i < sb_in->tyenv->types_used; i++) {
      TempMapEnt ent;
      ent.kind    = Orig;
      ent.shadowV = IRTemp_INVALID;
//      ent.shadowB = IRTemp_INVALID;
      VG_(addToXA)( mce.tmpMap, &ent );
   }
   tl_assert( VG_(sizeXA)( mce.tmpMap ) == sb_in->tyenv->types_used );

   /* Make a preliminary inspection of the statements, to see if there
      are any dodgy-looking literals.  If there are, we generate
      extra-detailed (hence extra-expensive) instrumentation in
      places.  Scan the whole bb even if dodgyness is found earlier,
      so that the flatness assertion is applied to all stmts. */

   bogus = False;

   for (i = 0; i < sb_in->stmts_used; i++) {

      st = sb_in->stmts[i];

//      if (verboze) {
//         VG_(printf)("\n");
//         ppIRStmt(st);
//         VG_(printf)("\n");
//      }

      tl_assert(st);
      tl_assert(isFlatIRStmt(st));

      if (!bogus) {
         bogus = checkForBogusLiterals(st);
         if (0 && bogus) {
            VG_(printf)("bogus: ");
            ppIRStmt(st);
            VG_(printf)("\n");
         }
      }
   }

   mce.bogusLiterals = bogus;

   /* Copy verbatim any IR preamble preceding the first IMark */

   tl_assert(mce.sb == sb_out);
   tl_assert(mce.sb != sb_in);

   i = 0;
   while (i < sb_in->stmts_used && sb_in->stmts[i]->tag != Ist_IMark) {
      st = sb_in->stmts[i];

      tl_assert(st);
      tl_assert(isFlatIRStmt(st));

      stmt( 'C', &mce, sb_in->stmts[i] );

      if(0){
         ppIRStmt(st);
         VG_(printf)("\n");
      }

      i++;
   }

   /* Nasty problem.  IR optimisation of the pre-instrumented IR may
      cause the IR following the preamble to contain references to IR
      temporaries defined in the preamble.  Because the preamble isn't
      instrumented, these temporaries don't have any shadows.
      Nevertheless uses of them following the preamble will cause
      memcheck to generate references to their shadows.  End effect is
      to cause IR sanity check failures, due to references to
      non-existent shadows.  This is only evident for the complex
      preambles used for function wrapping on TOC-afflicted platforms
      (ppc64-linux).

      The following loop therefore scans the preamble looking for
      assignments to temporaries.  For each one found it creates an
      assignment to the corresponding (V) shadow temp, marking it as
      'defined'.  This is the same resulting IR as if the main
      instrumentation loop before had been applied to the statement
      'tmp = CONSTANT'.

      Similarly, if origin tracking is enabled, we must generate an
      assignment for the corresponding origin (B) shadow, claiming
      no-origin, as appropriate for a defined value.
   */
   for (j = 0; j < i; j++) {
      if (sb_in->stmts[j]->tag == Ist_WrTmp) {
         /* findShadowTmpV checks its arg is an original tmp;
            no need to assert that here. */
         IRTemp tmp_o = sb_in->stmts[j]->Ist.WrTmp.tmp;
         IRTemp tmp_v = findShadowTmpV(&mce, tmp_o);
         IRType ty_v  = typeOfIRTemp(sb_out->tyenv, tmp_v);
         assign( 'V', &mce, tmp_v, definedOfType( ty_v ) );
         //if (MC_(clo_mc_level) == 3) {
         //   IRTemp tmp_b = findShadowTmpB(&mce, tmp_o);
         //   tl_assert(typeOfIRTemp(sb_out->tyenv, tmp_b) == Ity_I32);
         //   assign( 'B', &mce, tmp_b, mkU32(0)/* UNKNOWN ORIGIN */);
         //}
         if (0) {
            VG_(printf)("create shadow tmp(s) for preamble tmp [%d] ty ", j);
            ppIRType( ty_v );
            VG_(printf)("\n");
         }
      }
   }

   /* Iterate over the remaining stmts to generate instrumentation. */

   tl_assert(sb_in->stmts_used > 0);
   tl_assert(i >= 0);
   tl_assert(i < sb_in->stmts_used);
   tl_assert(sb_in->stmts[i]->tag == Ist_IMark);

   if(0){
      VG_(printf)("tyenv: ");
      ppIRTypeEnv(mce.sb->tyenv);
      VG_(printf)("\n");
   }

   for (/*use existing i*/; i < sb_in->stmts_used; i++) {
      st = sb_in->stmts[i];
      first_stmt = sb_out->stmts_used;

      if (verboze) {
         VG_(printf)("\n");
         ppIRStmt(st);
         VG_(printf)("\n");
      }

      /* Emulate shadow operations for each stmt ... */
      // Taintgrind: clone the IRStmt. Defined in copy.c
      IRStmt *clone = deepMallocIRStmt(st);

      switch (st->tag) {

         case Ist_WrTmp:  // all the assign tmp stmts, e.g. t1 = GET:I32(0)
            do_shadow_WRTMP( &mce,
                             clone,
                             st->Ist.WrTmp.tmp,
                             st->Ist.WrTmp.data );
//            assign( 'V', &mce, findShadowTmpV(&mce, st->Ist.WrTmp.tmp),
//                               expr2vbits( &mce, st->Ist.WrTmp.data) );
            break;

         case Ist_Put:
            do_shadow_PUT( &mce,
                           clone,
                           st->Ist.Put.offset,
                           st->Ist.Put.data,
                           NULL /* shadow atom */, NULL /* guard */ );
            break;

         case Ist_PutI:
              do_shadow_PUTI( &mce, st->Ist.PutI.details);
            break;

         case Ist_Store:
            do_shadow_Store( &mce, clone,
                                   st->Ist.Store.end,
                                   st->Ist.Store.addr, 0/* addr bias */,
                                   st->Ist.Store.data,
                                   NULL /* shadow data */,
                                   NULL/*guard*/ );
            break;

         case Ist_StoreG:
            do_shadow_StoreG( &mce, st->Ist.StoreG.details );
            break;

         case Ist_LoadG:
            do_shadow_LoadG( &mce, st->Ist.LoadG.details );
            break;

         case Ist_Exit: // Conditional jumps, if(t<guard>) goto {Boring} <addr>:I32
            di2 = create_dirty_EXIT( &mce, clone, st->Ist.Exit.guard, 
                                     st->Ist.Exit.jk, st->Ist.Exit.dst );
            complainIfTainted( &mce, st->Ist.Exit.guard, di2 );
            break;

         case Ist_IMark:
            break;

         case Ist_NoOp:
         case Ist_MBE:
            break;

         case Ist_Dirty:
            do_shadow_Dirty( &mce, st->Ist.Dirty.details );
            break;

         // Taintgrind: Needed for x64
         case Ist_AbiHint:
            // Do nothing
//            do_AbiHint( &mce, st->Ist.AbiHint.base,
//                              st->Ist.AbiHint.len,
//                              st->Ist.AbiHint.nia );
            break;

         case Ist_CAS:
            do_shadow_CAS( &mce, st->Ist.CAS.details );
            /* Note, do_shadow_CAS copies the CAS itself to the output
               block, because it needs to add instrumentation both
               before and after it.  Hence skip the copy below.  Also
               skip the origin-tracking stuff (call to schemeS) above,
               since that's all tangled up with it too; do_shadow_CAS
               does it all. */
            break;

         case Ist_LLSC:
            do_shadow_LLSC( &mce,
                            st->Ist.LLSC.end,
                            st->Ist.LLSC.result,
                            st->Ist.LLSC.addr,
                            st->Ist.LLSC.storedata );
            break;

         default:
            VG_(printf)("\n");
            ppIRStmt(st);
            VG_(printf)("\n");
            VG_(tool_panic)("tnt_translate.c: TNT_(instrument): unhandled IRStmt");

      } /* switch (st->tag) */

      /* ... and finally copy the stmt itself to the output.  Except,
         skip the copy of IRCASs; see comments on case Ist_CAS
         above. */
      /* Taintgrind: Similarly, we execute the WrTmp's and Dirty's first,
                 so that we can print out the resulting values post-execution */
      if (st->tag != Ist_CAS &&
          st->tag != Ist_WrTmp &&
          st->tag != Ist_Dirty )
         stmt('C', &mce, st);
   }
   /* Now we need to complain if the jump target is undefined. */
   first_stmt = sb_out->stmts_used;

   if (verboze) {
      VG_(printf)("sb_in->next = ");
      ppIRExpr(sb_in->next);
      VG_(printf)("\n\n");
   }

   di2 = create_dirty_NEXT( &mce, sb_in->next );
   if ( di2 ) complainIfTainted( &mce, sb_in->next, di2 );

   if (0 && verboze) {
      for (j = first_stmt; j < sb_out->stmts_used; j++) {
         VG_(printf)("   ");
         ppIRStmt(sb_out->stmts[j]);
         VG_(printf)("\n");
      }
      VG_(printf)("\n");
   }

   /* If this fails, there's been some serious snafu with tmp management,
      that should be investigated. */
   tl_assert( VG_(sizeXA)( mce.tmpMap ) == mce.sb->tyenv->types_used );
   VG_(deleteXA)( mce.tmpMap );

   tl_assert(mce.sb == sb_out);
   return sb_out;
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
