#include "pub_tool_basics.h"
#include "pub_tool_hashtable.h"   // For tnt_include.h, VgHashtable
#include "pub_tool_libcassert.h"  // tl_assert
#include "pub_tool_libcbase.h"    // VG_strcpy
#include "pub_tool_libcprint.h"   // VG_(printf)
#include "pub_tool_machine.h"     // IRStmt
#include "pub_tool_tooliface.h"   // VG_(CallbackClosure)

#include "tnt_include.h"

//char *TNT_(smt2_concat)( char *buf, ULong addr, UInt c );
//void TNT_(smt2_binop_tt_10) ( IRStmt *clone );
//void TNT_(smt2_binop_tt_01) ( IRStmt *clone );
//void TNT_(smt2_binop_tt_11) ( IRStmt *clone );

const Int SMT2_ty[] = {
   0,
   1,
   8,
   16,
   32,
   64,
   128,  /* 128-bit scalar */
   32,   /* IEEE 754 float */
   64,   /* IEEE 754 double */
   32,   /* 32-bit Decimal floating point */
   64,   /* 64-bit Decimal floating point */
   128,  /* 128-bit Decimal floating point */
   128,  /* 128-bit floating point; implementation defined */
   128,  /* 128-bit SIMD */
   256   /* 256-bit SIMD */
};

// Array for tracking tmp variable types
UInt *tt; //[TI_MAX];

void TNT_(smt2_preamble)()
{
    VG_(printf)("(set-logic QF_BV)\n");
}

// Get the concrete value (1 byte) of an address location
#define a2v16(v, c) \
   (UInt)((v >> ((1-(c))*8)) & 0xff)

#define a2t16(t, c) \
   (t >> ((1-(c))*8)) & 0xff

#define a2v32(v, c) \
   (UInt)((v >> ((3-(c))*8)) & 0xff)

#define a2t32(t, c) \
   (t >> ((3-(c))*8)) & 0xff

#define a2v64(v, c) \
   (UInt)((v >> ((7-(c))*8)) & 0xff)

#define a2t64(t, c) \
   (t >> ((7-(c))*8)) & 0xff

static char *tnt_smt2_concat_16( char *buf, ULong addr, UInt c, UInt v, UInt t )
{
   char tmp[1024];

   if ( c == 0 )
   {
      if ( a2t16(t,c) )
         VG_(sprintf)(tmp, "a%llx", addr);
      else
         VG_(sprintf)(tmp, "#x%02x", a2v16(v,c));

      if ( a2t16(t,c+1) )
         VG_(sprintf)(buf, "(concat %s a%llx)", tmp, addr+1);
      else
         VG_(sprintf)(buf, "(concat %s #x%02x)", tmp, a2v16(v,c+1));
      return buf;
   }
   if ( a2t16(t,c+1) )
       VG_(sprintf)(tmp, "(concat a%llx %s)", addr, tnt_smt2_concat_16(buf, addr+1, c-1, v, t) );
   else
       VG_(sprintf)(tmp, "(concat #x%02x %s)", a2v16(v,c+1), tnt_smt2_concat_16(buf, addr+1, c-1, v, t) );
   VG_(strcpy)(buf, tmp);
   return buf;
}

static char *tnt_smt2_concat_32( char *buf, ULong addr, UInt c, UInt v, UInt t )
{
   char tmp[1024];

   if ( c == 0 )
   {
      if ( a2t32(t,c) )
         VG_(sprintf)(tmp, "a%llx", addr);
      else
         VG_(sprintf)(tmp, "#x%02x", a2v32(v,c));

      if ( a2t32(t,c+1) )
         VG_(sprintf)(buf, "(concat %s a%llx)", tmp, addr+1);
      else
         VG_(sprintf)(buf, "(concat %s #x%02x)", tmp, a2v32(v,c+1));
      return buf;
   }
   if ( a2t32(t,c+1) )
       VG_(sprintf)(tmp, "(concat a%llx %s)", addr, tnt_smt2_concat_32(buf, addr+1, c-1, v, t) );
   else
       VG_(sprintf)(tmp, "(concat #x%02x %s)", a2v32(v,c+1), tnt_smt2_concat_32(buf, addr+1, c-1, v, t) );
   VG_(strcpy)(buf, tmp);
   return buf;
}

static char *tnt_smt2_concat_64( char *buf, ULong addr, UInt c, ULong v, ULong t )
{
   char tmp[1024];

   if ( c == 0 )
   {
      if ( a2t64(t,c) )
         VG_(sprintf)(tmp, "a%llx", addr);
      else
         VG_(sprintf)(tmp, "#x%02x", a2v64(v,c));

      if ( a2t64(t,c+1) )
         VG_(sprintf)(buf, "(concat %s a%llx)", tmp, addr+1);
      else
         VG_(sprintf)(buf, "(concat %s #x%02x)", tmp, a2v64(v,c+1));
      return buf;
   }
   if ( a2t64(t,c+1) )
       VG_(sprintf)(tmp, "(concat a%llx %s)", addr, tnt_smt2_concat_64(buf, addr+1, c-1, v, t) );
   else
       VG_(sprintf)(tmp, "(concat #x%02x %s)", a2v64(v,c+1), tnt_smt2_concat_64(buf, addr+1, c-1, v, t) );
   VG_(strcpy)(buf, tmp);
   return buf;
}

static char *tnt_smt2_concat_indexed( char *buf, UInt t, UInt c, UInt max )
{
   char tmp[1024];

   if ( c == 0 )
   {
      VG_(sprintf)(buf, "(concat t%d_%d_%d t%d_%d_%d)", t, _ti(t), max-c, t, _ti(t), max-c+1);
      return buf;
   }
   VG_(sprintf)(tmp, "(concat t%d_%d_%d %s)", t, _ti(t), max-c, tnt_smt2_concat_indexed(buf, t, c-1, max) );
   VG_(strcpy)(buf, tmp);
   return buf;
}

// if tmp GOTO ...
void TNT_(smt2_exit) ( IRStmt *clone )
{
   IRExpr *guard = clone->Ist.Exit.guard;
   UInt gtmp     = guard->Iex.RdTmp.tmp;
   // Save current assertions
   VG_(printf)("(push)\n");
   // Invert branch
   if ( tv[gtmp] ) {
      VG_(printf)("(assert (= t%d_%d #b0))\n", gtmp, _ti(gtmp));
   } else {
      VG_(printf)("(assert (= t%d_%d #b1))\n", gtmp, _ti(gtmp));
   }
   VG_(printf)("(check-sat)\n(get-model)\n");
   // Restore assertions
   VG_(printf)("(pop)\n");
   // Add original branch condition
   if ( tv[gtmp] ) {
      VG_(printf)("(assert (= t%d_%d #b1))\n", gtmp, _ti(gtmp));
   } else {
      VG_(printf)("(assert (= t%d_%d #b0))\n", gtmp, _ti(gtmp));
   }
}


static void tnt_smt2_loadstore_atmp ( UInt atmp, ULong address )
{
   // Save current assertions
   VG_(printf)("(push)\n");
   // Invert branch
   if ( tt[atmp] == 32 )
      VG_(printf)("(assert (not (= t%d_%d #x%08llx)))\n", atmp, _ti(atmp), address);
   else if ( tt[atmp] == 64 )
      VG_(printf)("(assert (not (= t%d_%d #x%016llx)))\n", atmp, _ti(atmp), address);
   else
      tl_assert(0);

   VG_(printf)("(check-sat)\n(get-model)\n");
   // Restore assertions
   VG_(printf)("(pop)\n");
   // Add original branch condition
   if ( tt[atmp] == 32 )
      VG_(printf)("(assert (= t%d_%d #x%08llx))\n", atmp, _ti(atmp), address);
   else if ( tt[atmp] == 64 )
      VG_(printf)("(assert (= t%d_%d #x%016llx))\n", atmp, _ti(atmp), address);
   else
      tl_assert(0);
}


static void tnt_smt2_load_ltmp_32 ( UInt ltmp, UInt ty, ULong address, UInt value, UInt taint )
{
   char buf[1024];

   VG_(printf)("(declare-fun t%d_%d () (_ BitVec %d))\n", ltmp, _ti(ltmp), SMT2_ty[ty]);

   if ( SMT2_ty[ty] == 128 )
   {
      VG_(printf)("(assert (= t%d_%d %s))\n", ltmp, _ti(ltmp), tnt_smt2_concat_32(buf, address, 14, value, taint) );
   } else if ( SMT2_ty[ty] == 64 )
   {
      VG_(printf)("(assert (= t%d_%d %s))\n", ltmp, _ti(ltmp), tnt_smt2_concat_32(buf, address, 6, value, taint) );
   } else if ( SMT2_ty[ty] == 32 )
   {
      VG_(printf)("(assert (= t%d_%d %s))\n", ltmp, _ti(ltmp), tnt_smt2_concat_32(buf, address, 2, value, taint) );
   } else if ( SMT2_ty[ty] == 16 )
   {
      VG_(printf)("(assert (= t%d_%d %s))\n", ltmp, _ti(ltmp), tnt_smt2_concat_16(buf, address, 0, value, taint) );
   } else if ( SMT2_ty[ty] == 8 )
   {
      VG_(printf)("(assert (= t%d_%d a%llx))\n", ltmp, _ti(ltmp), address );
   } else {
      VG_(printf)("smt2_load_t: SMT2_ty[ty] = %d not yet supported\n", SMT2_ty[ty]);
      tl_assert(0);
   }
}


static void tnt_smt2_load_ltmp_64 ( UInt ltmp, UInt ty, ULong address, ULong value, ULong taint )
{
   char buf[1024];

   VG_(printf)("(declare-fun t%d_%d () (_ BitVec %d))\n", ltmp, _ti(ltmp), SMT2_ty[ty]);

   if ( SMT2_ty[ty] == 128 )
   {
      VG_(printf)("(assert (= t%d_%d %s))\n", ltmp, _ti(ltmp), tnt_smt2_concat_64(buf, address, 14, value, taint) );
   } else if ( SMT2_ty[ty] == 64 )
   {
      VG_(printf)("(assert (= t%d_%d %s))\n", ltmp, _ti(ltmp), tnt_smt2_concat_64(buf, address, 6, value, taint) );
   } else if ( SMT2_ty[ty] == 32 )
   {
      VG_(printf)("(assert (= t%d_%d %s))\n", ltmp, _ti(ltmp), tnt_smt2_concat_32(buf, address, 2, value, taint) );
   } else if ( SMT2_ty[ty] == 16 )
   {
      VG_(printf)("(assert (= t%d_%d %s))\n", ltmp, _ti(ltmp), tnt_smt2_concat_16(buf, address, 0, value, taint) );
   } else if ( SMT2_ty[ty] == 8 )
   {
      VG_(printf)("(assert (= t%d_%d a%llx))\n", ltmp, _ti(ltmp), address );
   } else {
      VG_(printf)("smt2_load_t: SMT2_ty[ty] = %d not yet supported\n", SMT2_ty[ty]);
      tl_assert(0);
   }
}


// ltmp = LOAD <ty> const 
void TNT_(smt2_load) ( IRStmt *clone, UWord value, UWord taint )
{

   UInt ltmp     = clone->Ist.WrTmp.tmp;
   UInt ty       = clone->Ist.WrTmp.data->Iex.Load.ty - Ity_INVALID;
   IRExpr* addr  = clone->Ist.WrTmp.data->Iex.Load.addr;
   UWord address;

   if (addr->tag == Iex_RdTmp) {
      UInt atmp     = addr->Iex.RdTmp.tmp;
      address = tv[atmp];

      if ( is_tainted(atmp) )
         tnt_smt2_loadstore_atmp ( atmp, address );
   } else {
      address = extract_IRConst(addr->Iex.Const.con);
   }

   if ( is_tainted(ltmp) ) {
      if (sizeof(UWord) == 4)
         tnt_smt2_load_ltmp_32 ( ltmp, ty, address, value, taint );
      else if (sizeof(UWord) == 8)
         tnt_smt2_load_ltmp_64 ( ltmp, ty, address, value, taint );
   }

   tt[ltmp] = SMT2_ty[ty];
}


static void tnt_smt2_store_dtmp( UInt dtmp, ULong address )
{
   tl_assert( tt[dtmp] );

   int numbytes = tt[dtmp]/8, i;

   for ( i=0; i<numbytes; i++ )
   {
      VG_(printf)("(declare-fun a%llx () (_ BitVec 8))\n", address+i);
      VG_(printf)("(assert (= a%llx ((_ extract %d %d) t%d_%d)))\n", address+i, ((i+1)*8)-1, i*8, dtmp, _ti(dtmp) );
   }
}


// STORE addr = data
void TNT_(smt2_store) ( IRStmt *clone )
{

   IRExpr *addr = clone->Ist.Store.addr;
   IRExpr *data = clone->Ist.Store.data;
   UWord address;

   if (addr->tag == Iex_RdTmp) {
      UInt atmp    = addr->Iex.RdTmp.tmp;
      address = tv[atmp];

      if ( is_tainted(atmp) )
         tnt_smt2_loadstore_atmp ( atmp, address );
   } else {
      address = extract_IRConst(addr->Iex.Const.con);
   }

   if (data->tag == Iex_RdTmp) {
      UInt dtmp    = data->Iex.RdTmp.tmp;

      if ( is_tainted(dtmp) )
         tnt_smt2_store_dtmp ( dtmp, address );
   }
}

#define smt2_sign_extend(a, b) \
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec " #b "))\n", ltmp, _ti(ltmp)); \
         VG_(printf)("(assert (= t%d_%d ((_ sign_extend " #a ") t%d_%d)))\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp) ); \
         tt[ltmp] = b

#define smt2_zero_extend(a, b) \
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec " #b "))\n", ltmp, _ti(ltmp)); \
         VG_(printf)("(assert (= t%d_%d ((_ zero_extend " #a ") t%d_%d)))\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp) ); \
         tt[ltmp] = b

#define smt2_extract(a, b, c) \
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec " #c "))\n", ltmp, _ti(ltmp)); \
         VG_(printf)("(assert (= t%d_%d ((_ extract " #b " " #a ") t%d_%d)))\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp) ); \
         tt[ltmp] = c

#define smt2_unop(a, b) \
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec " #b "))\n", ltmp, _ti(ltmp)); \
         VG_(printf)("(assert (= t%d_%d (" #a " t%d_%d)))\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp) ); \
         tt[ltmp] = b

// PMOVMSKB http://x86.renejeschke.de/html/file_module_x86_id_243.html
#define smt2_getmsbsMxN(ty) \
      { \
         int i; char buf[512]; \
         tl_assert(tt[rtmp] == (ty*8)); \
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec " #ty "))\n", ltmp, _ti(ltmp)); \
         for ( i=0; i<ty; i++ ) { \
            VG_(printf)("(declare-fun t%d_%d_%d () (_ BitVec 1))\n", ltmp, _ti(ltmp), i); \
            VG_(printf)("(assert (= t%d_%d_%d ((_ extract %d %d) t%d_%d) ))\n", ltmp, _ti(ltmp), i, (i+1)*8-1, (i+1)*8-1, rtmp, _ti(rtmp) ); \
         } \
         VG_(printf)("(assert (= t%d_%d %s))\n", ltmp, _ti(ltmp), tnt_smt2_concat_indexed(buf, ltmp, ty-2, ty-2) ); \
         tt[ltmp] = ty; \
      }

// ctz32 https://github.com/agocke/qemu/blob/master/host-utils.h
#define smt2_ctz64(ty) \
      { \
         int mask = 0xFFFFFFFF, shift = 32, i; \
         tl_assert(tt[rtmp] == ty); \
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec " #ty "))\n", ltmp, _ti(ltmp)); \
         /* cnt = 0; */ \
         VG_(printf)("(declare-fun t%d_%d_cnt0 () (_ BitVec " #ty "))\n", ltmp, _ti(ltmp)); \
         VG_(printf)("(assert (= t%d_%d_cnt0 #x%016x))\n", ltmp, _ti(ltmp), 0); \
         VG_(printf)("(declare-fun t%d_%d_sh0 () (_ BitVec " #ty "))\n", rtmp, _ti(rtmp)); \
         VG_(printf)("(assert (= t%d_%d_sh0 t%d_%d))\n", rtmp, _ti(rtmp), rtmp, _ti(rtmp)); \
         for ( i=0; i<6; i++ ) { \
            /* if (!(val & 0xFFFFFFFF)) */ \
            VG_(printf)("(declare-fun t%d_%d_%d () (_ BitVec 1))\n", rtmp, _ti(rtmp), i); \
            VG_(printf)("(assert (= t%d_%d_%d (bvnot (bvand t%d_%d_sh%d #x%016x))))\n", rtmp, _ti(rtmp), i, rtmp, _ti(rtmp), i, mask); \
            /*    cnt += 32; */ \
            VG_(printf)("(declare-fun t%d_%d_cnt%d () (_ BitVec " #ty "))\n", ltmp, _ti(ltmp), i+1); \
            VG_(printf)("(assert (= t%d_%d_cnt%d (bvadd t%d_%d_cnt%d (ite t%d_%d_%d #x%016x #x%016x))))\n", ltmp, _ti(ltmp), i+1, ltmp, _ti(ltmp), i, rtmp, _ti(rtmp), i, shift, 0); \
            /*    val >>= 32; */ \
            VG_(printf)("(declare-fun t%d_%d_sh%d () (_ BitVec " #ty "))\n", rtmp, _ti(rtmp), i+1); \
            VG_(printf)("(assert (= t%d_%d_sh%d (bvshr t%d_%d_sh%d (ite t%d_%d_%d #x%016x #x%016x))))\n", rtmp, _ti(rtmp), i+1, rtmp, _ti(rtmp), i, rtmp, _ti(rtmp), i, shift, 0); \
            shift /= 2; \
            mask >>= shift; \
         } \
         /* if (!(val & 0x1)) */ \
         VG_(printf)("(declare-fun t%d_%d_6 () (_ BitVec 1))\n", rtmp, _ti(rtmp)); \
         VG_(printf)("(assert (= t%d_%d_6 (bvnot (bvand t%d_%d_sh6 #x%016x))))\n", rtmp, _ti(rtmp), rtmp, _ti(rtmp), 0x1); \
         /*    cnt += 1; */ \
         VG_(printf)("(assert (= t%d_%d (bvadd t%d_%d_cnt6 (ite t%d_%d_6 #x%016x #x%016x))))\n", ltmp, _ti(ltmp), ltmp, _ti(ltmp), rtmp, _ti(rtmp), 1, 0); \
         tt[ltmp] = ty; \
      }

// ltmp = <op> rtmp
void TNT_(smt2_unop_t) ( IRStmt *clone )
{

   UInt ltmp   = clone->Ist.WrTmp.tmp;
   UInt op     = clone->Ist.WrTmp.data->Iex.Unop.op;
   IRExpr* arg = clone->Ist.WrTmp.data->Iex.Unop.arg;
   UInt rtmp   = arg->Iex.RdTmp.tmp;

   switch(op) {
      case Iop_1Sto8:     smt2_sign_extend(7, 8);    break;
      case Iop_1Sto16:    smt2_sign_extend(15, 16);  break;
      case Iop_1Sto32:    smt2_sign_extend(31, 32);  break;
      case Iop_1Sto64:    smt2_sign_extend(63, 64);  break;
      case Iop_1Uto8:     smt2_zero_extend(7, 8);    break;
      case Iop_1Uto32:    smt2_zero_extend(31, 32);  break;
      case Iop_1Uto64:    smt2_zero_extend(63, 64);  break;
      case Iop_8Sto16:    smt2_sign_extend(8, 16);   break;
      case Iop_8Sto32:    smt2_sign_extend(24, 32);  break;
      case Iop_8Sto64:    smt2_sign_extend(56, 64);  break;
      case Iop_8Uto16:    smt2_zero_extend(8, 16);   break;
      case Iop_8Uto32:    smt2_zero_extend(24, 32);  break;
      case Iop_8Uto64:    smt2_zero_extend(56, 64);  break;
      case Iop_16to8:     smt2_extract(0, 7, 8);     break;
      case Iop_16HIto8:   smt2_extract(8, 15, 8);    break;
      case Iop_16Sto32:   smt2_sign_extend(16, 32);  break;
      case Iop_16Sto64:   smt2_sign_extend(48, 64);  break;
      case Iop_16Uto32:   smt2_zero_extend(16, 32);  break;
      case Iop_16Uto64:   smt2_zero_extend(48, 64);  break;
      case Iop_32to1:     smt2_extract(0, 0, 1);     break;
      case Iop_32to8:     smt2_extract(0, 7, 8);     break;
      case Iop_32to16:    smt2_extract(0, 15, 16);   break;
      case Iop_32HIto16:  smt2_extract(16, 31, 16);  break;
      case Iop_32Sto64:   smt2_sign_extend(32, 64);  break;
      case Iop_32Uto64:   smt2_zero_extend(32, 64);  break;
      case Iop_64to1:     smt2_extract(0, 0, 1);     break;
      case Iop_64to8:     smt2_extract(0, 7, 8);     break;
      case Iop_64to16:    smt2_extract(0, 15, 16);   break;
      case Iop_64to32:    smt2_extract(0, 31, 32);   break;
      case Iop_64HIto32:  smt2_extract(32, 63, 32);  break;
      case Iop_128to64:   smt2_extract(0, 63, 64);   break;
      case Iop_128HIto64: smt2_extract(64, 127, 64); break;
      case Iop_Ctz64:     smt2_ctz64(64);            break;
      case Iop_GetMSBs8x8:  smt2_getmsbsMxN(8)       break;
      case Iop_GetMSBs8x16: smt2_getmsbsMxN(16)      break;
      case Iop_Not1:      smt2_unop(bvnot, 1);       break;
      case Iop_Not8:      smt2_unop(bvnot, 8);       break;
      case Iop_Not16:     smt2_unop(bvnot, 16);      break;
      case Iop_Not32:     smt2_unop(bvnot, 32);      break;
      case Iop_Not64:     smt2_unop(bvnot, 64);      break;
      default:
         VG_(printf)("smt2_unop_t: ");
         ppIROp(op);
         VG_(printf)(" not yet supported\n");
         tl_assert(0);
   }
}

#define smt2_binop_tc_add(ty, zeros, op) \
         tl_assert(tt[rtmp] == ty); \
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec " #ty "))\n", ltmp, _ti(ltmp)); \
         VG_(printf)("(assert (= t%d_%d (" #op " t%d_%d #x%0" #zeros "llx) ))\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp), c ); \
         tt[ltmp] = ty

#define smt2_binop_tc_cmp(ty, zeros, op) \
         tl_assert(tt[rtmp] == ty); \
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec 1))\n", ltmp, _ti(ltmp)); \
         VG_(printf)("(assert (= t%d_%d (ite (" #op " t%d_%d #x%0" #zeros "llx) #b1 #b0) ))\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp), c ); \
         tt[ltmp] = 1

// PCMPEQB http://x86.renejeschke.de/html/file_module_x86_id_234.html
#define smt2_binop_tc_cmpMxN(m, n, ty, zeros, op) \
      { \
         int i; char buf[512]; \
         tl_assert(tt[rtmp] == ty); \
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec " #ty "))\n", ltmp, _ti(ltmp)); \
         for ( i=0; i<n; i++ ) { \
            VG_(printf)("(declare-fun t%d_%d_%d () (_ BitVec " #m "))\n", ltmp, _ti(ltmp), i); \
            VG_(printf)("(assert (= t%d_%d_%d (ite (" #op " ((_ extract %d %d) t%d_%d) #x%0" #zeros "llx) #xff #x00) ))\n", ltmp, _ti(ltmp), i, (i+1)*m-1, i*m, rtmp, _ti(rtmp), c ); \
         } \
         VG_(printf)("(assert (= t%d_%d %s))\n", ltmp, _ti(ltmp), tnt_smt2_concat_indexed(buf, ltmp, n-2, n-2) ); \
         tt[ltmp] = ty; \
      }

#define smt2_binop_ct_add(ty, zeros, op) \
         tl_assert(tt[rtmp] == ty); \
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec " #ty "))\n", ltmp, _ti(ltmp)); \
         VG_(printf)("(assert (= t%d_%d (" #op " #x%0" #zeros "llx t%d_%d) ))\n", ltmp, _ti(ltmp), c, rtmp, _ti(rtmp) ); \
         tt[ltmp] = ty

#define smt2_binop_ct_cmp(ty, zeros, op) \
         tl_assert(tt[rtmp] == ty); \
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec 1))\n", ltmp, _ti(ltmp)); \
         VG_(printf)("(assert (= t%d_%d (ite (" #op " #x%0" #zeros "llx t%d_%d) #b1 #b0) ))\n", ltmp, _ti(ltmp), c, rtmp, _ti(rtmp) ); \
         tt[ltmp] = 1

static void tnt_smt2_binop_tc_common ( UInt op, UInt ltmp, UInt rtmp, ULong c ) {

   switch(op) {
      case Iop_Add8:     smt2_binop_tc_add( 8,  2, bvadd);  break;
      case Iop_Add16:    smt2_binop_tc_add(16,  4, bvadd);  break;
      case Iop_Add32:    smt2_binop_tc_add(32,  8, bvadd);  break;
      case Iop_Add64:    smt2_binop_tc_add(64, 16, bvadd);  break;
      case Iop_And8:     smt2_binop_tc_add( 8,  2, bvand);  break;
      case Iop_And16:    smt2_binop_tc_add(16,  4, bvand);  break;
      case Iop_And32:    smt2_binop_tc_add(32,  8, bvand);  break;
      case Iop_And64:    smt2_binop_tc_add(64, 16, bvand);  break;
      case Iop_CmpEQ8:   smt2_binop_tc_cmp( 8,  2, =);      break;
      case Iop_CmpEQ8x16:smt2_binop_tc_cmpMxN(8,16,128,2,=) break;
      case Iop_CmpEQ16:  smt2_binop_tc_cmp(16,  4, =);      break;
      case Iop_CmpEQ32:  smt2_binop_tc_cmp(32,  8, =);      break;
      case Iop_CmpEQ64:  smt2_binop_tc_cmp(64, 16, =);      break;
      case Iop_CmpLE32S: smt2_binop_tc_cmp(32,  8, bvsle);  break;
      case Iop_CmpLE64S: smt2_binop_tc_cmp(64, 16, bvsle);  break;
      case Iop_CmpLE32U: smt2_binop_tc_cmp(32,  8, bvule);  break;
      case Iop_CmpLE64U: smt2_binop_tc_cmp(64, 16, bvule);  break;
      case Iop_CmpLT32S: smt2_binop_tc_cmp(32,  8, bvslt);  break;
      case Iop_CmpLT64S: smt2_binop_tc_cmp(64, 16, bvslt);  break;
      case Iop_CmpLT32U: smt2_binop_tc_cmp(32,  8, bvult);  break;
      case Iop_CmpLT64U: smt2_binop_tc_cmp(64, 16, bvult);  break;
      case Iop_Or8:      smt2_binop_tc_add( 8,  2, bvor);   break;
      case Iop_Or16:     smt2_binop_tc_add(16,  4, bvor);   break;
      case Iop_Or32:     smt2_binop_tc_add(32,  8, bvor);   break;
      case Iop_Or64:     smt2_binop_tc_add(64, 16, bvor);   break;
      case Iop_Sar8:     smt2_binop_tc_add( 8,  2, bvashr); break;
      case Iop_Sar16:    smt2_binop_tc_add(16,  4, bvashr); break;
      case Iop_Sar32:    smt2_binop_tc_add(32,  8, bvashr); break;
      case Iop_Sar64:    smt2_binop_tc_add(64, 16, bvashr); break;
      case Iop_Shl8:     smt2_binop_tc_add( 8,  2, bvshl);  break;
      case Iop_Shl16:    smt2_binop_tc_add(16,  4, bvshl);  break;
      case Iop_Shl32:    smt2_binop_tc_add(32,  8, bvshl);  break;
      case Iop_Shl64:    smt2_binop_tc_add(64, 16, bvshl);  break;
      case Iop_Shr8:     smt2_binop_tc_add( 8,  2, bvlshr); break;
      case Iop_Shr16:    smt2_binop_tc_add(16,  4, bvlshr); break;
      case Iop_Shr32:    smt2_binop_tc_add(32,  8, bvlshr); break;
      case Iop_Shr64:    smt2_binop_tc_add(64, 16, bvlshr); break;
      case Iop_Sub8:     smt2_binop_tc_add( 8,  2, bvsub);  break;
      case Iop_Sub16:    smt2_binop_tc_add(16,  4, bvsub);  break;
      case Iop_Sub32:    smt2_binop_tc_add(32,  8, bvsub);  break;
      case Iop_Sub64:    smt2_binop_tc_add(64, 16, bvsub);  break;
      case Iop_Xor8:     smt2_binop_tc_add( 8,  2, bvxor);  break;
      case Iop_Xor16:    smt2_binop_tc_add(16,  4, bvxor);  break;
      case Iop_Xor32:    smt2_binop_tc_add(32,  8, bvxor);  break;
      case Iop_Xor64:    smt2_binop_tc_add(64, 16, bvxor);  break;
      default:
         VG_(printf)("smt2_binop_tc_common: ");
         ppIROp(op);
         VG_(printf)(" not yet supported\n");
         tl_assert(0);
   }
}

static void tnt_smt2_binop_ct_common ( UInt op, UInt ltmp, UInt rtmp, ULong c ) {

   switch(op) {
      case Iop_Add8:     smt2_binop_ct_add( 8, 2, bvadd);  break;
      case Iop_Add16:    smt2_binop_ct_add(16, 4, bvadd);  break;
      case Iop_Add32:    smt2_binop_ct_add(32, 8, bvadd);  break;
      case Iop_Add64:    smt2_binop_ct_add(64,16, bvadd);  break;
      case Iop_And8:     smt2_binop_ct_add( 8, 2, bvand);  break;
      case Iop_And16:    smt2_binop_ct_add(16, 4, bvand);  break;
      case Iop_And32:    smt2_binop_ct_add(32, 8, bvand);  break;
      case Iop_And64:    smt2_binop_ct_add(64,16, bvand);  break;
      case Iop_CmpEQ8:   smt2_binop_ct_cmp(8,  2, =);      break;
      case Iop_CmpEQ16:  smt2_binop_ct_cmp(16, 4, =);      break;
      case Iop_CmpEQ32:  smt2_binop_ct_cmp(32, 8, =);      break;
      case Iop_CmpEQ64:  smt2_binop_ct_cmp(64,16, =);      break;
      case Iop_CmpLE32S: smt2_binop_ct_cmp(32, 8, bvsle);  break;
      case Iop_CmpLE64S: smt2_binop_ct_cmp(64,16, bvsle);  break;
      case Iop_CmpLE32U: smt2_binop_ct_cmp(32, 8, bvule);  break;
      case Iop_CmpLE64U: smt2_binop_ct_cmp(64,16, bvule);  break;
      case Iop_CmpLT32S: smt2_binop_ct_cmp(32, 8, bvslt);  break;
      case Iop_CmpLT64S: smt2_binop_ct_cmp(64,16, bvslt);  break;
      case Iop_CmpLT32U: smt2_binop_ct_cmp(32, 8, bvult);  break;
      case Iop_CmpLT64U: smt2_binop_ct_cmp(64,16, bvult);  break;
      case Iop_Or8:      smt2_binop_ct_add( 8, 2, bvor);   break;
      case Iop_Or16:     smt2_binop_ct_add(16, 4, bvor);   break;
      case Iop_Or32:     smt2_binop_ct_add(32, 8, bvor);   break;
      case Iop_Or64:     smt2_binop_ct_add(64,16, bvor);   break;
      case Iop_Sar8:     smt2_binop_ct_add( 8, 2, bvashr); break;
      case Iop_Sar16:    smt2_binop_ct_add(16, 4, bvashr); break;
      case Iop_Sar32:    smt2_binop_ct_add(32, 8, bvashr); break;
      case Iop_Sar64:    smt2_binop_ct_add(64,16, bvashr); break;
      case Iop_Shl8:     smt2_binop_ct_add( 8, 2, bvshl);  break;
      case Iop_Shl16:    smt2_binop_ct_add(16, 4, bvshl);  break;
      case Iop_Shl32:    smt2_binop_ct_add(32, 8, bvshl);  break;
      case Iop_Shl64:    smt2_binop_ct_add(64,16, bvshl);  break;
      case Iop_Shr8:     smt2_binop_ct_add( 8, 2, bvlshr); break;
      case Iop_Shr16:    smt2_binop_ct_add(16, 4, bvlshr); break;
      case Iop_Shr32:    smt2_binop_ct_add(32, 8, bvlshr); break;
      case Iop_Shr64:    smt2_binop_ct_add(64,16, bvlshr); break;
      case Iop_Sub8:     smt2_binop_ct_add( 8, 2, bvsub);  break;
      case Iop_Sub16:    smt2_binop_ct_add(16, 4, bvsub);  break;
      case Iop_Sub32:    smt2_binop_ct_add(32, 8, bvsub);  break;
      case Iop_Sub64:    smt2_binop_ct_add(64,16, bvsub);  break;
      case Iop_Xor8:     smt2_binop_ct_add( 8, 2, bvxor);  break;
      case Iop_Xor16:    smt2_binop_ct_add(16, 4, bvxor);  break;
      case Iop_Xor32:    smt2_binop_ct_add(32, 8, bvxor);  break;
      case Iop_Xor64:    smt2_binop_ct_add(64,16, bvxor);  break;
      default:
         VG_(printf)("smt2_binop_ct_common: ");
         ppIROp(op);
         VG_(printf)(" not yet supported\n");
         tl_assert(0);
   }
}

// ltmp = <op> rtmp1 c
void TNT_(smt2_binop_tc) ( IRStmt *clone )
{

   UInt ltmp    = clone->Ist.WrTmp.tmp;
   UInt op      = clone->Ist.WrTmp.data->Iex.Binop.op;
   IRExpr* arg1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
   IRExpr* arg2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
   UInt rtmp    = arg1->Iex.RdTmp.tmp;
   ULong c      = extract_IRConst64( arg2->Iex.Const.con );

   tnt_smt2_binop_tc_common ( op, ltmp, rtmp, c );
}


// ltmp = <op> c rtmp2
void TNT_(smt2_binop_ct) ( IRStmt *clone )
{

   UInt ltmp    = clone->Ist.WrTmp.tmp;
   UInt op      = clone->Ist.WrTmp.data->Iex.Binop.op;
   IRExpr* arg1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
   IRExpr* arg2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
   UInt rtmp    = arg2->Iex.RdTmp.tmp;
   ULong c      = extract_IRConst64( arg1->Iex.Const.con );

   tnt_smt2_binop_ct_common ( op, ltmp, rtmp, c );
}


// ltmp = <op> rtmp1 rtmp2, rtmp1 is tainted, similar to binop_tc
static void tnt_smt2_binop_tt_10 ( IRStmt *clone )
{
   UInt ltmp    = clone->Ist.WrTmp.tmp;
   UInt op      = clone->Ist.WrTmp.data->Iex.Binop.op;
   IRExpr* arg1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
   IRExpr* arg2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
   UInt rtmp    = arg1->Iex.RdTmp.tmp;
   UInt rtmp2   = arg2->Iex.RdTmp.tmp;
   ULong c      = tv[rtmp2];

   tnt_smt2_binop_tc_common ( op, ltmp, rtmp, c );
}


// ltmp = <op> rtmp1 rtmp2, rtmp2 is tainted, similar to binop_ct
static void tnt_smt2_binop_tt_01 ( IRStmt *clone )
{
   UInt ltmp    = clone->Ist.WrTmp.tmp;
   UInt op      = clone->Ist.WrTmp.data->Iex.Binop.op;
   IRExpr* arg1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
   IRExpr* arg2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
   UInt rtmp1   = arg1->Iex.RdTmp.tmp;
   UInt rtmp    = arg2->Iex.RdTmp.tmp;
   ULong c      = tv[rtmp1];

   tnt_smt2_binop_ct_common ( op, ltmp, rtmp, c );
}


#define smt2_binop_tt_11_add(a, d) \
         tl_assert(tt[rtmp1] == a); \
         tl_assert(tt[rtmp2] == a); \
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec " #a "))\n", ltmp, _ti(ltmp)); \
         VG_(printf)("(assert (= t%d_%d (" #d " t%d_%d t%d_%d) ))\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1), rtmp2, _ti(rtmp2) ); \
         tt[ltmp] = a

#define smt2_binop_tt_11_cmp(a, d) \
         tl_assert(tt[rtmp1] == a); \
         tl_assert(tt[rtmp2] == a); \
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec 1))\n", ltmp, _ti(ltmp)); \
         VG_(printf)("(assert (= t%d_%d (ite (" #d " t%d_%d t%d_%d) #b1 #b0) ))\n", ltmp, _ti(ltmp), rtmp1, _ti(rtmp1), rtmp2, _ti(rtmp2) ); \
         tt[ltmp] = 1

// ltmp = <op> rtmp1 rtmp2, both tainted
static void tnt_smt2_binop_tt_11 ( IRStmt *clone )
{
   UInt ltmp    = clone->Ist.WrTmp.tmp;
   UInt op      = clone->Ist.WrTmp.data->Iex.Binop.op;
   IRExpr* arg1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
   IRExpr* arg2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
   UInt rtmp1   = arg1->Iex.RdTmp.tmp;
   UInt rtmp2   = arg2->Iex.RdTmp.tmp;

   switch(op) {
      case Iop_Add8:     smt2_binop_tt_11_add( 8, bvadd);  break;
      case Iop_Add16:    smt2_binop_tt_11_add(16, bvadd);  break;
      case Iop_Add32:    smt2_binop_tt_11_add(32, bvadd);  break;
      case Iop_Add64:    smt2_binop_tt_11_add(64, bvadd);  break;
      case Iop_And8:     smt2_binop_tt_11_add( 8, bvand);  break;
      case Iop_And16:    smt2_binop_tt_11_add(16, bvand);  break;
      case Iop_And32:    smt2_binop_tt_11_add(32, bvand);  break;
      case Iop_And64:    smt2_binop_tt_11_add(64, bvand);  break;
      case Iop_CmpEQ8:   smt2_binop_tt_11_cmp( 8, =);      break;
      case Iop_CmpEQ16:  smt2_binop_tt_11_cmp(16, =);      break;
      case Iop_CmpEQ32:  smt2_binop_tt_11_cmp(32, =);      break;
      case Iop_CmpEQ64:  smt2_binop_tt_11_cmp(64, =);      break;
      case Iop_CmpLE32S: smt2_binop_tt_11_cmp(32, bvsle);  break;
      case Iop_CmpLE32U: smt2_binop_tt_11_cmp(32, bvule);  break;
      case Iop_CmpLT32S: smt2_binop_tt_11_cmp(32, bvslt);  break;
      case Iop_CmpLT32U: smt2_binop_tt_11_cmp(32, bvult);  break;
      case Iop_Or8:      smt2_binop_tt_11_add( 8, bvor);   break;
      case Iop_Or16:     smt2_binop_tt_11_add(16, bvor);   break;
      case Iop_Or32:     smt2_binop_tt_11_add(32, bvor);   break;
      case Iop_Or64:     smt2_binop_tt_11_add(64, bvor);   break;
      case Iop_Sar8:     smt2_binop_tt_11_add( 8, bvashr); break;
      case Iop_Sar16:    smt2_binop_tt_11_add(16, bvashr); break;
      case Iop_Sar32:    smt2_binop_tt_11_add(32, bvashr); break;
      case Iop_Sar64:    smt2_binop_tt_11_add(64, bvashr); break;
      case Iop_Shl8:     smt2_binop_tt_11_add( 8, bvshl);  break;
      case Iop_Shl16:    smt2_binop_tt_11_add(16, bvshl);  break;
      case Iop_Shl32:    smt2_binop_tt_11_add(32, bvshl);  break;
      case Iop_Shl64:    smt2_binop_tt_11_add(64, bvshl);  break;
      case Iop_Shr8:     smt2_binop_tt_11_add( 8, bvlshr); break;
      case Iop_Shr16:    smt2_binop_tt_11_add(16, bvlshr); break;
      case Iop_Shr32:    smt2_binop_tt_11_add(32, bvlshr); break;
      case Iop_Shr64:    smt2_binop_tt_11_add(64, bvlshr); break;
      case Iop_Sub8:     smt2_binop_tt_11_add( 8, bvsub);  break;
      case Iop_Sub16:    smt2_binop_tt_11_add(16, bvsub);  break;
      case Iop_Sub32:    smt2_binop_tt_11_add(32, bvsub);  break;
      case Iop_Sub64:    smt2_binop_tt_11_add(64, bvsub);  break;
      case Iop_Xor8:     smt2_binop_tt_11_add( 8, bvxor);  break;
      case Iop_Xor16:    smt2_binop_tt_11_add(16, bvxor);  break;
      case Iop_Xor32:    smt2_binop_tt_11_add(32, bvxor);  break;
      case Iop_Xor64:    smt2_binop_tt_11_add(64, bvxor);  break;
      default:
         VG_(printf)("smt2_binop_tt_11: ");
         ppIROp(op);
         VG_(printf)(" not yet supported\n");
         tl_assert(0);
   }
}


// ltmp = <op> rtmp1 rtmp2
void TNT_(smt2_binop_tt) ( IRStmt *clone )
{
   IRExpr* arg1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
   IRExpr* arg2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
   UInt rtmp1   = arg1->Iex.RdTmp.tmp;
   UInt rtmp2   = arg2->Iex.RdTmp.tmp;

   if ( is_tainted(rtmp1) && !is_tainted(rtmp2) )
      tnt_smt2_binop_tt_10(clone);
   else if ( !is_tainted(rtmp1) && is_tainted(rtmp2) )
      tnt_smt2_binop_tt_01(clone);
   else if ( is_tainted(rtmp1) && is_tainted(rtmp2) )
      tnt_smt2_binop_tt_11(clone);
}


// ltmp = rtmp
void TNT_(smt2_rdtmp) ( IRStmt *clone )
{

   UInt ltmp = clone->Ist.WrTmp.tmp;
   UInt rtmp = clone->Ist.WrTmp.data->Iex.RdTmp.tmp;

   tl_assert(tt[rtmp]);

   VG_(printf)("(declare-fun t%d_%d () (_ BitVec %d))\n", ltmp, _ti(ltmp), tt[rtmp]);
   VG_(printf)("(assert (= t%d_%d t%d_%d))\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp) );
   tt[ltmp] = tt[rtmp];
}

// tmp = reg
void TNT_(smt2_get) ( IRStmt *clone )
{
   UInt ltmp    = clone->Ist.WrTmp.tmp;
   IRExpr *data = clone->Ist.WrTmp.data;
   UInt ty      = data->Iex.Get.ty - Ity_INVALID;
   UInt reg     = data->Iex.Get.offset/(sizeof(UWord));

   VG_(printf)("(declare-fun t%d_%d () (_ BitVec %d))\n", ltmp, _ti(ltmp), SMT2_ty[ty]);

   switch (SMT2_ty[ty]) {
      case 8:
         VG_(printf)("(assert (= t%d_%d ((_ extract 7 0) r%d_%d)))\n", ltmp, _ti(ltmp), reg, ri[reg] );
         break;
      case 16:
         VG_(printf)("(assert (= t%d_%d ((_ extract 15 0) r%d_%d)))\n", ltmp, _ti(ltmp), reg, ri[reg] );
         break;
      case 32:
         VG_(printf)("(assert (= t%d_%d ((_ extract 31 0) r%d_%d)))\n", ltmp, _ti(ltmp), reg, ri[reg] );
         break;
      case 64:
         VG_(printf)("(assert (= t%d_%d ((_ extract 63 0) r%d_%d)))\n", ltmp, _ti(ltmp), reg, ri[reg] );
         break;
      default:
         VG_(printf)("smt2_get: SMT2_ty[ty] = %d not yet supported\n", SMT2_ty[ty]);
         tl_assert(0);
   }
   tt[ltmp] = SMT2_ty[ty];
}

// reg = tmp
void TNT_(smt2_put_t_32) ( IRStmt *clone )
{

   UInt reg     = clone->Ist.Put.offset/(sizeof(UWord));
   IRExpr *data = clone->Ist.Put.data;
   UInt tmp     = data->Iex.RdTmp.tmp;

   tl_assert(tt[tmp]);

   VG_(printf)("(declare-fun r%d_%d () (_ BitVec 32))\n", reg, ri[reg]);

   switch (tt[tmp]) {
      case 8:
         VG_(printf)("(assert (= r%d_%d ((_ zero_extend 24) t%d_%d)))\n", reg, ri[reg], tmp, _ti(tmp) );
         break;
      case 16:
         VG_(printf)("(assert (= r%d_%d ((_ zero_extend 16) t%d_%d)))\n", reg, ri[reg], tmp, _ti(tmp) );
         break;
      case 32:
         VG_(printf)("(assert (= r%d_%d t%d_%d))\n", reg, ri[reg], tmp, _ti(tmp) );
         break;
      default:
         VG_(printf)("smt2_put: tt[tmp] = %d not yet supported\n", tt[tmp]);
         tl_assert(0);
         break;
   }
}

// reg = tmp
void TNT_(smt2_put_t_64) ( IRStmt *clone )
{

   UInt reg     = clone->Ist.Put.offset/(sizeof(UWord));
   IRExpr *data = clone->Ist.Put.data;
   UInt tmp     = data->Iex.RdTmp.tmp;

   tl_assert(tt[tmp]);

   VG_(printf)("(declare-fun r%d_%d () (_ BitVec 64))\n", reg, ri[reg]);

   switch (tt[tmp]) {
      case 8:
         VG_(printf)("(assert (= r%d_%d ((_ zero_extend 56) t%d_%d)))\n", reg, ri[reg], tmp, _ti(tmp) );
         break;
      case 16:
         VG_(printf)("(assert (= r%d_%d ((_ zero_extend 48) t%d_%d)))\n", reg, ri[reg], tmp, _ti(tmp) );
         break;
      case 32:
         VG_(printf)("(assert (= r%d_%d ((_ zero_extend 32) t%d_%d)))\n", reg, ri[reg], tmp, _ti(tmp) );
         break;
      case 64:
         VG_(printf)("(assert (= r%d_%d t%d_%d))\n", reg, ri[reg], tmp, _ti(tmp) );
         break;
      default:
         VG_(printf)("smt2_put: tt[tmp] = %d not yet supported\n", tt[tmp]);
         tl_assert(0);
         break;
   }
}

void TNT_(smt2_x86g_calculate_condition) ( IRStmt *clone )
{
   UInt ltmp    = clone->Ist.WrTmp.tmp;
   IRExpr *data = clone->Ist.WrTmp.data;
   UInt ty      = data->Iex.CCall.retty - Ity_INVALID;

   //char buf[1024];

   VG_(printf)("(declare-fun t%d_%d () (_ BitVec %d))\n", ltmp, _ti(ltmp), SMT2_ty[ty]);

   //VG_(printf)("(assert (= t%d_%d (%s)))\n", ltmp, _ti(ltmp),
   //         tnt_smt2_amd64g_calculate_condition_cond( clone, buf ) );

   tt[ltmp] = SMT2_ty[ty];
}

// VEX/priv/guest_amd64_defs.h
// extern ULong amd64g_calculate_condition ( 
//                 ULong/*AMD64Condcode*/ cond, 
//                 ULong cc_op, 
//                 ULong cc_dep1, ULong cc_dep2, ULong cc_ndep 
//              );
typedef
   enum {
      AMD64CondO      = 0,  /* overflow           */
      AMD64CondNO     = 1,  /* no overflow        */
      AMD64CondB      = 2,  /* below              */
      AMD64CondNB     = 3,  /* not below          */
      AMD64CondZ      = 4,  /* zero               */
      AMD64CondNZ     = 5,  /* not zero           */
      AMD64CondBE     = 6,  /* below or equal     */
      AMD64CondNBE    = 7,  /* not below or equal */
      AMD64CondS      = 8,  /* negative           */
      AMD64CondNS     = 9,  /* not negative       */
      AMD64CondP      = 10, /* parity even        */
      AMD64CondNP     = 11, /* not parity even    */
      AMD64CondL      = 12, /* jump less          */
      AMD64CondNL     = 13, /* not less           */
      AMD64CondLE     = 14, /* less or equal      */
      AMD64CondNLE    = 15, /* not less or equal  */
      AMD64CondAlways = 16  /* HACK */
   }
   AMD64Condcode;

enum {
    AMD64G_CC_OP_COPY=0,  /* DEP1 = current flags, DEP2 = 0, NDEP = unused */
                          /* just copy DEP1 to output */
    AMD64G_CC_OP_ADDB,    /* 1 */
    AMD64G_CC_OP_ADDW,    /* 2 DEP1 = argL, DEP2 = argR, NDEP = unused */
    AMD64G_CC_OP_ADDL,    /* 3 */
    AMD64G_CC_OP_ADDQ,    /* 4 */
    AMD64G_CC_OP_SUBB,    /* 5 */
    AMD64G_CC_OP_SUBW,    /* 6 DEP1 = argL, DEP2 = argR, NDEP = unused */
    AMD64G_CC_OP_SUBL,    /* 7 */
    AMD64G_CC_OP_SUBQ,    /* 8 */
    AMD64G_CC_OP_ADCB,    /* 9 */
    AMD64G_CC_OP_ADCW,    /* 10 DEP1 = argL, DEP2 = argR ^ oldCarry, NDEP = oldCarry */
    AMD64G_CC_OP_ADCL,    /* 11 */
    AMD64G_CC_OP_ADCQ,    /* 12 */
    AMD64G_CC_OP_SBBB,    /* 13 */
    AMD64G_CC_OP_SBBW,    /* 14 DEP1 = argL, DEP2 = argR ^ oldCarry, NDEP = oldCarry */
    AMD64G_CC_OP_SBBL,    /* 15 */
    AMD64G_CC_OP_SBBQ,    /* 16 */
    AMD64G_CC_OP_LOGICB,  /* 17 */
    AMD64G_CC_OP_LOGICW,  /* 18 DEP1 = result, DEP2 = 0, NDEP = unused */
    AMD64G_CC_OP_LOGICL,  /* 19 */
    AMD64G_CC_OP_LOGICQ,  /* 20 */
    AMD64G_CC_OP_INCB,    /* 21 */
    AMD64G_CC_OP_INCW,    /* 22 DEP1 = result, DEP2 = 0, NDEP = oldCarry (0 or 1) */
    AMD64G_CC_OP_INCL,    /* 23 */
    AMD64G_CC_OP_INCQ,    /* 24 */
    AMD64G_CC_OP_DECB,    /* 25 */
    AMD64G_CC_OP_DECW,    /* 26 DEP1 = result, DEP2 = 0, NDEP = oldCarry (0 or 1) */
    AMD64G_CC_OP_DECL,    /* 27 */
    AMD64G_CC_OP_DECQ,    /* 28 */
    AMD64G_CC_OP_SHLB,    /* 29 DEP1 = res, DEP2 = res', NDEP = unused */
    AMD64G_CC_OP_SHLW,    /* 30 where res' is like res but shifted one bit less */
    AMD64G_CC_OP_SHLL,    /* 31 */
    AMD64G_CC_OP_SHLQ,    /* 32 */
    AMD64G_CC_OP_SHRB,    /* 33 DEP1 = res, DEP2 = res', NDEP = unused */
    AMD64G_CC_OP_SHRW,    /* 34 where res' is like res but shifted one bit less */
    AMD64G_CC_OP_SHRL,    /* 35 */
    AMD64G_CC_OP_SHRQ,    /* 36 */
    AMD64G_CC_OP_ROLB,    /* 37 */
    AMD64G_CC_OP_ROLW,    /* 38 DEP1 = res, DEP2 = 0, NDEP = old flags */
    AMD64G_CC_OP_ROLL,    /* 39 */
    AMD64G_CC_OP_ROLQ,    /* 40 */
    AMD64G_CC_OP_RORB,    /* 41 */
    AMD64G_CC_OP_RORW,    /* 42 DEP1 = res, DEP2 = 0, NDEP = old flags */
    AMD64G_CC_OP_RORL,    /* 43 */
    AMD64G_CC_OP_RORQ,    /* 44 */
    AMD64G_CC_OP_UMULB,   /* 45 */
    AMD64G_CC_OP_UMULW,   /* 46 DEP1 = argL, DEP2 = argR, NDEP = unused */
    AMD64G_CC_OP_UMULL,   /* 47 */
    AMD64G_CC_OP_UMULQ,   /* 48 */
    AMD64G_CC_OP_SMULB,   /* 49 */
    AMD64G_CC_OP_SMULW,   /* 50 DEP1 = argL, DEP2 = argR, NDEP = unused */
    AMD64G_CC_OP_SMULL,   /* 51 */
    AMD64G_CC_OP_SMULQ,   /* 52 */
    AMD64G_CC_OP_NUMBER
};

static char *tnt_smt2_amd64g_calculate_condition_op_tc_common( IRStmt *clone, char *buf, UInt dep1tmp, ULong dep2c )
{
   IRExpr *data = clone->Ist.WrTmp.data;
   IRExpr *op   = data->Iex.CCall.args[1];
   ULong cc_op;

   if ( op->tag == Iex_Const )
      cc_op = extract_IRConst64( op->Iex.Const.con );
   else if ( op->tag == Iex_RdTmp ) {
      cc_op = tv[op->Iex.RdTmp.tmp];
   } else {
      VG_(printf)("cc_op->tag: %x\n", op->tag);
      tl_assert(0);
   }

   char tmp[1024];

   switch ( cc_op )
   {
      case AMD64G_CC_OP_SUBB:
         VG_(sprintf)(tmp, "(bvsub ((_ extract 7 0) t%d_%d) #x%02x) #x%02x",
            dep1tmp, _ti(dep1tmp),
            (char)dep2c, 0 );
         break;
      case AMD64G_CC_OP_SUBW:
         VG_(sprintf)(tmp, "(bvsub ((_ extract 15 0) t%d_%d) #x%04x) #x%04x",
            dep1tmp, _ti(dep1tmp),
            (short)dep2c, 0 );
         break;
      case AMD64G_CC_OP_SUBL:
         VG_(sprintf)(tmp, "(bvsub ((_ extract 31 0) t%d_%d) #x%08x) #x%08x",
            dep1tmp, _ti(dep1tmp),
            (int)dep2c, 0 );
         break;
      case AMD64G_CC_OP_SUBQ:
         VG_(sprintf)(tmp, "(bvsub t%d_%d #x%016llx) #x%016llx",
            dep1tmp, _ti(dep1tmp),
            dep2c, 0LL );
         break;
      default:
         VG_(printf)("smt2_amd64g_calculate_condition: cc_op = %llx not yet supported\n", cc_op);
         tl_assert(0);
   }
   VG_(strcpy)(buf, tmp);
   return buf;
}

static char *tnt_smt2_amd64g_calculate_condition_op_tc( IRStmt *clone, char *buf )
{
   IRExpr *data = clone->Ist.WrTmp.data;
   IRExpr *dep1 = data->Iex.CCall.args[2];
   IRExpr *dep2 = data->Iex.CCall.args[3];

   UInt dep1tmp = dep1->Iex.RdTmp.tmp;
   ULong dep2c  = extract_IRConst64( dep2->Iex.Const.con );

   return tnt_smt2_amd64g_calculate_condition_op_tc_common( clone, buf, dep1tmp, dep2c );
}

static char *tnt_smt2_amd64g_calculate_condition_op_ct_common( IRStmt *clone, char *buf, ULong dep1c, UInt dep2tmp )
{
   IRExpr *data = clone->Ist.WrTmp.data;
   IRExpr *op   = data->Iex.CCall.args[1];
   ULong cc_op;

   if ( op->tag == Iex_Const )
      cc_op = extract_IRConst64( op->Iex.Const.con );
   else if ( op->tag == Iex_RdTmp ) {
      cc_op = tv[op->Iex.RdTmp.tmp];
   } else {
      VG_(printf)("cc_op->tag: %x\n", op->tag);
      tl_assert(0);
   }

   char tmp[1024];

   switch ( cc_op )
   {
      case AMD64G_CC_OP_SUBB:
         VG_(sprintf)(tmp, "(bvsub #x%02x ((_ extract 7 0) t%d_%d)) #x%02x",
            (char)dep1c,
            dep2tmp, _ti(dep2tmp), 0 );
         break;
      case AMD64G_CC_OP_SUBW:
         VG_(sprintf)(tmp, "(bvsub #x%04x ((_ extract 15 0) t%d_%d)) #x%04x",
            (short)dep1c,
            dep2tmp, _ti(dep2tmp), 0 );
         break;
      case AMD64G_CC_OP_SUBL:
         VG_(sprintf)(tmp, "(bvsub #x%08x ((_ extract 31 0) t%d_%d)) #x%08x",
            (int)dep1c,
            dep2tmp, _ti(dep2tmp), 0 );
         break;
      case AMD64G_CC_OP_SUBQ:
         VG_(sprintf)(tmp, "(bvsub #x%016llx t%d_%d) #x%016llx",
            dep1c,
            dep2tmp, _ti(dep2tmp), 0LL );
         break;
      default:
         VG_(printf)("smt2_amd64g_calculate_condition: cc_op = %llx not yet supported\n", cc_op);
         tl_assert(0);
   }
   VG_(strcpy)(buf, tmp);
   return buf;
}

static char *tnt_smt2_amd64g_calculate_condition_op_ct( IRStmt *clone, char *buf )
{
   IRExpr *data = clone->Ist.WrTmp.data;
   IRExpr *dep1 = data->Iex.CCall.args[2];
   IRExpr *dep2 = data->Iex.CCall.args[3];

   ULong dep1c  = extract_IRConst64( dep1->Iex.Const.con );
   UInt dep2tmp = dep2->Iex.RdTmp.tmp;

   return tnt_smt2_amd64g_calculate_condition_op_ct_common( clone, buf, dep1c, dep2tmp );
}

static char *tnt_smt2_amd64g_calculate_condition_op_tt_01( IRStmt *clone, char *buf )
{
   IRExpr *data = clone->Ist.WrTmp.data;
   IRExpr *dep1 = data->Iex.CCall.args[2];
   IRExpr *dep2 = data->Iex.CCall.args[3];

   UInt dep1tmp = dep1->Iex.RdTmp.tmp;
   ULong dep1c  = tv[dep1tmp];
   UInt dep2tmp = dep2->Iex.RdTmp.tmp;

   return tnt_smt2_amd64g_calculate_condition_op_ct_common( clone, buf, dep1c, dep2tmp );
}

static char *tnt_smt2_amd64g_calculate_condition_op_tt_10( IRStmt *clone, char *buf )
{
   IRExpr *data = clone->Ist.WrTmp.data;
   IRExpr *dep1 = data->Iex.CCall.args[2];
   IRExpr *dep2 = data->Iex.CCall.args[3];

   UInt dep1tmp = dep1->Iex.RdTmp.tmp;
   UInt dep2tmp = dep2->Iex.RdTmp.tmp;
   ULong dep2c  = tv[dep2tmp];

   return tnt_smt2_amd64g_calculate_condition_op_tc_common( clone, buf, dep1tmp, dep2c );
}

static char *tnt_smt2_amd64g_calculate_condition_op_tt_11( IRStmt *clone, char *buf )
{
   IRExpr *data = clone->Ist.WrTmp.data;
   IRExpr *dep1 = data->Iex.CCall.args[2];
   IRExpr *dep2 = data->Iex.CCall.args[3];
   UInt dep1tmp = dep1->Iex.RdTmp.tmp;
   UInt dep2tmp = dep2->Iex.RdTmp.tmp;
   IRExpr *op   = data->Iex.CCall.args[1];
   ULong cc_op;

   if ( op->tag == Iex_Const )
      cc_op = extract_IRConst64( op->Iex.Const.con );
   else if ( op->tag == Iex_RdTmp ) {
      cc_op = tv[op->Iex.RdTmp.tmp];
   } else {
      VG_(printf)("cc_op->tag: %x\n", op->tag);
      tl_assert(0);
   }

   char tmp[1024];

   switch ( cc_op )
   {
      case AMD64G_CC_OP_SUBB:
         VG_(sprintf)(tmp, "(bvsub t%d_%d t%d_%d) #x%02x",
            dep1tmp, _ti(dep1tmp),
            dep2tmp, _ti(dep2tmp), 0 );
         break;
      case AMD64G_CC_OP_SUBW:
         VG_(sprintf)(tmp, "(bvsub t%d_%d t%d_%d) #x%04x",
            dep1tmp, _ti(dep1tmp),
            dep2tmp, _ti(dep2tmp), 0 );
         break;
      case AMD64G_CC_OP_SUBL:
         VG_(sprintf)(tmp, "(bvsub t%d_%d t%d_%d) #x%08x",
            dep1tmp, _ti(dep1tmp),
            dep2tmp, _ti(dep2tmp), 0 );
         break;
      case AMD64G_CC_OP_SUBQ:
         VG_(sprintf)(tmp, "(bvsub t%d_%d t%d_%d) #x%016llx",
            dep1tmp, _ti(dep1tmp),
            dep2tmp, _ti(dep2tmp), 0LL );
         break;
      default:
         VG_(printf)("smt2_amd64g_calculate_condition: cc_op = %llx not yet supported\n", cc_op);
         tl_assert(0);
   }
   VG_(strcpy)(buf, tmp);
   return buf;
}

static char *tnt_smt2_amd64g_calculate_condition_op( IRStmt *clone, char *buf )
{
   IRExpr *data = clone->Ist.WrTmp.data;
   IRExpr *dep1 = data->Iex.CCall.args[2];
   IRExpr *dep2 = data->Iex.CCall.args[3];

   if ( dep1->tag == Iex_RdTmp && dep2->tag == Iex_Const )
      return tnt_smt2_amd64g_calculate_condition_op_tc(clone, buf);
   else if ( dep1->tag == Iex_Const && dep2->tag == Iex_RdTmp )
      return tnt_smt2_amd64g_calculate_condition_op_ct(clone, buf);
   else if ( dep1->tag == Iex_RdTmp && dep2->tag == Iex_RdTmp ) {
      UInt dep1tmp = dep1->Iex.RdTmp.tmp;
      UInt dep2tmp = dep2->Iex.RdTmp.tmp;
      if ( !is_tainted(dep1tmp) && is_tainted(dep2tmp) )
         return tnt_smt2_amd64g_calculate_condition_op_tt_01(clone, buf);
      else if ( is_tainted(dep1tmp) && !is_tainted(dep2tmp) )
         return tnt_smt2_amd64g_calculate_condition_op_tt_10(clone, buf);
      else if ( is_tainted(dep1tmp) && is_tainted(dep2tmp) )
         return tnt_smt2_amd64g_calculate_condition_op_tt_11(clone, buf);
      else
         tl_assert(0);
   } else
      tl_assert(0);
}

static char *tnt_smt2_amd64g_calculate_condition_cond( IRStmt *clone, char *buf )
{
   IRExpr *data = clone->Ist.WrTmp.data;
   tl_assert( data->Iex.CCall.args[0]->tag == Iex_Const );
   ULong cond   = extract_IRConst64( data->Iex.CCall.args[0]->Iex.Const.con );

   char tmp[1024];

   switch ( cond )
   {
      case AMD64CondZ:
         VG_(sprintf)(tmp, "ite (= %s) #x%016llx #x%016llx",
            tnt_smt2_amd64g_calculate_condition_op(clone, buf),
            1LL, 0LL );
         break;
      case AMD64CondNZ:
         VG_(sprintf)(tmp, "ite (not (= %s)) #x%016llx #x%016llx",
            tnt_smt2_amd64g_calculate_condition_op(clone, buf),
            1LL, 0LL );
         break;
      case AMD64CondS:
         VG_(sprintf)(tmp, "ite (bvslt %s) #x%016llx #x%016llx",
            tnt_smt2_amd64g_calculate_condition_op(clone, buf),
            1LL, 0LL );
         break;
      case AMD64CondNS:
         VG_(sprintf)(tmp, "ite (bvsge %s) #x%016llx #x%016llx",
            tnt_smt2_amd64g_calculate_condition_op(clone, buf),
            1LL, 0LL );
         break;
      default:
         VG_(printf)("smt2_amd64g_calculate_condition: cond = %llx not yet supported\n", cond);
         tl_assert(0);
   }
   VG_(strcpy)(buf, tmp);
   return buf;
}

void TNT_(smt2_amd64g_calculate_condition) ( IRStmt *clone )
{
   UInt ltmp    = clone->Ist.WrTmp.tmp;
   IRExpr *data = clone->Ist.WrTmp.data;
   UInt ty      = data->Iex.CCall.retty - Ity_INVALID;

   char buf[1024];

   VG_(printf)("(declare-fun t%d_%d () (_ BitVec %d))\n", ltmp, _ti(ltmp), SMT2_ty[ty]);

   VG_(printf)("(assert (= t%d_%d (%s)))\n", ltmp, _ti(ltmp),
            tnt_smt2_amd64g_calculate_condition_cond( clone, buf ) );

   tt[ltmp] = SMT2_ty[ty];
}

void TNT_(smt2_ite_tt) ( IRStmt *clone )
{
   UInt ltmp    = clone->Ist.WrTmp.tmp;
   IRExpr *data = clone->Ist.WrTmp.data;
   UInt ctmp    = data->Iex.ITE.cond->Iex.RdTmp.tmp;
   UInt ttmp    = data->Iex.ITE.iftrue->Iex.RdTmp.tmp;
   UInt ftmp    = data->Iex.ITE.iffalse->Iex.RdTmp.tmp;

   VG_(printf)("(declare-fun t%d_%d () (_ BitVec %d))\n", ltmp, _ti(ltmp), tt[ttmp]);

   if ( !is_tainted(ctmp) && !is_tainted(ttmp) && is_tainted(ftmp) ) {
      VG_(printf)("(assert (= t%d_%d (ite #b%d %016llx t%d_%d)))\n",
            ltmp, _ti(ltmp),
            (char)tv[ctmp],
            tv[ttmp],
            ftmp, _ti(ftmp) );
   } else if ( is_tainted(ctmp) && !is_tainted(ttmp) && is_tainted(ftmp) ) {
      VG_(printf)("(assert (= t%d_%d (ite t%d_%d %016llx t%d_%d)))\n",
            ltmp, _ti(ltmp),
            ctmp, _ti(ctmp),
            tv[ttmp],
            ftmp, _ti(ftmp) );
   } else if ( !is_tainted(ctmp) && !is_tainted(ttmp) && is_tainted(ftmp) ) {
      VG_(printf)("(assert (= t%d_%d (ite #b%d t%d_%d %016llx)))\n",
            ltmp, _ti(ltmp),
            (char)tv[ctmp],
            ttmp, _ti(ttmp),
            tv[ftmp] );
   } else if ( is_tainted(ctmp) && !is_tainted(ttmp) && is_tainted(ftmp) ) {
      VG_(printf)("(assert (= t%d_%d (ite t%d_%d t%d_%d %016llx)))\n",
            ltmp, _ti(ltmp),
            ctmp, _ti(ctmp),
            ttmp, _ti(ttmp),
            tv[ftmp] );
   } else if ( !is_tainted(ctmp) && is_tainted(ttmp) && is_tainted(ftmp) ) {
      VG_(printf)("(assert (= t%d_%d (ite #b%d t%d_%d t%d_%d)))\n",
            ltmp, _ti(ltmp),
            (char)tv[ctmp],
            ttmp, _ti(ttmp),
            ftmp, _ti(ftmp) );
   } else if ( is_tainted(ctmp) && is_tainted(ttmp) && is_tainted(ftmp) ) {
      VG_(printf)("(assert (= t%d_%d (ite t%d_%d t%d_%d t%d_%d)))\n",
            ltmp, _ti(ltmp),
            ctmp, _ti(ctmp),
            ttmp, _ti(ttmp),
            ftmp, _ti(ftmp) );
   }

   tt[ltmp] = tt[ttmp];
}
