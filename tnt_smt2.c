#include "pub_tool_basics.h"
#include "pub_tool_hashtable.h"   // For tnt_include.h, VgHashtable
#include "pub_tool_libcassert.h"  // tl_assert
#include "pub_tool_libcbase.h"    // VG_strcpy
#include "pub_tool_libcprint.h"   // VG_(printf)
#include "pub_tool_machine.h"     // IRStmt
#include "pub_tool_tooliface.h"   // VG_(CallbackClosure)

#include "tnt_include.h"

char *TNT_(smt2_concat)( char *buf, ULong addr, UInt c );

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
UInt tt[TI_MAX];

void TNT_(smt2_preamble)()
{
    VG_(printf)("(set-logic QF_BV)\n");
}

char *TNT_(smt2_concat)( char *buf, ULong addr, UInt c )
{
   char tmp[1024];

   if ( c == 0 )
   {
      VG_(sprintf)(buf, "(concat a%llx a%llx)", addr, addr+1);
      return buf;
   }
   VG_(sprintf)(tmp, "(concat a%llx %s)", addr, TNT_(smt2_concat)(buf, addr+1, c-1) );
   VG_(strcpy)(buf, tmp);
   return buf;
}

// ltmp = LOAD <ty> atmp
void TNT_(smt2_load_t) (
   IRStmt *clone,
   ULong value,
   ULong taint ) {

   UInt ltmp     = clone->Ist.WrTmp.tmp;
   UInt ty       = clone->Ist.WrTmp.data->Iex.Load.ty - Ity_INVALID;
   IRExpr* addr  = clone->Ist.WrTmp.data->Iex.Load.addr;
   UInt atmp     = addr->Iex.RdTmp.tmp;
   ULong address = tv[atmp];
   char buf[1024];

   if ( SMT2_ty[ty] == 32 )
   {
      VG_(printf)("(declare-fun t%d_%d () (_ BitVec %d))\n", ltmp, _ti(ltmp), SMT2_ty[ty]);
      //VG_(printf)("(assert (= t%d_%d (concat a%llx %s)))\n", ltmp, _ti(ltmp), address, TNT_(smt2_concat)(buf, address+1, 1) );
      VG_(printf)("(assert (= t%d_%d %s))\n", ltmp, _ti(ltmp), TNT_(smt2_concat)(buf, address, 2) );
      tt[ltmp] = SMT2_ty[ty];
   } else {
      VG_(printf)("SMT2_ty[ty] = %d\n", SMT2_ty[ty]);
      tl_assert(0);
   }
}

// STORE atmp = dtmp
void TNT_(smt2_store_tt) (
   IRStmt *clone,
   ULong value,
   ULong taint ) {

   IRExpr *addr = clone->Ist.Store.addr;
   IRExpr *data = clone->Ist.Store.data;
   UInt atmp    = addr->Iex.RdTmp.tmp;
   UInt dtmp    = data->Iex.RdTmp.tmp;
   ULong address = tv[atmp];
   int i;

   tl_assert(tt[dtmp]);

   int numbytes = tt[dtmp]/8;

   for ( i=0; i<numbytes; i++ )
   {
      VG_(printf)("(declare-fun a%llx () (_ BitVec 8))\n", address+i);
      VG_(printf)("(assert (= a%llx ((_ extract %d %d) t%d_%d)))\n", address+i, ((i+1)*8)-1, i*8, dtmp, _ti(dtmp) );
   }
}


// ltmp = <op> rtmp
void TNT_(smt2_unop_t) (
   IRStmt *clone,
   ULong value,
   ULong taint ) {

   UInt ltmp   = clone->Ist.WrTmp.tmp;
   UInt op     = clone->Ist.WrTmp.data->Iex.Unop.op;
   IRExpr* arg = clone->Ist.WrTmp.data->Iex.Unop.arg;
   UInt rtmp   = arg->Iex.RdTmp.tmp;

   switch(op) {
      case Iop_1Uto64:
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec 64))\n", ltmp, _ti(ltmp));
         VG_(printf)("(assert (= t%d_%d ((_ zero_extend 63) t%d_%d)))\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp) );
         tt[ltmp] = 64;
         break;
      case Iop_32Uto64:
   
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec 64))\n", ltmp, _ti(ltmp));
         VG_(printf)("(assert (= t%d_%d ((_ zero_extend 32) t%d_%d)))\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp) );
         tt[ltmp] = 64;
         break;
      case Iop_64to1:
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec 1))\n", ltmp, _ti(ltmp));
         VG_(printf)("(assert (= t%d_%d ((_ extract 1 0) t%d_%d)))\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp) );
         tt[ltmp] = 1;
         break;
      case Iop_64to32:
         VG_(printf)("(declare-fun t%d_%d () (_ BitVec 32))\n", ltmp, _ti(ltmp));
         VG_(printf)("(assert (= t%d_%d ((_ extract 31 0) t%d_%d)))\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp) );
         tt[ltmp] = 32;
         break;
      default:
         VG_(printf)("%s\n", IROp_string[op-Iop_INVALID]);
         tl_assert(0);
   }
}

// ltmp = rtmp
void TNT_(smt2_rdtmp) (
   IRStmt *clone,
   ULong value,
   ULong taint ) {

   UInt ltmp = clone->Ist.WrTmp.tmp;
   UInt rtmp = clone->Ist.WrTmp.data->Iex.RdTmp.tmp;

   tl_assert(tt[rtmp]);

   VG_(printf)("(declare-fun t%d_%d () (_ BitVec %d))\n", ltmp, _ti(ltmp), tt[rtmp]);
   VG_(printf)("(assert (= t%d_%d t%d_%d))\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp) );
   tt[ltmp] = tt[rtmp];
}

// reg = tmp
void TNT_(smt2_put_t) (
   IRStmt *clone,
   ULong value,
   ULong taint ) {

   UInt reg     = clone->Ist.Put.offset;
   IRExpr *data = clone->Ist.Put.data;
   UInt tmp     = data->Iex.RdTmp.tmp;

   tl_assert(tt[tmp]);

   VG_(printf)("(declare-fun r%d_%d () (_ BitVec %d))\n", reg, ri[reg], tt[tmp]);
   VG_(printf)("(assert (= r%d_%d t%d_%d))\n", reg, ri[reg], tmp, _ti(tmp) );
}
