#include "pub_tool_basics.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_machine.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_vki.h"
#include "pub_tool_aspacemgr.h"

#include "tnt_include.h"

const Int SMT2_ty[] = {
   0, 1, 8, 16, 32, 64, 128, 16, 32, 64, 32, 64, 128, 128, 128, 256
};

extern UInt *tt;

static Int trace_fd = -1;
static ULong trace_seq = 0;
static ULong tmp_def_seq[TI_MAX];
static ULong reg_def_seq[RI_MAX];

static const HChar *stmt_name(IRStmtTag tag)
{
   switch (tag) {
      case Ist_Put: return "Put";
      case Ist_PutI: return "PutI";
      case Ist_WrTmp: return "WrTmp";
      case Ist_Store: return "Store";
      case Ist_Exit: return "Exit";
      case Ist_Dirty: return "Dirty";
      default: return "Other";
   }
}

static const HChar *expr_name(IRExprTag tag)
{
   switch (tag) {
      case Iex_Get: return "Get";
      case Iex_GetI: return "GetI";
      case Iex_RdTmp: return "RdTmp";
      case Iex_Qop: return "Qop";
      case Iex_Triop: return "Triop";
      case Iex_Binop: return "Binop";
      case Iex_Unop: return "Unop";
      case Iex_Load: return "Load";
      case Iex_Const: return "Const";
      case Iex_ITE: return "ITE";
      case Iex_CCall: return "CCall";
      case Iex_VECRET: return "VECRET";
      case Iex_GSPTR: return "GSPTR";
      default: return "Other";
   }
}

static const HChar *op_name(IROp op)
{
   switch (op) {
      case Iop_Add8: return "Add8";
      case Iop_Add16: return "Add16";
      case Iop_Add32: return "Add32";
      case Iop_Add64: return "Add64";
      case Iop_Sub8: return "Sub8";
      case Iop_Sub16: return "Sub16";
      case Iop_Sub32: return "Sub32";
      case Iop_Sub64: return "Sub64";
      case Iop_Mul8: return "Mul8";
      case Iop_Mul16: return "Mul16";
      case Iop_Mul32: return "Mul32";
      case Iop_Mul64: return "Mul64";
      case Iop_Or8: return "Or8";
      case Iop_Or16: return "Or16";
      case Iop_Or32: return "Or32";
      case Iop_Or64: return "Or64";
      case Iop_And8: return "And8";
      case Iop_And16: return "And16";
      case Iop_And32: return "And32";
      case Iop_And64: return "And64";
      case Iop_Xor8: return "Xor8";
      case Iop_Xor16: return "Xor16";
      case Iop_Xor32: return "Xor32";
      case Iop_Xor64: return "Xor64";
      case Iop_Shl8: return "Shl8";
      case Iop_Shl16: return "Shl16";
      case Iop_Shl32: return "Shl32";
      case Iop_Shl64: return "Shl64";
      case Iop_Shr8: return "Shr8";
      case Iop_Shr16: return "Shr16";
      case Iop_Shr32: return "Shr32";
      case Iop_Shr64: return "Shr64";
      case Iop_Sar8: return "Sar8";
      case Iop_Sar16: return "Sar16";
      case Iop_Sar32: return "Sar32";
      case Iop_Sar64: return "Sar64";
      case Iop_CmpEQ8: return "CmpEQ8";
      case Iop_CmpEQ16: return "CmpEQ16";
      case Iop_CmpEQ32: return "CmpEQ32";
      case Iop_CmpEQ64: return "CmpEQ64";
      case Iop_CmpNE8: return "CmpNE8";
      case Iop_CmpNE16: return "CmpNE16";
      case Iop_CmpNE32: return "CmpNE32";
      case Iop_CmpNE64: return "CmpNE64";
      case Iop_CmpNEZ8: return "CmpNEZ8";
      case Iop_CmpNEZ16: return "CmpNEZ16";
      case Iop_CmpNEZ32: return "CmpNEZ32";
      case Iop_CmpNEZ64: return "CmpNEZ64";
      case Iop_CmpwNEZ32: return "CmpwNEZ32";
      case Iop_CmpwNEZ64: return "CmpwNEZ64";
      case Iop_CmpLT32S: return "CmpLT32S";
      case Iop_CmpLT64S: return "CmpLT64S";
      case Iop_CmpLT32U: return "CmpLT32U";
      case Iop_CmpLT64U: return "CmpLT64U";
      case Iop_CmpLE32S: return "CmpLE32S";
      case Iop_CmpLE64S: return "CmpLE64S";
      case Iop_CmpLE32U: return "CmpLE32U";
      case Iop_CmpLE64U: return "CmpLE64U";
      case Iop_Not1: return "Not1";
      case Iop_Not8: return "Not8";
      case Iop_Not16: return "Not16";
      case Iop_Not32: return "Not32";
      case Iop_Not64: return "Not64";
      case Iop_And1: return "And1";
      case Iop_Or1: return "Or1";
      case Iop_1Sto8: return "1Sto8";
      case Iop_1Sto16: return "1Sto16";
      case Iop_1Sto32: return "1Sto32";
      case Iop_1Sto64: return "1Sto64";
      case Iop_1Uto8: return "1Uto8";
      case Iop_1Uto32: return "1Uto32";
      case Iop_1Uto64: return "1Uto64";
      case Iop_8Sto16: return "8Sto16";
      case Iop_8Sto32: return "8Sto32";
      case Iop_8Sto64: return "8Sto64";
      case Iop_8Uto16: return "8Uto16";
      case Iop_8Uto32: return "8Uto32";
      case Iop_8Uto64: return "8Uto64";
      case Iop_16to8: return "16to8";
      case Iop_16HIto8: return "16HIto8";
      case Iop_16Sto32: return "16Sto32";
      case Iop_16Sto64: return "16Sto64";
      case Iop_16Uto32: return "16Uto32";
      case Iop_16Uto64: return "16Uto64";
      case Iop_16HLto32: return "16HLto32";
      case Iop_32to1: return "32to1";
      case Iop_32to8: return "32to8";
      case Iop_32to16: return "32to16";
      case Iop_32HIto16: return "32HIto16";
      case Iop_32Sto64: return "32Sto64";
      case Iop_32Uto64: return "32Uto64";
      case Iop_32HLto64: return "32HLto64";
      case Iop_64to1: return "64to1";
      case Iop_64to8: return "64to8";
      case Iop_64to16: return "64to16";
      case Iop_64to32: return "64to32";
      case Iop_64HIto32: return "64HIto32";
      case Iop_128to64: return "128to64";
      case Iop_128HIto64: return "128HIto64";
      case Iop_CtzNat64: return "CtzNat64";
      case Iop_CtzNat32: return "CtzNat32";
      case Iop_ClzNat64: return "ClzNat64";
      case Iop_ClzNat32: return "ClzNat32";
      case Iop_GetMSBs8x8: return "GetMSBs8x8";
      case Iop_GetMSBs8x16: return "GetMSBs8x16";
      case Iop_CmpEQ8x16: return "CmpEQ8x16";
      case Iop_CmpEQ8x32: return "CmpEQ8x32";
      case Iop_AndV128: return "AndV128";
      case Iop_OrV128: return "OrV128";
      case Iop_XorV128: return "XorV128";
      case Iop_NotV128: return "NotV128";
      case Iop_AndV256: return "AndV256";
      case Iop_OrV256: return "OrV256";
      case Iop_XorV256: return "XorV256";
      case Iop_NotV256: return "NotV256";
      case Iop_CmpF64: return "CmpF64";
      case Iop_CmpNEZ8x16: return "CmpNEZ8x16";
      case Iop_CmpNEZ16x8: return "CmpNEZ16x8";
      case Iop_CmpNEZ32x4: return "CmpNEZ32x4";
      case Iop_CmpNEZ64x2: return "CmpNEZ64x2";
      default: return "IROp";
   }
}

static UInt op_result_bits(IROp op)
{
   switch (op) {
      case Iop_CmpEQ8: case Iop_CmpEQ16: case Iop_CmpEQ32: case Iop_CmpEQ64:
      case Iop_CmpNE8: case Iop_CmpNE16: case Iop_CmpNE32: case Iop_CmpNE64:
      case Iop_CmpLT32S: case Iop_CmpLT64S: case Iop_CmpLT32U: case Iop_CmpLT64U:
      case Iop_CmpLE32S: case Iop_CmpLE64S: case Iop_CmpLE32U: case Iop_CmpLE64U:
      case Iop_32to1: case Iop_64to1:
         return 1;
      
      case Iop_Add8: case Iop_Sub8: case Iop_Mul8: case Iop_Or8: case Iop_And8:
      case Iop_Xor8: case Iop_Shl8: case Iop_Shr8: case Iop_Sar8: case Iop_Not8:
      case Iop_1Sto8: case Iop_1Uto8: case Iop_16to8: case Iop_16HIto8:
      case Iop_32to8: case Iop_64to8:
         return 8;
      
      case Iop_Add16: case Iop_Sub16: case Iop_Mul16: case Iop_Or16: case Iop_And16:
      case Iop_Xor16: case Iop_Shl16: case Iop_Shr16: case Iop_Sar16: case Iop_Not16:
      case Iop_1Sto16: case Iop_8Sto16: case Iop_8Uto16: case Iop_32to16:
      case Iop_32HIto16: case Iop_64to16:
         return 16;
      
      case Iop_Add32: case Iop_Sub32: case Iop_Mul32: case Iop_Or32: case Iop_And32:
      case Iop_Xor32: case Iop_Shl32: case Iop_Shr32: case Iop_Sar32: case Iop_Not32:
      case Iop_1Sto32: case Iop_1Uto32: case Iop_8Sto32: case Iop_8Uto32:
      case Iop_16Sto32: case Iop_16Uto32: case Iop_64to32: case Iop_64HIto32:
      case Iop_16HLto32: case Iop_CmpF64:
         return 32;
 
      case Iop_Add64: case Iop_Sub64: case Iop_Mul64: case Iop_Or64: case Iop_And64:
      case Iop_Xor64: case Iop_Shl64: case Iop_Shr64: case Iop_Sar64: case Iop_Not64:
      case Iop_1Sto64: case Iop_1Uto64: case Iop_8Sto64: case Iop_8Uto64:
      case Iop_16Sto64: case Iop_16Uto64: case Iop_32Sto64: case Iop_32Uto64:
      case Iop_32HLto64:
      case Iop_128to64: case Iop_128HIto64: case Iop_CtzNat64: case Iop_ClzNat64:
      case Iop_CmpwNEZ64:
         return 64;
      
      case Iop_CtzNat32: case Iop_ClzNat32: case Iop_CmpwNEZ32:
      case Iop_CmpNEZ8: case Iop_CmpNEZ16: case Iop_CmpNEZ32: case Iop_CmpNEZ64:
         return 32;
      
      case Iop_CmpEQ8x16:
      case Iop_AndV128: case Iop_OrV128: case Iop_XorV128: case Iop_NotV128:
         return 128;
      
      case Iop_CmpEQ8x32:
      case Iop_AndV256: case Iop_OrV256: case Iop_XorV256: case Iop_NotV256:
         return 256;
      
      case Iop_GetMSBs8x8:
         return 8;
      
      case Iop_GetMSBs8x16:
         return 16;
      
      default:
         return 0;
   }
}

static UInt const_bits(IRConst *con)
{
   switch (con->tag) {
      case Ico_U1: return 1;
      case Ico_U8: return 8;
      case Ico_U16: return 16;
      case Ico_U32: case Ico_F32: case Ico_F32i: return 32;
      case Ico_U64: case Ico_F64: case Ico_F64i: return 64;
      case Ico_U128: case Ico_V128: return 128;
      case Ico_V256: return 256;
      default: return 0;
   }
}

static ULong const_value(IRConst *con)
{
   switch (con->tag) {
      case Ico_U1: return con->Ico.U1 ? 1 : 0;
      case Ico_U8: return con->Ico.U8;
      case Ico_U16: return con->Ico.U16;
      case Ico_U32: return con->Ico.U32;
      case Ico_U64: return con->Ico.U64;
      case Ico_U128: return con->Ico.U128;
      case Ico_F32i: return con->Ico.F32i;
      case Ico_F64i: return con->Ico.F64i;
      case Ico_V128: return con->Ico.V128;
      case Ico_V256: return con->Ico.V256;
      default: return 0;
   }
}

static UInt tmp_bits(UInt tmp)
{
   if (tmp < TI_MAX && tt[tmp] != 0)
      return tt[tmp];
   return 0;
}

static UInt expr_bits(IRExpr *e)
{
   switch (e->tag) {
      case Iex_RdTmp: return tmp_bits(e->Iex.RdTmp.tmp);
      case Iex_Const: return const_bits(e->Iex.Const.con);
      case Iex_Get: return SMT2_ty[e->Iex.Get.ty - Ity_INVALID];
      case Iex_Load: return SMT2_ty[e->Iex.Load.ty - Ity_INVALID];
      case Iex_Unop: return op_result_bits(e->Iex.Unop.op);
      case Iex_Binop: return op_result_bits(e->Iex.Binop.op);
      case Iex_ITE: return expr_bits(e->Iex.ITE.iftrue);
      case Iex_CCall: return SMT2_ty[e->Iex.CCall.retty - Ity_INVALID];
      default: return 0;
   }
}

static ULong expr_value(IRExpr *e)
{
   switch (e->tag) {
      case Iex_RdTmp: return tv[e->Iex.RdTmp.tmp];
      case Iex_Const: return const_value(e->Iex.Const.con);
      default: return 0;
   }
}

static ULong expr_taint(IRExpr *e)
{
   switch (e->tag) {
      case Iex_RdTmp:
         return is_tainted(e->Iex.RdTmp.tmp) ? V_BITS64_TAINTED : 0;
      case Iex_Const:
         return 0;
      default:
         return 0;
   }
}

static void trace_write(const HChar *buf)
{
   if (trace_fd >= 0)
      (void)VG_(write)(trace_fd, buf, VG_(strlen)(buf));
   else
      VG_(printf)("%s", buf);
}

static void trace_puts(const HChar *s)
{
   trace_write(s);
}

static void trace_hex(ULong v)
{
   HChar buf[32];
   VG_(snprintf)(buf, sizeof(buf), "\"0x%llx\"", v);
   trace_write(buf);
}

static void trace_u64(ULong v)
{
   HChar buf[32];
   VG_(snprintf)(buf, sizeof(buf), "%llu", v);
   trace_write(buf);
}

static void trace_u(UInt v)
{
   HChar buf[24];
   VG_(snprintf)(buf, sizeof(buf), "%u", v);
   trace_write(buf);
}

static void trace_byte(UChar v)
{
   HChar buf[8];
   VG_(snprintf)(buf, sizeof(buf), "\"0x%02x\"", (UInt)v);
   trace_write(buf);
}

static void trace_json_string(const HChar *s)
{
   const HChar *p;
   HChar b[8];
   trace_puts("\"");
   for (p = s; p && *p; p++) {
      if (*p == '"' || *p == '\\') {
         b[0] = '\\'; b[1] = *p; b[2] = 0;
         trace_puts(b);
      } else if (*p == '\n') {
         trace_puts("\\n");
      } else if (*p == '\r') {
         trace_puts("\\r");
      } else if (*p == '\t') {
         trace_puts("\\t");
      } else {
         b[0] = *p; b[1] = 0;
         trace_puts(b);
      }
   }
   trace_puts("\"");
}

static void trace_tmp_obj(UInt tmp)
{
   trace_puts("{\"kind\":\"tmp\",\"id\":");
   trace_u(tmp);
   trace_puts(",\"ssa\":");
   trace_u(_ti(tmp));
   trace_puts(",\"def_seq\":");
   trace_u64(tmp_def_seq[tmp]);
   trace_puts(",\"bits\":");
   trace_u(tmp_bits(tmp));
   trace_puts(",\"value\":");
   trace_hex(tv[tmp]);
   trace_puts(",\"taint\":");
   trace_hex(is_tainted(tmp) ? V_BITS64_TAINTED : 0);
   trace_puts("}");
}

static void trace_reg_obj(UInt reg, UInt bits, ULong value, ULong taint)
{
   trace_puts("{\"kind\":\"reg\",\"id\":");
   trace_u(reg);
   trace_puts(",\"ssa\":");
   trace_u(ri[reg]);
   trace_puts(",\"def_seq\":");
   trace_u64(reg_def_seq[reg]);
   trace_puts(",\"bits\":");
   trace_u(bits);
   trace_puts(",\"value\":");
   trace_hex(value);
   trace_puts(",\"taint\":");
   trace_hex(taint);
   trace_puts("}");
}

static void trace_const_obj(IRConst *con)
{
   trace_puts("{\"kind\":\"const\",\"bits\":");
   trace_u(const_bits(con));
   trace_puts(",\"value\":");
   trace_hex(const_value(con));
   trace_puts(",\"taint\":\"0x0\"}");
}

static void trace_addr_obj(IRExpr *addr)
{
   ULong address;
   trace_puts("\"address\":{");
   if (addr->tag == Iex_RdTmp) {
      UInt tmp = addr->Iex.RdTmp.tmp;
      address = tv[tmp];
      trace_puts("\"expr\":");
      trace_tmp_obj(tmp);
      trace_puts(",\"value\":");
      trace_hex(address);
   } else if (addr->tag == Iex_Const) {
      address = const_value(addr->Iex.Const.con);
      trace_puts("\"expr\":");
      trace_const_obj(addr->Iex.Const.con);
      trace_puts(",\"value\":");
      trace_hex(address);
   } else {
      trace_puts("\"expr\":{\"kind\":\"");
      trace_puts(expr_name(addr->tag));
      trace_puts("\"},\"value\":\"0x0\"");
   }
   trace_puts("}");
}

static void trace_load_bytes(Addr addr, UInt bits)
{
   UInt i;
   UInt nbytes = (bits + 7) / 8;
   trace_puts(",\"bytes\":[");
   if (addr != 0 && VG_(am_is_valid_for_client)(addr, nbytes, VKI_PROT_READ)) {
      UChar *p = (UChar *)addr;
      for (i = 0; i < nbytes; i++) {
         if (i) trace_puts(",");
         trace_byte(p[i]);
      }
   }
   trace_puts("]");
}

static void trace_expr_obj(IRExpr *e)
{
   switch (e->tag) {
      case Iex_RdTmp:
         trace_tmp_obj(e->Iex.RdTmp.tmp);
         break;
      case Iex_Const:
         trace_const_obj(e->Iex.Const.con);
         break;
      case Iex_Get: {
         UInt reg = e->Iex.Get.offset/(sizeof(UWord));
         trace_reg_obj(reg, expr_bits(e), 0, 0);
         break;
      }
      default:
         trace_puts("{\"kind\":\"");
         trace_puts(expr_name(e->tag));
         trace_puts("\",\"bits\":");
         trace_u(expr_bits(e));
         trace_puts(",\"value\":");
         trace_hex(expr_value(e));
         trace_puts(",\"taint\":");
         trace_hex(expr_taint(e));
         trace_puts("}");
         break;
   }
}

static void trace_args1(IRExpr *a)
{
   trace_puts("\"args\":[");
   trace_expr_obj(a);
   trace_puts("]");
}

static void trace_args2(IRExpr *a, IRExpr *b)
{
   trace_puts("\"args\":[");
   trace_expr_obj(a);
   trace_puts(",");
   trace_expr_obj(b);
   trace_puts("]");
}

static const HChar *trace_wr_tmp_op_name(IRExpr *e)
{
   switch (e->tag) {
      case Iex_Unop:
         return op_name(e->Iex.Unop.op);
      case Iex_Binop:
         return op_name(e->Iex.Binop.op);
      case Iex_Triop:
         return op_name(e->Iex.Triop.details->op);
      case Iex_Qop:
         return op_name(e->Iex.Qop.details->op);
      case Iex_ITE:
         return "ITE";
      case Iex_CCall:
         return e->Iex.CCall.cee && e->Iex.CCall.cee->name
                   ? e->Iex.CCall.cee->name
                   : "CCall";
      default:
         return expr_name(e->tag);
   }
}

static void trace_stmt_start(IRStmt *clone, const HChar *op, UWord value, UWord taint)
{
   trace_seq++;
   trace_puts("{\"event\":\"stmt\",\"seq\":");
   trace_u64(trace_seq);
   trace_puts(",\"stmt\":\"");
   trace_puts(stmt_name(clone->tag));
   trace_puts("\",\"op\":");
   trace_json_string(op);
   trace_puts(",\"value\":");
   trace_hex(value);
   trace_puts(",\"taint\":");
   trace_hex(taint);
   trace_puts(",");
}

static void trace_stmt_end(void)
{
   trace_puts("}\n");
}

void TNT_(trace_open)(const HChar *path)
{
   if (path && path[0]) {
      SysRes sres = VG_(open)(path, VKI_O_CREAT|VKI_O_WRONLY|VKI_O_TRUNC,
                              VKI_S_IRUSR|VKI_S_IWUSR|VKI_S_IRGRP|VKI_S_IROTH);
      if (sr_isError(sres)) {
         VG_(printf)("taintgrind: cannot open --trace-file=%s\n", path);
         VG_(exit)(1);
      }
      trace_fd = sr_Res(sres);
   }
}

void TNT_(trace_close)(void)
{
   if (trace_fd >= 0) {
      VG_(close)(trace_fd);
      trace_fd = -1;
   }
}

void TNT_(smt2_preamble)(void)
{
   trace_puts("{\"event\":\"meta\",\"version\":1,\"format\":\"taintgrind-trace-jsonl\"}\n");
}

void TNT_(trace_source)(Addr a, SizeT len, const HChar *name)
{
   SizeT i;
   for (i = 0; i < len; i++) {
      trace_seq++;
      trace_puts("{\"event\":\"source\",\"seq\":");
      trace_u64(trace_seq);
      trace_puts(",\"addr\":");
      trace_hex((ULong)(a + i));
      trace_puts(",\"bits\":8,\"name\":");
      trace_json_string(name && name[0] ? name : "byte");
      trace_puts(",\"index\":");
      trace_u((UInt)i);
      trace_puts("}\n");
   }
}

void TNT_(trace_stmt)(IRStmt *clone, UWord value, UWord taint)
{
   const HChar *op = stmt_name(clone->tag);

   if (clone->tag == Ist_WrTmp)
      op = trace_wr_tmp_op_name(clone->Ist.WrTmp.data);

   trace_stmt_start(clone, op, value, taint);

   if (clone->tag == Ist_WrTmp) {
      UInt ltmp = clone->Ist.WrTmp.tmp;
      IRExpr *e = clone->Ist.WrTmp.data;
      UInt bits = expr_bits(e);
      
      if (bits)
         tt[ltmp] = bits;
      
      trace_puts("\"expr\":\"");
      trace_puts(expr_name(e->tag));
      trace_puts("\",\"dst\":");
      tmp_def_seq[ltmp] = trace_seq;
      trace_tmp_obj(ltmp);
      
      switch (e->tag) {
         case Iex_GetI:
            trace_puts(",");
            trace_args1(e->Iex.GetI.ix);
            break;
         case Iex_Unop:
            trace_puts(",\"irop\":");
            trace_json_string(op_name(e->Iex.Unop.op));
            trace_puts(",\"irop_code\":");
            trace_u((UInt)e->Iex.Unop.op);
            trace_puts(",");
            trace_args1(e->Iex.Unop.arg);
            break;
         case Iex_Binop:
            trace_puts(",\"irop\":");
            trace_json_string(op_name(e->Iex.Binop.op));
            trace_puts(",\"irop_code\":");
            trace_u((UInt)e->Iex.Binop.op);
            trace_puts(",");
            trace_args2(e->Iex.Binop.arg1, e->Iex.Binop.arg2);
            break;
         case Iex_Triop:
            trace_puts(",\"irop\":");
            trace_json_string(op_name(e->Iex.Triop.details->op));
            trace_puts(",\"irop_code\":");
            trace_u((UInt)e->Iex.Triop.details->op);
            trace_puts(",\"args\":[");
            trace_expr_obj(e->Iex.Triop.details->arg1);
            trace_puts(",");
            trace_expr_obj(e->Iex.Triop.details->arg2);
            trace_puts(",");
            trace_expr_obj(e->Iex.Triop.details->arg3);
            trace_puts("]");
            break;
         case Iex_Qop:
            trace_puts(",\"irop\":");
            trace_json_string(op_name(e->Iex.Qop.details->op));
            trace_puts(",\"irop_code\":");
            trace_u((UInt)e->Iex.Qop.details->op);
            trace_puts(",\"args\":[");
            trace_expr_obj(e->Iex.Qop.details->arg1);
            trace_puts(",");
            trace_expr_obj(e->Iex.Qop.details->arg2);
            trace_puts(",");
            trace_expr_obj(e->Iex.Qop.details->arg3);
            trace_puts(",");
            trace_expr_obj(e->Iex.Qop.details->arg4);
            trace_puts("]");
            break;
         case Iex_CCall: {
            Int i;
            trace_puts(",\"helper\":");
            trace_json_string(e->Iex.CCall.cee && e->Iex.CCall.cee->name
                              ? e->Iex.CCall.cee->name
                              : "CCall");
            trace_puts(",\"args\":[");
            for (i = 0; e->Iex.CCall.args[i]; i++) {
               if (i) trace_puts(",");
               trace_expr_obj(e->Iex.CCall.args[i]);
            }
            trace_puts("]");
            break;
         }
         case Iex_ITE:
            trace_puts(",");
            trace_args1(e->Iex.ITE.cond);
            trace_puts(",\"iftrue\":");
            trace_expr_obj(e->Iex.ITE.iftrue);
            trace_puts(",\"iffalse\":");
            trace_expr_obj(e->Iex.ITE.iffalse);
            break;
         default:
            break;
      }
   } else if (clone->tag == Ist_PutI) {
      trace_puts("\"data\":");
      trace_expr_obj(clone->Ist.PutI.details->data);
      trace_puts(",\"index\":");
      trace_expr_obj(clone->Ist.PutI.details->ix);
   } else if (clone->tag == Ist_Dirty) {
      IRDirty *d = clone->Ist.Dirty.details;
      Int i;
      trace_puts("\"args\":[");
      for (i = 0; d->args[i]; i++) {
         if (i) trace_puts(",");
         trace_expr_obj(d->args[i]);
      }
      trace_puts("]");
      if (d->tmp != IRTemp_INVALID) {
         trace_puts(",\"dst\":");
         tmp_def_seq[d->tmp] = trace_seq;
         trace_tmp_obj(d->tmp);
      }
   } else {
      trace_puts("\"note\":\"generic\"");
   }

   trace_stmt_end();
}

void TNT_(smt2_exit)(IRStmt *clone)
{
   IRExpr *guard = clone->Ist.Exit.guard;
   trace_stmt_start(clone, "Exit", 0, guard->tag == Iex_RdTmp && is_tainted(guard->Iex.RdTmp.tmp));
   trace_puts("\"guard\":");
   trace_expr_obj(guard);
   trace_stmt_end();
}

void TNT_(smt2_load)(IRStmt *clone, UWord value, UWord taint)
{
   UInt ltmp = clone->Ist.WrTmp.tmp;
   IRExpr *load = clone->Ist.WrTmp.data;
   UInt bits = SMT2_ty[load->Iex.Load.ty - Ity_INVALID];
   Addr addr = 0;
   tt[ltmp] = bits;

   trace_stmt_start(clone, "Load", value, taint);
   trace_puts("\"dst\":");
   tmp_def_seq[ltmp] = trace_seq;
   trace_tmp_obj(ltmp);
   trace_puts(",");
   trace_addr_obj(load->Iex.Load.addr);
   
   if (load->Iex.Load.addr->tag == Iex_RdTmp)
      addr = tv[load->Iex.Load.addr->Iex.RdTmp.tmp];
   else if (load->Iex.Load.addr->tag == Iex_Const)
      addr = const_value(load->Iex.Load.addr->Iex.Const.con);
   
   trace_load_bytes(addr, bits);
   trace_puts(",\"bits\":");
   trace_u(bits);
   trace_stmt_end();
}

void TNT_(smt2_store)(IRStmt *clone)
{
   trace_stmt_start(clone, "Store", 0, 0);
   trace_addr_obj(clone->Ist.Store.addr);
   trace_puts(",\"data\":");
   trace_expr_obj(clone->Ist.Store.data);
   trace_puts(",\"bits\":");
   trace_u(expr_bits(clone->Ist.Store.data));
   trace_stmt_end();
}

void TNT_(smt2_unop_t)(IRStmt *clone)
{
   UInt ltmp = clone->Ist.WrTmp.tmp;
   IRExpr *e = clone->Ist.WrTmp.data;
   UInt bits = op_result_bits(e->Iex.Unop.op);
   tt[ltmp] = bits;

   trace_stmt_start(clone, op_name(e->Iex.Unop.op), tv[ltmp], is_tainted(ltmp) ? V_BITS64_TAINTED : 0);
   trace_puts("\"dst\":");
   tmp_def_seq[ltmp] = trace_seq;
   trace_tmp_obj(ltmp);
   trace_puts(",\"irop_code\":");
   trace_u((UInt)e->Iex.Unop.op);
   trace_puts(",");
   trace_args1(e->Iex.Unop.arg);
   trace_stmt_end();
}

void TNT_(smt2_binop_tc)(IRStmt *clone)
{
   UInt ltmp = clone->Ist.WrTmp.tmp;
   IRExpr *e = clone->Ist.WrTmp.data;
   UInt bits = op_result_bits(e->Iex.Binop.op);
   tt[ltmp] = bits;

   trace_stmt_start(clone, op_name(e->Iex.Binop.op), tv[ltmp], is_tainted(ltmp) ? V_BITS64_TAINTED : 0);
   trace_puts("\"dst\":");
   tmp_def_seq[ltmp] = trace_seq;
   trace_tmp_obj(ltmp);
   trace_puts(",\"irop_code\":");
   trace_u((UInt)e->Iex.Binop.op);
   trace_puts(",");
   trace_args2(e->Iex.Binop.arg1, e->Iex.Binop.arg2);
   trace_stmt_end();
}

void TNT_(smt2_binop_ct)(IRStmt *clone)
{
   TNT_(smt2_binop_tc)(clone);
}

void TNT_(smt2_binop_tt)(IRStmt *clone)
{
   TNT_(smt2_binop_tc)(clone);
}

void TNT_(smt2_rdtmp)(IRStmt *clone)
{
   UInt ltmp = clone->Ist.WrTmp.tmp;
   IRExpr *e = clone->Ist.WrTmp.data;
   UInt rtmp = e->Iex.RdTmp.tmp;
   tt[ltmp] = tt[rtmp];

   trace_stmt_start(clone, "RdTmp", tv[ltmp], is_tainted(ltmp) ? V_BITS64_TAINTED : 0);
   trace_puts("\"dst\":");
   tmp_def_seq[ltmp] = trace_seq;
   trace_tmp_obj(ltmp);
   trace_puts(",");
   trace_args1(e);
   trace_stmt_end();
}

void TNT_(smt2_get)(IRStmt *clone)
{
   UInt ltmp = clone->Ist.WrTmp.tmp;
   IRExpr *e = clone->Ist.WrTmp.data;
   UInt bits = SMT2_ty[e->Iex.Get.ty - Ity_INVALID];
   UInt reg = e->Iex.Get.offset/(sizeof(UWord));
   tt[ltmp] = bits;

   trace_stmt_start(clone, "Get", tv[ltmp], is_tainted(ltmp) ? V_BITS64_TAINTED : 0);
   trace_puts("\"dst\":");
   tmp_def_seq[ltmp] = trace_seq;
   trace_tmp_obj(ltmp);
   trace_puts(",\"args\":[");
   trace_reg_obj(reg, bits, tv[ltmp], is_tainted(ltmp) ? V_BITS64_TAINTED : 0);
   trace_puts("]");
   trace_stmt_end();
}

void TNT_(smt2_put_t_32)(IRStmt *clone)
{
   UInt reg = clone->Ist.Put.offset/(sizeof(UWord));
   UInt bits = expr_bits(clone->Ist.Put.data);
   if (!bits) bits = 32;
   trace_stmt_start(clone, "Put", 0, 0);
   trace_puts("\"dst\":");
   reg_def_seq[reg] = trace_seq;
   trace_reg_obj(reg, bits, 0, 0);
   trace_puts(",");
   trace_args1(clone->Ist.Put.data);
   trace_stmt_end();
}

void TNT_(smt2_put_t_64)(IRStmt *clone)
{
   UInt reg = clone->Ist.Put.offset/(sizeof(UWord));
   UInt bits = expr_bits(clone->Ist.Put.data);
   if (!bits) bits = 64;
   trace_stmt_start(clone, "Put", 0, 0);
   trace_puts("\"dst\":");
   reg_def_seq[reg] = trace_seq;
   trace_reg_obj(reg, bits, 0, 0);
   trace_puts(",");
   trace_args1(clone->Ist.Put.data);
   trace_stmt_end();
}

void TNT_(smt2_x86g_calculate_condition)(IRStmt *clone)
{
   UInt ltmp = clone->Ist.WrTmp.tmp;
   IRExpr *e = clone->Ist.WrTmp.data;
   tt[ltmp] = SMT2_ty[e->Iex.CCall.retty - Ity_INVALID];
   trace_stmt_start(clone, "x86g_calculate_condition", tv[ltmp], is_tainted(ltmp) ? V_BITS64_TAINTED : 0);
   trace_puts("\"dst\":");
   tmp_def_seq[ltmp] = trace_seq;
   trace_tmp_obj(ltmp);
   trace_puts(",\"args\":[");
   
   for (Int i = 0; e->Iex.CCall.args[i]; i++) {
      if (i) trace_puts(",");
      trace_expr_obj(e->Iex.CCall.args[i]);
   }
   
   trace_puts("]");
   trace_stmt_end();
}

void TNT_(smt2_amd64g_calculate_condition)(IRStmt *clone)
{
   TNT_(smt2_x86g_calculate_condition)(clone);
}

void TNT_(smt2_ite_tt)(IRStmt *clone)
{
   UInt ltmp = clone->Ist.WrTmp.tmp;
   IRExpr *e = clone->Ist.WrTmp.data;
   tt[ltmp] = expr_bits(e->Iex.ITE.iftrue);

   trace_stmt_start(clone, "ITE", tv[ltmp], is_tainted(ltmp) ? V_BITS64_TAINTED : 0);
   trace_puts("\"dst\":");
   tmp_def_seq[ltmp] = trace_seq;
   trace_tmp_obj(ltmp);
   trace_puts(",");
   trace_args1(e->Iex.ITE.cond);
   trace_puts(",\"iftrue\":");
   trace_expr_obj(e->Iex.ITE.iftrue);
   trace_puts(",\"iffalse\":");
   trace_expr_obj(e->Iex.ITE.iffalse);
   trace_stmt_end();
}
