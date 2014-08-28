/*--------------------------------------------------------------------------------*/
/*-------------------------------- AVALANCHE -------------------------------------*/
/*--- Tracegring. Transforms IR tainted trace to STP declarations.      copy.c ---*/
/*--------------------------------------------------------------------------------*/

/*
   This file is part of Tracegrind, the Valgrind tool,
   which tracks tainted data coming from the specified file
   and converts IR trace to STP declarations.

   Copyright (C) 2009 Ildar Isaev
      iisaev@ispras.ru

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

#include "copy.h"
#include "pub_tool_mallocfree.h"

IRConst* mallocIRConst_U1(Bool bit)
{
   IRConst* c = VG_(malloc)("IRConst", sizeof(IRConst));
   c->tag     = Ico_U1;
   c->Ico.U1  = bit;
   return c;
}
IRConst* mallocIRConst_U8(UChar u8)
{
   IRConst* c = VG_(malloc)("IRConst", sizeof(IRConst));
   c->tag     = Ico_U8;
   c->Ico.U8  = u8;
   return c;
}
IRConst* mallocIRConst_U16(UShort u16)
{
   IRConst* c = VG_(malloc)("IRConst", sizeof(IRConst));
   c->tag     = Ico_U16;
   c->Ico.U16 = u16;
   return c;
}
IRConst* mallocIRConst_U32(UInt u32)
{
   IRConst* c = VG_(malloc)("IRConst", sizeof(IRConst));
   c->tag     = Ico_U32;
   c->Ico.U32 = u32;
   return c;
}
IRConst* mallocIRConst_U64(ULong u64)
{
   IRConst* c = VG_(malloc)("IRConst", sizeof(IRConst));
   c->tag     = Ico_U64;
   c->Ico.U64 = u64;
   return c;
}
IRConst* mallocIRConst_F64(Double f64)
{
   IRConst* c = VG_(malloc)("IRConst", sizeof(IRConst));
   c->tag     = Ico_F64;
   c->Ico.F64 = f64;
   return c;
}
IRConst* mallocIRConst_F64i(ULong f64i)
{
   IRConst* c  = VG_(malloc)("IRConst", sizeof(IRConst));
   c->tag      = Ico_F64i;
   c->Ico.F64i = f64i;
   return c;
}
IRConst* mallocIRConst_V128(UShort con)
{
   IRConst* c  = VG_(malloc)("IRConst", sizeof(IRConst));
   c->tag      = Ico_V128;
   c->Ico.V128 = con;
   return c;
}



IRCallee* mallocIRCallee(Int regparms, const HChar* name, void* addr)
{
   IRCallee* ce = VG_(malloc)("IRCallee", sizeof(IRCallee));
   ce->regparms = regparms;
   ce->name     = name;
   ce->addr     = addr;
   ce->mcx_mask = 0;
   return ce;
}

IRRegArray* mallocIRRegArray(Int base, IRType elemTy, Int nElems)
{
   IRRegArray* arr = VG_(malloc)("IRRegArray", sizeof(IRRegArray));
   arr->base       = base;
   arr->elemTy     = elemTy;
   arr->nElems     = nElems;
   return arr;
}

IRExpr* mallocIRExpr_Binder(Int binder) {
   IRExpr* e            = VG_(malloc)("IRExpr", sizeof(IRExpr));
   e->tag               = Iex_Binder;
   e->Iex.Binder.binder = binder;
   return e;
}
IRExpr* mallocIRExpr_Get(Int off, IRType ty) {
   IRExpr* e         = VG_(malloc)("IRExpr", sizeof(IRExpr));
   e->tag            = Iex_Get;
   e->Iex.Get.offset = off;
   e->Iex.Get.ty     = ty;
   return e;
}
IRExpr* mallocIRExpr_GetI(IRRegArray* descr, IRExpr* ix, Int bias) {
   IRExpr* e         = VG_(malloc)("IRExpr", sizeof(IRExpr));
   e->tag            = Iex_GetI;
   e->Iex.GetI.descr = descr;
   e->Iex.GetI.ix    = ix;
   e->Iex.GetI.bias  = bias;
   return e;
}
IRExpr* mallocIRExpr_RdTmp(IRTemp tmp) {
   IRExpr* e        = VG_(malloc)("IRExpr", sizeof(IRExpr));
   e->tag           = Iex_RdTmp;
   e->Iex.RdTmp.tmp = tmp;
   return e;
}
IRExpr* mallocIRExpr_Qop(IROp op, IRExpr* arg1, IRExpr* arg2, 
                              IRExpr* arg3, IRExpr* arg4) {
   IRExpr* e       = VG_(malloc)("IRExpr", sizeof(IRExpr));
   e->tag          = Iex_Qop;
   IRQop *details  = VG_(malloc)("IRQop", sizeof(IRQop));
   e->Iex.Qop.details       = details;
   e->Iex.Qop.details->op   = op;
   e->Iex.Qop.details->arg1 = arg1;
   e->Iex.Qop.details->arg2 = arg2;
   e->Iex.Qop.details->arg3 = arg3;
   e->Iex.Qop.details->arg4 = arg4;
   return e;
}
IRExpr* mallocIRExpr_Triop (IROp op, IRExpr* arg1, 
                                 IRExpr* arg2, IRExpr* arg3) {
   IRExpr* e         = VG_(malloc)("IRExpr", sizeof(IRExpr));
   e->tag            = Iex_Triop;
   IRTriop *details  = VG_(malloc)("IRTriop", sizeof(IRTriop));
   e->Iex.Triop.details       = details;
   e->Iex.Triop.details->op   = op;
   e->Iex.Triop.details->arg1 = arg1;
   e->Iex.Triop.details->arg2 = arg2;
   e->Iex.Triop.details->arg3 = arg3;
   return e;
}
IRExpr* mallocIRExpr_Binop(IROp op, IRExpr* arg1, IRExpr* arg2) {
   IRExpr* e         = VG_(malloc)("IRExpr", sizeof(IRExpr));
   e->tag            = Iex_Binop;
   e->Iex.Binop.op   = op;
   e->Iex.Binop.arg1 = arg1;
   e->Iex.Binop.arg2 = arg2;
   return e;
}
IRExpr* mallocIRExpr_Unop(IROp op, IRExpr* arg) {
   IRExpr* e       = VG_(malloc)("IRExpr", sizeof(IRExpr));
   e->tag          = Iex_Unop;
   e->Iex.Unop.op  = op;
   e->Iex.Unop.arg = arg;
   return e;
}
IRExpr* mallocIRExpr_Load(IREndness end, IRType ty, IRExpr* addr) {
   IRExpr* e        = VG_(malloc)("IRExpr", sizeof(IRExpr));
   e->tag           = Iex_Load;
   e->Iex.Load.end  = end;
   e->Iex.Load.ty   = ty;
   e->Iex.Load.addr = addr;
   return e;
}
IRExpr* mallocIRExpr_Const(IRConst* con) {
   IRExpr* e        = VG_(malloc)("IRExpr", sizeof(IRExpr));
   e->tag           = Iex_Const;
   e->Iex.Const.con = con;
   return e;
}
IRExpr* mallocIRExpr_CCall(IRCallee* cee, IRType retty, IRExpr** args) {
   IRExpr* e          = VG_(malloc)("IRExpr", sizeof(IRExpr));
   e->tag             = Iex_CCall;
   e->Iex.CCall.cee   = cee;
   e->Iex.CCall.retty = retty;
   e->Iex.CCall.args  = args;
   return e;
}
IRExpr* mallocIRExpr_ITE(IRExpr* cond, IRExpr* iftrue, IRExpr* iffalse) {
   IRExpr* e          = VG_(malloc)("IRExpr", sizeof(IRExpr));
   e->tag             = Iex_ITE;
   e->Iex.ITE.cond  = cond;
   e->Iex.ITE.iftrue = iftrue;
   e->Iex.ITE.iffalse = iffalse;
   return e;
}

IRDirty* mallocEmptyIRDirty(void) {
   IRDirty* d = VG_(malloc)("IRExpr", sizeof(IRDirty));
   d->cee      = NULL;
   d->guard    = NULL;
   d->args     = NULL;
   d->tmp      = IRTemp_INVALID;
   d->mFx      = Ifx_None;
   d->mAddr    = NULL;
   d->mSize    = 0;
   d->nFxState = 0;
   return d;
}



IRStmt* mallocIRStmt_NoOp(void)
{
   /* Just use a single static closure. */
   static IRStmt static_closure;
   static_closure.tag = Ist_NoOp;
   return &static_closure;
}
IRStmt* mallocIRStmt_IMark(Addr64 addr, Int len) {
   IRStmt* s         = VG_(malloc)("IRStmt", sizeof(IRStmt));
   s->tag            = Ist_IMark;
   s->Ist.IMark.addr = addr;
   s->Ist.IMark.len  = len;
   return s;
}
IRStmt* mallocIRStmt_AbiHint(IRExpr* base, Int len, IRExpr* nia) {
   IRStmt* s           = VG_(malloc)("IRStmt", sizeof(IRStmt));
   s->tag              = Ist_AbiHint;
   s->Ist.AbiHint.base = base;
   s->Ist.AbiHint.len  = len;
   s->Ist.AbiHint.nia  = nia;
   return s;
}
IRStmt* mallocIRStmt_Put(Int off, IRExpr* data) {
   IRStmt* s         = VG_(malloc)("IRStmt", sizeof(IRStmt));
   s->tag            = Ist_Put;
   s->Ist.Put.offset = off;
   s->Ist.Put.data   = data;
   return s;
}
IRStmt* mallocIRStmt_PutI(IRRegArray* descr, IRExpr* ix,
                      Int bias, IRExpr* data) {
   IRStmt* s         = VG_(malloc)("IRStmt", sizeof(IRStmt));
   s->tag            = Ist_PutI;
   IRPutI *details   = VG_(malloc)("IRPutI", sizeof(IRPutI));
   s->Ist.PutI.details        = details;
   s->Ist.PutI.details->descr = descr;
   s->Ist.PutI.details->ix    = ix;
   s->Ist.PutI.details->bias  = bias;
   s->Ist.PutI.details->data  = data;
   return s;
}
IRStmt* mallocIRStmt_WrTmp(IRTemp tmp, IRExpr* data) {
   IRStmt* s         = VG_(malloc)("IRStmt", sizeof(IRStmt));
   s->tag            = Ist_WrTmp;
   s->Ist.WrTmp.tmp  = tmp;
   s->Ist.WrTmp.data = data;
   return s;
}
IRStmt* mallocIRStmt_Store(IREndness end, IRExpr* addr, IRExpr* data) {
   IRStmt* s         = VG_(malloc)("IRStmt", sizeof(IRStmt));
   s->tag            = Ist_Store;
   s->Ist.Store.end  = end;
   s->Ist.Store.addr = addr;
   s->Ist.Store.data = data;
   return s;
}
IRStmt* mallocIRStmt_Dirty(IRDirty* d)
{
   IRStmt* s            = VG_(malloc)("IRStmt", sizeof(IRStmt));
   s->tag               = Ist_Dirty;
   s->Ist.Dirty.details = d;
   return s;
}
IRStmt* mallocIRStmt_MBE(IRMBusEvent event)
{
   IRStmt* s        = VG_(malloc)("IRStmt", sizeof(IRStmt));
   s->tag           = Ist_MBE;
   s->Ist.MBE.event = event;
   return s;
}
IRStmt* mallocIRStmt_Exit(IRExpr* guard, IRJumpKind jk, IRConst* dst) {
   IRStmt* s         = VG_(malloc)("IRStmt", sizeof(IRStmt));
   s->tag            = Ist_Exit;
   s->Ist.Exit.guard = guard;
   s->Ist.Exit.jk    = jk;
   s->Ist.Exit.dst   = dst;
   return s;
}

IRExpr** shallowMallocIRExprVec(IRExpr** vec)
{
   Int      i;
   IRExpr** newvec;
   for (i = 0; vec[i]; i++)
      ;
   newvec = VG_(malloc)("IRExprVec", (i+1)*sizeof(IRExpr*));
   for (i = 0; vec[i]; i++)
      newvec[i] = vec[i];
   newvec[i] = NULL;
   return newvec;
}

IRExpr** deepMallocIRExprVec(IRExpr** vec)
{
   Int      i;
   IRExpr** newvec = shallowMallocIRExprVec( vec);
   for (i = 0; newvec[i]; i++)
      newvec[i] = deepMallocIRExpr(newvec[i]);
   return newvec;
}

IRConst* deepMallocIRConst(IRConst* c)
{
   switch (c->tag) {
      case Ico_U1:   return mallocIRConst_U1(c->Ico.U1);
      case Ico_U8:   return mallocIRConst_U8(c->Ico.U8);
      case Ico_U16:  return mallocIRConst_U16(c->Ico.U16);
      case Ico_U32:  return mallocIRConst_U32(c->Ico.U32);
      case Ico_U64:  return mallocIRConst_U64(c->Ico.U64);
      case Ico_F64:  return mallocIRConst_F64(c->Ico.F64);
      case Ico_F64i: return mallocIRConst_F64i(c->Ico.F64i);
      case Ico_V128: return mallocIRConst_V128(c->Ico.V128);
      default: return NULL;
   }
}

IRCallee* deepMallocIRCallee(IRCallee* ce)
{
   IRCallee* ce2 = mallocIRCallee(ce->regparms, ce->name, ce->addr);
   ce2->mcx_mask = ce->mcx_mask;
   return ce2;
}

IRRegArray* deepMallocIRRegArray(IRRegArray* d)
{
   return mallocIRRegArray(d->base, d->elemTy, d->nElems);
}

IRExpr* deepMallocIRExpr(IRExpr* e)
{
   switch (e->tag) {
      case Iex_Get: 
         return mallocIRExpr_Get(e->Iex.Get.offset, e->Iex.Get.ty);
      case Iex_GetI: 
         return mallocIRExpr_GetI(deepMallocIRRegArray(e->Iex.GetI.descr), 
                            deepMallocIRExpr(e->Iex.GetI.ix),
                            e->Iex.GetI.bias);
      case Iex_RdTmp: 
         return mallocIRExpr_RdTmp(e->Iex.RdTmp.tmp);
      case Iex_Qop: 
         return mallocIRExpr_Qop(e->Iex.Qop.details->op,
                           deepMallocIRExpr(e->Iex.Qop.details->arg1),
                           deepMallocIRExpr(e->Iex.Qop.details->arg2),
                           deepMallocIRExpr(e->Iex.Qop.details->arg3),
                           deepMallocIRExpr(e->Iex.Qop.details->arg4));
      case Iex_Triop: 
         return mallocIRExpr_Triop(e->Iex.Triop.details->op,
                             deepMallocIRExpr(e->Iex.Triop.details->arg1),
                             deepMallocIRExpr(e->Iex.Triop.details->arg2),
                             deepMallocIRExpr(e->Iex.Triop.details->arg3));
      case Iex_Binop: 
         return mallocIRExpr_Binop(e->Iex.Binop.op,
                             deepMallocIRExpr(e->Iex.Binop.arg1),
                             deepMallocIRExpr(e->Iex.Binop.arg2));
      case Iex_Unop: 
         return mallocIRExpr_Unop(e->Iex.Unop.op,
                            deepMallocIRExpr(e->Iex.Unop.arg));
      case Iex_Load: 
         return mallocIRExpr_Load(e->Iex.Load.end,
                            e->Iex.Load.ty,
                            deepMallocIRExpr(e->Iex.Load.addr));
      case Iex_Const: 
         return mallocIRExpr_Const(deepMallocIRConst(e->Iex.Const.con));
      case Iex_CCall:
         return mallocIRExpr_CCall(deepMallocIRCallee(e->Iex.CCall.cee),
                             e->Iex.CCall.retty,
                             deepMallocIRExprVec(e->Iex.CCall.args));

      case Iex_ITE: 
         return mallocIRExpr_ITE(deepMallocIRExpr(e->Iex.ITE.cond),
                             deepMallocIRExpr(e->Iex.ITE.iftrue),
                             deepMallocIRExpr(e->Iex.ITE.iffalse));
      default:
         return NULL;
   }
}

IRDirty* deepMallocIRDirty(IRDirty* d)
{
   Int      i;
   IRDirty* d2 = mallocEmptyIRDirty();
   d2->cee   = deepMallocIRCallee(d->cee);
   d2->guard = deepMallocIRExpr(d->guard);
   d2->args  = deepMallocIRExprVec(d->args);
   d2->tmp   = d->tmp;
   d2->mFx   = d->mFx;
   d2->mAddr = d->mAddr==NULL ? NULL : deepMallocIRExpr(d->mAddr);
   d2->mSize = d->mSize;
   d2->nFxState = d->nFxState;
   for (i = 0; i < d2->nFxState; i++)
      d2->fxState[i] = d->fxState[i];
   return d2;
}

IRStmt* deepMallocIRStmt(IRStmt* s)
{
   switch (s->tag) {
      case Ist_NoOp:
         return mallocIRStmt_NoOp();
      case Ist_AbiHint:
         return mallocIRStmt_AbiHint(deepMallocIRExpr(s->Ist.AbiHint.base),
                               s->Ist.AbiHint.len,
                               deepMallocIRExpr(s->Ist.AbiHint.nia));
      case Ist_IMark:
         return mallocIRStmt_IMark(s->Ist.IMark.addr, s->Ist.IMark.len);
      case Ist_Put: 
         return mallocIRStmt_Put(s->Ist.Put.offset, 
                           deepMallocIRExpr(s->Ist.Put.data));
      case Ist_PutI: 
         return mallocIRStmt_PutI(deepMallocIRRegArray(s->Ist.PutI.details->descr),
                            deepMallocIRExpr(s->Ist.PutI.details->ix),
                            s->Ist.PutI.details->bias, 
                            deepMallocIRExpr(s->Ist.PutI.details->data));
      case Ist_WrTmp:
         return mallocIRStmt_WrTmp(s->Ist.WrTmp.tmp,
                             deepMallocIRExpr(s->Ist.WrTmp.data));
      case Ist_Store: 
         return mallocIRStmt_Store(s->Ist.Store.end,
                             deepMallocIRExpr(s->Ist.Store.addr),
                             deepMallocIRExpr(s->Ist.Store.data));
      case Ist_Dirty: 
         return mallocIRStmt_Dirty(deepMallocIRDirty(s->Ist.Dirty.details));
      case Ist_MBE:
         return mallocIRStmt_MBE(s->Ist.MBE.event);
      case Ist_Exit: 
         return mallocIRStmt_Exit(deepMallocIRExpr(s->Ist.Exit.guard),
                            s->Ist.Exit.jk,
                            deepMallocIRConst(s->Ist.Exit.dst));
      default: 
         return NULL;
   }
}

