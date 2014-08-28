/*--------------------------------------------------------------------------------*/
/*-------------------------------- AVALANCHE -------------------------------------*/
/*--- Tracegring. Transforms IR tainted trace to STP declarations.      copy.h ---*/
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

#ifndef __COPY_H
#define __COPY_H

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_xarray.h"
#include "pub_tool_clientstate.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_vki.h"

IRConst* mallocIRConst_U1(Bool bit);
IRConst* mallocIRConst_U8(UChar u8);
IRConst* mallocIRConst_U16(UShort u16);
IRConst* mallocIRConst_U32(UInt u32);
IRConst* mallocIRConst_U64(ULong u64);
IRConst* mallocIRConst_F64(Double f64);
IRConst* mallocIRConst_F64i(ULong f64i);
IRConst* mallocIRConst_V128(UShort con);

IRCallee* mallocIRCallee(Int regparms, const HChar* name, void* addr);

IRRegArray* mallocIRRegArray(Int base, IRType elemTy, Int nElems);

IRExpr* mallocIRExpr_Binder(Int binder);
IRExpr* mallocIRExpr_Get(Int off, IRType ty);
IRExpr* mallocIRExpr_GetI(IRRegArray* descr, IRExpr* ix, Int bias);
IRExpr* mallocIRExpr_RdTmp(IRTemp tmp);
IRExpr* mallocIRExpr_Qop(IROp op, IRExpr* arg1, IRExpr* arg2, IRExpr* arg3, IRExpr* arg4);
IRExpr* mallocIRExpr_Triop(IROp op, IRExpr* arg1, IRExpr* arg2, IRExpr* arg3);
IRExpr* mallocIRExpr_Binop(IROp op, IRExpr* arg1, IRExpr* arg2);
IRExpr* mallocIRExpr_Unop(IROp op, IRExpr* arg);
IRExpr* mallocIRExpr_Load(IREndness end, IRType ty, IRExpr* addr);
IRExpr* mallocIRExpr_Const(IRConst* con);
IRExpr* mallocIRExpr_CCall(IRCallee* cee, IRType retty, IRExpr** args);
IRExpr* mallocIRExpr_ITE(IRExpr* cond, IRExpr* iftrue, IRExpr* iffalse);

IRDirty* mallocEmptyIRDirty(void);



IRStmt* mallocIRStmt_NoOp(void);
IRStmt* mallocIRStmt_IMark(Addr64 addr, Int len);
IRStmt* mallocIRStmt_AbiHint(IRExpr* base, Int len, IRExpr* nia);
IRStmt* mallocIRStmt_Put(Int off, IRExpr* data);
IRStmt* mallocIRStmt_PutI(IRRegArray* descr, IRExpr* ix, Int bias, IRExpr* data);
IRStmt* mallocIRStmt_WrTmp(IRTemp tmp, IRExpr* data);
IRStmt* mallocIRStmt_Store(IREndness end, IRExpr* addr, IRExpr* data);
IRStmt* mallocIRStmt_Dirty(IRDirty* d);
IRStmt* mallocIRStmt_MBE(IRMBusEvent event);
IRStmt* mallocIRStmt_Exit(IRExpr* guard, IRJumpKind jk, IRConst* dst);

IRExpr** shallowMallocIRExprVec(IRExpr** vec);

IRExpr** deepMallocIRExprVec(IRExpr** vec);

IRConst* deepMallocIRConst(IRConst* c);

IRCallee* deepMallocIRCallee(IRCallee* ce);

IRRegArray* deepMallocIRRegArray(IRRegArray* d);

IRExpr* deepMallocIRExpr(IRExpr* e);

IRDirty* deepMallocIRDirty(IRDirty* d);

IRStmt* deepMallocIRStmt(IRStmt* s);

#endif

