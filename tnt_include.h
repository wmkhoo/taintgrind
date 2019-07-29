
/*--------------------------------------------------------------------*/
/*--- A header file for all parts of Taintgrind.                   ---*/
/*---                                                tnt_include.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Taintgrind, a heavyweight Valgrind tool for
   taint analysis.

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

#ifndef __TNT_INCLUDE_H
#define __TNT_INCLUDE_H

#include "taintgrind.h"

#define STACK_TRACE_SIZE 20

#define TNT_(str)    VGAPPEND(vgTaintgrind_,str)

/*------------------------------------------------------------*/
/*--- Profiling of memory events                           ---*/
/*------------------------------------------------------------*/

/* Define to collect detailed performance info. */
/* #define TNT_PROFILE_MEMORY */

#ifdef TNT_PROFILE_MEMORY
#  define N_PROF_EVENTS 500

UInt   TNT_(event_ctr)[N_PROF_EVENTS];
HChar* TNT_(event_ctr_name)[N_PROF_EVENTS];

#  define PROF_EVENT(ev, name)                                \
   do { tl_assert((ev) >= 0 && (ev) < N_PROF_EVENTS);         \
        /* crude and inaccurate check to ensure the same */   \
        /* event isn't being used with > 1 name */            \
        if (TNT_(event_ctr_name)[ev])                         \
           tl_assert(name == TNT_(event_ctr_name)[ev]);       \
        TNT_(event_ctr)[ev]++;                                \
        TNT_(event_ctr_name)[ev] = (name);                    \
   } while (False);

#else

#  define PROF_EVENT(ev, name) /* */

#endif   /* TNT_PROFILE_MEMORY */


/*------------------------------------------------------------*/
/*--- V and A bits (Victoria & Albert ?)                   ---*/
/*------------------------------------------------------------*/

/* The number of entries in the primary map can be altered.  However
   we hardwire the assumption that each secondary map covers precisely
   64k of address space. */
#define SM_SIZE 65536            /* DO NOT CHANGE */
#define SM_MASK (SM_SIZE-1)      /* DO NOT CHANGE */

#define V_BIT_UNTAINTED         0
#define V_BIT_TAINTED       1

#define V_BITS8_UNTAINTED       0
#define V_BITS8_TAINTED     0xFF

#define V_BITS16_UNTAINTED      0
#define V_BITS16_TAINTED    0xFFFF

#define V_BITS32_UNTAINTED      0
#define V_BITS32_TAINTED    0xFFFFFFFF

#define V_BITS64_UNTAINTED      0ULL
#define V_BITS64_TAINTED    0xFFFFFFFFFFFFFFFFULL


/*------------------------------------------------------------*/
/*--- Instrumentation                                      ---*/
/*------------------------------------------------------------*/

// Debug variable
//int tnt_read;

/* Functions/vars defined in tnt_main.c */
UChar get_vabits2( Addr a ); // Taintgrind: needed by TNT_(instrument)
void TNT_(make_mem_noaccess)( Addr a, SizeT len );
void TNT_(make_mem_tainted)( Addr a, SizeT len );
void TNT_(make_mem_tainted_named)( Addr a, SizeT len, const HChar *varname );
void TNT_(make_mem_untainted)( Addr a, SizeT len );
void TNT_(copy_address_range_state) ( Addr src, Addr dst, SizeT len );

// Emits instructions
VG_REGPARM(1) void TNT_(emit_insn)  ( IRStmt *, UWord, UWord, UWord );
VG_REGPARM(1) void TNT_(emit_insn1) ( IRStmt *, UWord, UWord );
VG_REGPARM(3) void TNT_(emit_next)  ( IRExpr *, UWord, UWord );

/* Functions defined in tnt_translate, used by tnt_main */
extern Int extract_IRConst( IRConst* con );
extern ULong extract_IRConst64( IRConst* con );

/* V-bits load/store helpers */
VG_REGPARM(1) void TNT_(helperc_STOREV64be) ( Addr, ULong );
VG_REGPARM(1) void TNT_(helperc_STOREV64le) ( Addr, ULong );
VG_REGPARM(2) void TNT_(helperc_STOREV32be) ( Addr, UWord );
VG_REGPARM(2) void TNT_(helperc_STOREV32le) ( Addr, UWord );
VG_REGPARM(2) void TNT_(helperc_STOREV16be) ( Addr, UWord );
VG_REGPARM(2) void TNT_(helperc_STOREV16le) ( Addr, UWord );
VG_REGPARM(2) void TNT_(helperc_STOREV8)    ( Addr, UWord );

VG_REGPARM(2) void  TNT_(helperc_LOADV256be) ( /*OUT*/V256*, Addr );
VG_REGPARM(2) void  TNT_(helperc_LOADV256le) ( /*OUT*/V256*, Addr );
VG_REGPARM(2) void  TNT_(helperc_LOADV128be) ( /*OUT*/V128*, Addr );
VG_REGPARM(2) void  TNT_(helperc_LOADV128le) ( /*OUT*/V128*, Addr );
VG_REGPARM(1) ULong TNT_(helperc_LOADV64be)  ( Addr );
VG_REGPARM(1) ULong TNT_(helperc_LOADV64le)  ( Addr );
VG_REGPARM(1) UWord TNT_(helperc_LOADV32be)  ( Addr );
VG_REGPARM(1) UWord TNT_(helperc_LOADV32le)  ( Addr );
VG_REGPARM(1) UWord TNT_(helperc_LOADV16be)  ( Addr );
VG_REGPARM(1) UWord TNT_(helperc_LOADV16le)  ( Addr );
VG_REGPARM(1) UWord TNT_(helperc_LOADV8)     ( Addr );

void TNT_(helperc_MAKE_STACK_UNINIT) ( Addr base, UWord len,
                                                 Addr nia );

/* Taintgrind args */
#define MAX_PATH 256
extern HChar  TNT_(clo_file_filter)[MAX_PATH];
extern Int    TNT_(clo_taint_start);
extern Int    TNT_(clo_taint_len);
extern Bool   TNT_(clo_taint_all);
extern Int    TNT_(clo_after_kbb);
extern Int    TNT_(clo_before_kbb);
extern Bool   TNT_(clo_tainted_ins_only);
extern Bool   TNT_(clo_critical_ins_only);
extern Bool   TNT_(clo_compact);
extern Bool   TNT_(clo_taint_network);
extern Bool   TNT_(clo_taint_stdin);
extern Int    TNT_(do_print);
extern Bool   TNT_(clo_smt2);
//extern Char* TNT_(clo_allowed_syscalls);
//extern Bool  TNT_(read_syscalls_file);

/* Functions defined in malloc_wrappers.c */
#define TNT_MALLOC_REDZONE_SZB    16

/* Shadow memory functions */
Bool TNT_(check_mem_is_noaccess)( Addr a, SizeT len, Addr* bad_addr );
void TNT_(make_mem_noaccess)        ( Addr a, SizeT len );
void TNT_(make_mem_undefined_w_otag)( Addr a, SizeT len, UInt otag );
void TNT_(make_mem_defined)         ( Addr a, SizeT len );
void TNT_(copy_address_range_state) ( Addr src, Addr dst, SizeT len );


/* Functions defined in tnt_syswrap.c */
extern void TNT_(setup_tainted_map)( void );
/* System call wrappers */
extern void TNT_(syscall_read)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_write)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_open)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_close)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_lseek)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_llseek)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_pread)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern Bool TNT_(syscall_allowed_check)(ThreadId tid, int syscallno);
extern void TNT_(syscall_socketcall)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_socket)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_connect)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_socketpair)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_accept)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_recv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_recvfrom)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_recvmsg)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);

/* Functions defined in tnt_translate.c */
IRSB* TNT_(instrument)( VgCallbackClosure* closure,
                        IRSB* bb_in,
                        const VexGuestLayout* layout,
                        const VexGuestExtents* vge,
                        const VexArchInfo* vai,
                        IRType gWordTy, IRType hWordTy );


/* Client request handler */
extern Bool TNT_(handle_client_requests) ( ThreadId tid, UWord* arg, UWord* ret );

/* SOAAP-related data */
extern HChar* client_binary_name;
#define FNNAME_MAX 100

extern UInt persistent_sandbox_nesting_depth;
extern UInt ephemeral_sandbox_nesting_depth;
extern Bool have_created_sandbox;

#define FD_MAX 256
#define FD_MAX_PATH 256
#define FD_READ 0x1
#define FD_WRITE 0x2
#define FD_STAT 0x4

extern UInt shared_fds[];

#define VAR_MAX 100
#define VAR_READ 0x1
#define VAR_WRITE 0x2

enum VariableType { Local = 3, Global = 4 };
enum VariableLocation { GlobalFromApplication = 5, GlobalFromElsewhere = 6 };

extern struct myStringArray shared_vars;
extern UInt shared_vars_perms[];
extern HChar* next_shared_variable_to_update;

#define IN_SANDBOX (persistent_sandbox_nesting_depth > 0 || ephemeral_sandbox_nesting_depth > 0)

#define FD_SET_PERMISSION(fd,perm) shared_fds[fd] |= perm
#define VAR_SET_PERMISSION(var_idx,perm) shared_vars_perms[var_idx] |= perm

#define SYSCALLS_MAX 500
extern Bool allowed_syscalls[];
#define IS_SYSCALL_ALLOWED(no) (allowed_syscalls[no] == True)

extern UInt callgate_nesting_depth;
#define IN_CALLGATE (nested_callgate_depth > 0)

/* System call array */
extern const char* syscallnames[];

extern int istty;

/* Utility functions */
extern Int TNT_(describe_data)(Addr addr, HChar* varnamebuf, UInt bufsize);
extern void TNT_(get_fnname)(ThreadId tid, const HChar** buf);
extern void TNT_(check_fd_access)(ThreadId tid, UInt fd, Int fd_request);
extern void TNT_(check_var_access)(ThreadId tid, const HChar* varname, Int var_request, enum VariableType type, enum VariableLocation var_loc);

/* Arrays for keeping track of register/tmp SSA indices, values */
#define TI_MAX 8192 
#define RI_MAX 8192 
#define VARNAMESIZE 1024 
// These arrays are initialised to 0 in TNT_(clo_post_init)
// Tmp variable indices; the MSB indicates whether it's tainted (1) or not (0)
UInt  *ti;
// Tmp variable values
ULong *tv;
// Reg variable indices; values are obtained in real-time
UInt  *ri;
// Tmp variable Types/Widths
UInt  *tt;
// Stores the variable name derived from describe_data()
HChar *varname;

#define _ti(ltmp) ti[ltmp] & 0x7fffffff
#define is_tainted(ltmp) (ti[ltmp] >> 31)

/* SMT2 functions */
extern void TNT_(smt2_preamble) (void);
extern void TNT_(smt2_exit)     ( IRStmt * );
extern void TNT_(smt2_load)     ( IRStmt *, UWord, UWord );
extern void TNT_(smt2_store)    ( IRStmt * );
extern void TNT_(smt2_unop_t)   ( IRStmt * );
extern void TNT_(smt2_binop_tc) ( IRStmt * );
extern void TNT_(smt2_binop_ct) ( IRStmt * );
extern void TNT_(smt2_binop_tt) ( IRStmt * );
extern void TNT_(smt2_rdtmp)    ( IRStmt * );
extern void TNT_(smt2_get)      ( IRStmt * );
extern void TNT_(smt2_put_t_32) ( IRStmt * );
extern void TNT_(smt2_put_t_64) ( IRStmt * );
extern void TNT_(smt2_x86g_calculate_condition)    ( IRStmt * );
extern void TNT_(smt2_amd64g_calculate_condition)  ( IRStmt * );
extern void TNT_(smt2_ite_tt)   ( IRStmt * );

#endif /* ndef __TNT_INCLUDE_H */

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
