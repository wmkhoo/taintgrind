
/*--------------------------------------------------------------------*/
/*--- A header file for all parts of Taintgrind.                   ---*/
/*---                                                tnt_include.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Taintgrind, a heavyweight Valgrind tool for
   taint analysis.

   Copyright (C) 2010 Wei Ming Khoo 

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
void TNT_(make_mem_defined)( Addr a, SizeT len );
void TNT_(copy_address_range_state) ( Addr src, Addr dst, SizeT len );

VG_REGPARM(3) void TNT_(h32_exit) ( UInt, UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_next) ( UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(h64_next) ( ULong, ULong, ULong );
VG_REGPARM(3) void TNT_(h32_store_tt) ( UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_store_tc) ( UInt, UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_load_t) ( UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_load_c) ( UInt, UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_get) ( UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_put) ( UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_unop) ( UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_binop_tc) ( UInt, UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_binop_ct) ( UInt, UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_binop_tt) ( UInt, UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(h32_rdtmp) ( UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(helperc_0_tainted_enc32) ( UInt, UInt, UInt, UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(helperc_0_tainted_enc64) ( ULong, ULong, ULong, ULong );
VG_REGPARM(3) void TNT_(helperc_1_tainted_enc32) ( UInt, UInt, UInt, UInt, UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(helperc_1_tainted_enc64) ( ULong, ULong, ULong, ULong, ULong, ULong );
VG_REGPARM(3) void TNT_(helperc_0_tainted) ( HChar *, UInt, UInt );
VG_REGPARM(3) void TNT_(helperc_1_tainted) ( HChar *, UInt, UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(helperc_2_tainted) ( HChar *, UInt, UInt, UInt, UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(helperc_3_tainted) ( HChar *, UInt, UInt, UInt, UInt, UInt );
VG_REGPARM(3) void TNT_(helperc_4_tainted) ( HChar *, UInt, UInt, UInt, UInt, UInt, UInt );

/* Strings used by tnt_translate, printed by tnt_main */
extern const char *IRType_string[];
extern const char *IREndness_string[];
extern const char *IRConst_string[];
extern const char *IROp_string[];
extern const char *IRExpr_string[];
extern const char *IRStmt_string[];
extern const char *IRJumpKind_string[];

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
extern Int    TNT_(do_print);
//extern Char* TNT_(clo_allowed_syscalls);
//extern Bool  TNT_(read_syscalls_file);

/* Functions defined in malloc_wrappers.c */
#define TNT_MALLOC_REDZONE_SZB    16

#if 0
/* For malloc()/new/new[] vs. free()/delete/delete[] mismatch checking. */
typedef
   enum {
      TNT_AllocMalloc = 0,
      TNT_AllocNew    = 1,
      TNT_AllocNewVec = 2,
      TNT_AllocCustom = 3
   }
   TNT_AllocKind;
#endif

/* This describes a heap block. Nb: first two fields must match core's
 * VgHashNode. */
typedef
   struct _HP_Chunk {
      struct _HP_Chunk* next;
      Addr         data;            // Address of the actual block.
      SizeT        req_szB;         // Size requested
      SizeT        slop_szB;        // Extra bytes given above those requested
   }
   HP_Chunk;
#if 0
/* Memory pool.  Nb: first two fields must match core's VgHashNode. */
typedef
   struct _TNT_Mempool {
      struct _TNT_Mempool* next;
      Addr          pool;           // pool identifier
      SizeT         rzB;            // pool red-zone size
      Bool          is_zeroed;      // allocations from this pool are zeroed
      VgHashTable   chunks;         // chunks associated with this pool
   }
   TNT_Mempool;


void* TNT_(new_block)  ( ThreadId tid,
                        Addr p, SizeT size, SizeT align,
                        Bool is_zeroed, TNT_AllocKind kind,
                        VgHashTable table);
void TNT_(handle_free) ( ThreadId tid,
                        Addr p, UInt rzB, TNT_AllocKind kind );

void TNT_(create_mempool)  ( Addr pool, UInt rzB, Bool is_zeroed );
void TNT_(destroy_mempool) ( Addr pool );
void TNT_(mempool_alloc)   ( ThreadId tid, Addr pool,
                            Addr addr, SizeT size );
void TNT_(mempool_free)    ( Addr pool, Addr addr );
void TNT_(mempool_trim)    ( Addr pool, Addr addr, SizeT size );
void TNT_(move_mempool)    ( Addr poolA, Addr poolB );
void TNT_(mempool_change)  ( Addr pool, Addr addrA, Addr addrB, SizeT size );
Bool TNT_(mempool_exists)  ( Addr pool );

TNT_Chunk* TNT_(get_freed_list_head)( void );
#endif

/* For tracking malloc'd blocks.  Nb: it's quite important that it's a
   VgHashTable, because VgHashTable allows duplicate keys without complaint.
   This can occur if a user marks a malloc() block as also a custom block with
   MALLOCLIKE_BLOCK. */
extern VgHashTable TNT_(malloc_list);

/* For tracking memory pools. */
//extern VgHashTable TNT_(mempool_list);

/* Shadow memory functions */
Bool TNT_(check_mem_is_noaccess)( Addr a, SizeT len, Addr* bad_addr );
void TNT_(make_mem_noaccess)        ( Addr a, SizeT len );
void TNT_(make_mem_undefined_w_otag)( Addr a, SizeT len, UInt otag );
void TNT_(make_mem_defined)         ( Addr a, SizeT len );
void TNT_(copy_address_range_state) ( Addr src, Addr dst, SizeT len );

void TNT_(print_malloc_stats) ( void );

void* TNT_(malloc)               ( ThreadId tid, SizeT n );
void* TNT_(__builtin_new)        ( ThreadId tid, SizeT n );
void* TNT_(__builtin_vec_new)    ( ThreadId tid, SizeT n );
void* TNT_(memalign)             ( ThreadId tid, SizeT align, SizeT n );
void* TNT_(calloc)               ( ThreadId tid, SizeT nmemb, SizeT size1 );
void  TNT_(free)                 ( ThreadId tid, void* p );
void  TNT_(__builtin_delete)     ( ThreadId tid, void* p );
void  TNT_(__builtin_vec_delete) ( ThreadId tid, void* p );
void* TNT_(realloc)              ( ThreadId tid, void* p, SizeT new_size );
SizeT TNT_(malloc_usable_size)   ( ThreadId tid, void* p );


/* Functions defined in tnt_syswrap.c */
/* System call wrappers */
extern void TNT_(syscall_read)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_write)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_open)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_close)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_llseek)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void TNT_(syscall_pread)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern Bool TNT_(syscall_allowed_check)(ThreadId tid, int syscallno);

/* Functions defined in tnt_translate.c */
IRSB* TNT_(instrument)( VgCallbackClosure* closure,
                        IRSB* bb_in,
                        VexGuestLayout* layout,
                        VexGuestExtents* vge,
                        VexArchInfo* vai,
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

/* Utility functions */
extern void TNT_(describe_data)(Addr addr, HChar* varnamebuf, UInt bufsize, enum VariableType* type, enum VariableLocation* loc);
extern void TNT_(get_fnname)(ThreadId tid, HChar* buf, UInt buf_size);
extern void TNT_(check_fd_access)(ThreadId tid, UInt fd, Int fd_request);
extern void TNT_(check_var_access)(ThreadId tid, HChar* varname, Int var_request, enum VariableType type, enum VariableLocation var_loc);

#endif /* ndef __TNT_INCLUDE_H */

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
