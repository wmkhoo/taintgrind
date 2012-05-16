
/*--------------------------------------------------------------------*/
/*--- Platform-specific syscalls stuff.        syswrap-x86-linux.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2008 Nicholas Nethercote
      njn@valgrind.org

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

#if defined(VGP_x86_freebsd)

/* TODO/FIXME jrs 20050207: assignments to the syscall return result
   in interrupted_syscall() need to be reviewed.  They don't seem
   to assign the shadow state.
*/

#include "pub_core_basics.h"
#include "pub_core_vki.h"
#include "pub_core_vkiscnums.h"
#include "pub_core_libcsetjmp.h"    // to keep _threadstate.h happy
#include "pub_core_threadstate.h"
#include "pub_core_aspacemgr.h"
#include "pub_core_debuglog.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"
#include "pub_core_libcsignal.h"
#include "pub_core_machine.h"
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"
#include "pub_core_scheduler.h"
#include "pub_core_sigframe.h"      // For VG_(sigframe_destroy)()
#include "pub_core_signals.h"
#include "pub_core_syscall.h"
#include "pub_core_syswrap.h"
#include "pub_core_tooliface.h"
#include "pub_core_stacks.h"        // VG_(register_stack)

#include "priv_types_n_macros.h"
#include "priv_syswrap-generic.h"    /* for decls of generic wrappers */
#include "priv_syswrap-freebsd.h"      /* for decls of linux-ish wrappers */
#include "priv_syswrap-main.h"

/* ---------------------------------------------------------------------
   clone() handling
   ------------------------------------------------------------------ */

/* Call f(arg1), but first switch stacks, using 'stack' as the new
   stack, and use 'retaddr' as f's return-to address.  Also, clear all
   the integer registers before entering f.*/
__attribute__((noreturn))
void ML_(call_on_new_stack_0_1) ( Addr stack,
			          Addr retaddr,
			          void (*f)(Word),
                                  Word arg1 );
//  4(%esp) == stack
//  8(%esp) == retaddr
// 12(%esp) == f
// 16(%esp) == arg1
asm(
".text\n"
".globl vgModuleLocal_call_on_new_stack_0_1\n"
"vgModuleLocal_call_on_new_stack_0_1:\n"
"   movl %esp, %esi\n"     // remember old stack pointer
"   movl 4(%esi), %esp\n"  // set stack
"   pushl 16(%esi)\n"      // arg1 to stack
"   pushl  8(%esi)\n"      // retaddr to stack
"   pushl 12(%esi)\n"      // f to stack
"   movl $0, %eax\n"       // zero all GP regs
"   movl $0, %ebx\n"
"   movl $0, %ecx\n"
"   movl $0, %edx\n"
"   movl $0, %esi\n"
"   movl $0, %edi\n"
"   movl $0, %ebp\n"
"   ret\n"                 // jump to f
"   ud2\n"                 // should never get here
".previous\n"
);


#if 0
/*
        Perform a rfork system call.  rfork is strange because it has
        fork()-like return-twice semantics, so it needs special
        handling here.

        Upon entry, we have:

            int (fn)(void*)     in  0+FSZ(%esp)
            void* child_stack   in  4+FSZ(%esp)
            int flags           in  8+FSZ(%esp)
            void* arg           in 12+FSZ(%esp)
            pid_t* child_tid    in 16+FSZ(%esp)
            pid_t* parent_tid   in 20+FSZ(%esp)
            void* tls_ptr       in 24+FSZ(%esp)

        System call requires:

            int    $__NR_clone  in %eax
            int    flags        in %ebx
            void*  child_stack  in %ecx
            pid_t* parent_tid   in %edx
            pid_t* child_tid    in %edi
            void*  tls_ptr      in %esi

	Returns an Int encoded in the linux-x86 way, not a SysRes.
 */
#define FSZ               "4+4+4+4" /* frame size = retaddr+ebx+edi+esi */
#define __NR_CLONE        VG_STRINGIFY(__NR_clone)
#define __NR_EXIT         VG_STRINGIFY(__NR_exit)

extern
Int do_syscall_clone_x86_freebsd ( Word (*fn)(void *), 
                                 void* stack, 
                                 Int   flags, 
                                 void* arg,
                                 Int*  child_tid, 
                                 Int*  parent_tid, 
                                 vki_modify_ldt_t * );
asm(
".text\n"
"do_syscall_clone_x86_freebsd:\n"
"        push    %ebx\n"
"        push    %edi\n"
"        push    %esi\n"

         /* set up child stack with function and arg */
"        movl     4+"FSZ"(%esp), %ecx\n"    /* syscall arg2: child stack */
"        movl    12+"FSZ"(%esp), %ebx\n"    /* fn arg */
"        movl     0+"FSZ"(%esp), %eax\n"    /* fn */
"        lea     -8(%ecx), %ecx\n"          /* make space on stack */
"        movl    %ebx, 4(%ecx)\n"           /*   fn arg */
"        movl    %eax, 0(%ecx)\n"           /*   fn */

         /* get other args to clone */
"        movl     8+"FSZ"(%esp), %ebx\n"    /* syscall arg1: flags */
"        movl    20+"FSZ"(%esp), %edx\n"    /* syscall arg3: parent tid * */
"        movl    16+"FSZ"(%esp), %edi\n"    /* syscall arg5: child tid * */
"        movl    24+"FSZ"(%esp), %esi\n"    /* syscall arg4: tls_ptr * */
"        movl    $"__NR_CLONE", %eax\n"
"        int     $0x80\n"                   /* clone() */
"        testl   %eax, %eax\n"              /* child if retval == 0 */
"        jnz     1f\n"

         /* CHILD - call thread function */
"        popl    %eax\n"
"        call    *%eax\n"                   /* call fn */

         /* exit with result */
"        movl    %eax, %ebx\n"              /* arg1: return value from fn */
"        movl    $"__NR_EXIT", %eax\n"
"        int     $0x80\n"

         /* Hm, exit returned */
"        ud2\n"

"1:\n"   /* PARENT or ERROR */
"        pop     %esi\n"
"        pop     %edi\n"
"        pop     %ebx\n"
"        ret\n"
".previous\n"
);

#undef FSZ
#undef __NR_CLONE
#undef __NR_EXIT


// forward declarations
static void setup_child ( ThreadArchState*, ThreadArchState*, Bool );

/* 
   When a client clones, we need to keep track of the new thread.  This means:
   1. allocate a ThreadId+ThreadState+stack for the the thread

   2. initialize the thread's new VCPU state

   3. create the thread using the same args as the client requested,
   but using the scheduler entrypoint for EIP, and a separate stack
   for ESP.
 */
static SysRes do_rfork ( ThreadId ptid, 
                         UInt flags)
{
   static const Bool debug = False;

   Addr         esp;
   ThreadId     ctid = VG_(alloc_ThreadState)();
   ThreadState* ptst = VG_(get_ThreadState)(ptid);
   ThreadState* ctst = VG_(get_ThreadState)(ctid);
   UWord*       stack;
   NSegment const* seg;
   SysRes       res;
   Int          eax;
   vki_sigset_t blockall, savedmask;

   VG_(sigfillset)(&blockall);

   vg_assert(VG_(is_running_thread)(ptid));
   vg_assert(VG_(is_valid_tid)(ctid));

   stack = (UWord*)ML_(allocstack)(ctid);
   if (stack == NULL) {
      res = VG_(mk_SysRes_Error)( VKI_ENOMEM );
      goto out;
   }

   /* Copy register state

      Both parent and child return to the same place, and the code
      following the clone syscall works out which is which, so we
      don't need to worry about it.

      The parent gets the child's new tid returned from clone, but the
      child gets 0.

      If the clone call specifies a NULL esp for the new thread, then
      it actually gets a copy of the parent's esp.
   */
   /* Note: the clone call done by the Quadrics Elan3 driver specifies
      clone flags of 0xF00, and it seems to rely on the assumption
      that the child inherits a copy of the parent's GDT.  
      setup_child takes care of setting that up. */
   setup_child( &ctst->arch, &ptst->arch, True );

   /* Make sys_clone appear to have returned Success(0) in the
      child. */
   ctst->arch.vex.guest_EAX = 0;

   /* Assume linuxthreads port storing its intended stack in %esi */
   esp = ctst->arch.vex.guest_ESI;

   ctst->os_state.parent = ptid;

   /* inherit signal mask */
   ctst->sig_mask     = ptst->sig_mask;
   ctst->tmp_sig_mask = ptst->sig_mask;

   /* We don't really know where the client stack is, because its
      allocated by the client.  The best we can do is look at the
      memory mappings and try to derive some useful information.  We
      assume that esp starts near its highest possible value, and can
      only go down to the start of the mmaped segment. */
   seg = VG_(am_find_nsegment)((Addr)esp);
   if (seg && seg->kind != SkResvn) {
      ctst->client_stack_highest_word = (Addr)VG_PGROUNDUP(esp);
      ctst->client_stack_szB = ctst->client_stack_highest_word - seg->start;

      VG_(register_stack)(seg->start, ctst->client_stack_highest_word);

      if (debug)
	 VG_(printf)("tid %d: guessed client stack range %#lx-%#lx\n",
		     ctid, seg->start, VG_PGROUNDUP(esp));
   } else {
      VG_(message)(Vg_UserMsg, "!? New thread %d starts with ESP(%#lx) unmapped\n",
		   ctid, esp);
      ctst->client_stack_szB  = 0;
   }

   /* Assume the clone will succeed, and tell any tool that wants to
      know that this thread has come into existence.  We cannot defer
      it beyond this point because sys_set_thread_area, just below,
      causes tCheck to assert by making references to the new ThreadId
      if we don't state the new thread exists prior to that point.
      If the clone fails, we'll send out a ll_exit notification for it
      at the out: label below, to clean up. */
   VG_TRACK ( pre_thread_ll_create, ptid, ctid );

   /* start the thread with everything blocked */
   VG_(sigprocmask)(VKI_SIG_SETMASK, &blockall, &savedmask);

   /* Create the new thread */
   /* XXX need to see what happens with tids etc with rfork */
   eax = do_syscall_clone_x86_freebsd(
            ML_(start_thread_NORETURN), stack, flags /*, &VG_(threads)[ctid], NULL*/ );
   res = VG_(mk_SysRes_x86_freebsd)( eax ); /* XXX edx returns too! */

   VG_(sigprocmask)(VKI_SIG_SETMASK, &savedmask, NULL);

  out:
   if (res.isError) {
      /* clone failed */
      VG_(cleanup_thread)(&ctst->arch);
      ctst->status = VgTs_Empty;
      /* oops.  Better tell the tool the thread exited in a hurry :-) */
      VG_TRACK( pre_thread_ll_exit, ctid );
   }

   return res;
}
#endif

/* Translate a struct modify_ldt_ldt_s to a VexGuestX86SegDescr */

static
void translate_to_hw_format ( /* IN  */ void* base,
                              /* OUT */ VexGuestX86SegDescr* out)
{
   UInt entry_1, entry_2;
   UInt base_addr = (UInt) base;
   vg_assert(8 == sizeof(VexGuestX86SegDescr));

   if (0)
      VG_(printf)("translate_to_hw_format: base %p\n", base );

   /* Allow LDTs to be cleared by the user. */
   if (base == 0) {
      entry_1 = 0;
      entry_2 = 0;
      goto install;
   }
   /* base as specified, no limit, read/write/accessed etc */
   entry_1 = ((base_addr & 0x0000ffff) << 16) | 0x0ffff;
   entry_2 = (base_addr & 0xff000000) |
             ((base_addr & 0x00ff0000) >> 16) | 0x00cff300;

   /* Install the new entry ...  */
  install:
   out->LdtEnt.Words.word1 = entry_1;
   out->LdtEnt.Words.word2 = entry_2;
}

/* Create a zeroed-out GDT. */
static VexGuestX86SegDescr* alloc_zeroed_x86_GDT ( void )
{
   Int nbytes = VEX_GUEST_X86_GDT_NENT * sizeof(VexGuestX86SegDescr);
   return VG_(arena_calloc)(VG_AR_CORE, "di.syswrap-x86.azxG.1", nbytes, 1);
}

#if 0
/* Create a zeroed-out LDT. */
static VexGuestX86SegDescr* alloc_zeroed_x86_LDT ( void )
{
   Int nbytes = VEX_GUEST_X86_LDT_NENT * sizeof(VexGuestX86SegDescr);
   return VG_(arena_calloc)(VG_AR_CORE, "di.syswrap-x86.azxL.1", nbytes, 1);
}

/* Free up an LDT or GDT allocated by the above fns. */
static void free_LDT_or_GDT ( VexGuestX86SegDescr* dt )
{
   vg_assert(dt);
   VG_(arena_free)(VG_AR_CORE, (void*)dt);
}

/* Copy contents between two existing LDTs. */
static void copy_LDT_from_to ( VexGuestX86SegDescr* src,
                               VexGuestX86SegDescr* dst )
{
   Int i;
   vg_assert(src);
   vg_assert(dst);
   for (i = 0; i < VEX_GUEST_X86_LDT_NENT; i++)
      dst[i] = src[i];
}

/* Copy contents between two existing GDTs. */
static void copy_GDT_from_to ( VexGuestX86SegDescr* src,
                               VexGuestX86SegDescr* dst )
{
   Int i;
   vg_assert(src);
   vg_assert(dst);
   for (i = 0; i < VEX_GUEST_X86_GDT_NENT; i++)
      dst[i] = src[i];
}

/* Free this thread's DTs, if it has any. */
static void deallocate_LGDTs_for_thread ( VexGuestX86State* vex )
{
   vg_assert(sizeof(HWord) == sizeof(void*));

   if (0)
      VG_(printf)("deallocate_LGDTs_for_thread: "
                  "ldt = 0x%x, gdt = 0x%x\n", 
                  vex->guest_LDT, vex->guest_GDT );

   if (vex->guest_LDT != (HWord)NULL) {
      free_LDT_or_GDT( (VexGuestX86SegDescr*)vex->guest_LDT );
      vex->guest_LDT = (HWord)NULL;
   }

   if (vex->guest_GDT != (HWord)NULL) {
      free_LDT_or_GDT( (VexGuestX86SegDescr*)vex->guest_GDT );
      vex->guest_GDT = (HWord)NULL;
   }
}
#endif

static SysRes sys_set_thread_area ( ThreadId tid, Int *idxptr, void *base)
{
   VexGuestX86SegDescr* gdt;
   Int idx;

   vg_assert(8 == sizeof(VexGuestX86SegDescr));
   vg_assert(sizeof(HWord) == sizeof(VexGuestX86SegDescr*));

   gdt = (VexGuestX86SegDescr*)VG_(threads)[tid].arch.vex.guest_GDT;

   /* If the thread doesn't have a GDT, allocate it now. */
   if (!gdt) {
      gdt = alloc_zeroed_x86_GDT();
      VG_(threads)[tid].arch.vex.guest_GDT = (HWord)gdt;
   }

   idx = *idxptr;
   if (idx == -1) {
      /* Find and use the first free entry.  Don't allocate entry
         zero, because the hardware will never do that, and apparently
         doing so confuses some code (perhaps stuff running on
         Wine). */
      for (idx = 1; idx < VEX_GUEST_X86_GDT_NENT; idx++) {
         if (gdt[idx].LdtEnt.Words.word1 == 0
             && gdt[idx].LdtEnt.Words.word2 == 0)
            break;
      }

      if (idx == VEX_GUEST_X86_GDT_NENT)
         return VG_(mk_SysRes_Error)( VKI_ESRCH );
   } else if (idx < 0 || idx == 0 || idx >= VEX_GUEST_X86_GDT_NENT) {
      /* Similarly, reject attempts to use GDT[0]. */
      return VG_(mk_SysRes_Error)( VKI_EINVAL );
   }

   translate_to_hw_format(base, &gdt[idx]);

   *idxptr = idx;
   return VG_(mk_SysRes_Success)( 0 );
}

static SysRes sys_get_thread_area ( ThreadId tid, Int idx, void ** basep )
{
   VexGuestX86SegDescr* gdt;
   UInt base;

   vg_assert(sizeof(HWord) == sizeof(VexGuestX86SegDescr*));
   vg_assert(8 == sizeof(VexGuestX86SegDescr));

   gdt = (VexGuestX86SegDescr*)VG_(threads)[tid].arch.vex.guest_GDT;

   /* If the thread doesn't have a GDT, allocate it now. */
   if (!gdt) {
      gdt = alloc_zeroed_x86_GDT();
      VG_(threads)[tid].arch.vex.guest_GDT = (HWord)gdt;
   }
   
   base = ( gdt[idx].LdtEnt.Bits.BaseHi << 24 ) |
          ( gdt[idx].LdtEnt.Bits.BaseMid << 16 ) |
            gdt[idx].LdtEnt.Bits.BaseLow;
   *basep = (void *)base;

   return VG_(mk_SysRes_Success)( 0 );
}

/* ---------------------------------------------------------------------
   More thread stuff
   ------------------------------------------------------------------ */

void VG_(cleanup_thread) ( ThreadArchState* arch )
{
}  


#if 0
static void setup_child ( /*OUT*/ ThreadArchState *child,
                          /*IN*/  ThreadArchState *parent,
                          Bool inherit_parents_GDT )
{
   /* We inherit our parent's guest state. */
   child->vex = parent->vex;
   child->vex_shadow1 = parent->vex_shadow1;
   child->vex_shadow2 = parent->vex_shadow2;

   /* We inherit our parent's LDT. */
   if (parent->vex.guest_LDT == (HWord)NULL) {
      /* We hope this is the common case. */
      child->vex.guest_LDT = (HWord)NULL;
   } else {
      /* No luck .. we have to take a copy of the parent's. */
      child->vex.guest_LDT = (HWord)alloc_zeroed_x86_LDT();
      copy_LDT_from_to( (VexGuestX86SegDescr*)parent->vex.guest_LDT,
                        (VexGuestX86SegDescr*)child->vex.guest_LDT );
   }
      
   /* Either we start with an empty GDT (the usual case) or inherit a
      copy of our parents' one (Quadrics Elan3 driver -style clone
      only). */
   child->vex.guest_GDT = (HWord)NULL;
      
   if (inherit_parents_GDT && parent->vex.guest_GDT != (HWord)NULL) {
      child->vex.guest_GDT = (HWord)alloc_zeroed_x86_GDT();
      copy_GDT_from_to( (VexGuestX86SegDescr*)parent->vex.guest_GDT,
                        (VexGuestX86SegDescr*)child->vex.guest_GDT );
   }
}
#endif

/* ---------------------------------------------------------------------
   PRE/POST wrappers for x86/Linux-specific syscalls
   ------------------------------------------------------------------ */

#define PRE(name)       DEFN_PRE_TEMPLATE(freebsd, name)
#define POST(name)      DEFN_POST_TEMPLATE(freebsd, name)

#if 0
struct thr_param {
    void        (*start_func)(void *);  /* thread entry function. */
    void        *arg;                   /* argument for entry function. */
    char        *stack_base;            /* stack base address. */
    size_t      stack_size;             /* stack size. */
    char        *tls_base;              /* tls base address. */
    size_t      tls_size;               /* tls size. */
    long        *child_tid;             /* address to store new TID. */
    long        *parent_tid;            /* parent accesses the new TID here. */
    int         flags;                  /* thread flags. */
    struct rtprio       *rtp;           /* Real-time scheduling priority */
    void        *spare[3];              /* TODO: cpu affinity mask etc. */
};
int thr_new(struct thr_param *param, int param_size);
#endif

PRE(sys_thr_new)
{
   static const Bool debug = False;

   ThreadId     ctid = VG_(alloc_ThreadState)();
   ThreadState* ptst = VG_(get_ThreadState)(tid);
   ThreadState* ctst = VG_(get_ThreadState)(ctid);
   SysRes       res;
   vki_sigset_t blockall, savedmask;
   struct vki_thr_param tp;
   Int idx = -1;
   Addr stk;

   PRINT("thr_new ( %#lx, %ld )",ARG1,ARG2);
   PRE_REG_READ2(int, "thr_new",
                 struct thr_param *, param,
                 int, param_size);
   
   PRE_MEM_READ( "thr_new(param)", ARG1, offsetof(struct vki_thr_param, spare));
   if (!ML_(safe_to_deref)( (void*)ARG1, offsetof(struct vki_thr_param, spare))) {
      SET_STATUS_Failure( VKI_EFAULT );
      return;
   }
   VG_(memset)(&tp, 0, sizeof(tp));
   VG_(memcpy)(&tp, (void *)ARG1, offsetof(struct vki_thr_param, spare));
   PRE_MEM_WRITE("clone(parent_tidptr)", (Addr)tp.parent_tid, sizeof(long));
   PRE_MEM_WRITE("clone(child_tidptr)", (Addr)tp.child_tid, sizeof(long));

   VG_(sigfillset)(&blockall);

   vg_assert(VG_(is_running_thread)(tid));
   vg_assert(VG_(is_valid_tid)(ctid));

   /* Copy register state

      On linux, both parent and child return to the same place, and the code
      following the clone syscall works out which is which, so we
      don't need to worry about it.
      On FreeBSD, thr_new arranges a direct call.  We don't actually need any
      of this gunk.

      The parent gets the child's new tid returned from clone, but the
      child gets 0.

      If the clone call specifies a NULL rsp for the new thread, then
      it actually gets a copy of the parent's rsp.
   */
   /* We inherit our parent's guest state. */
   ctst->arch.vex = ptst->arch.vex;
   ctst->arch.vex_shadow1 = ptst->arch.vex_shadow1;
   ctst->arch.vex_shadow2 = ptst->arch.vex_shadow2;

   /* Make sys_clone appear to have returned Success(0) in the
      child. */
   ctst->arch.vex.guest_EAX = 0;
   ctst->arch.vex.guest_EDX = 0;
   LibVEX_GuestX86_put_eflag_c(0, &ctst->arch.vex);

   ctst->os_state.parent = tid;

   /* inherit signal mask */
   ctst->sig_mask = ptst->sig_mask;
   ctst->tmp_sig_mask = ptst->sig_mask;

   /* Linux has to guess, we don't */
   VG_(register_stack)((Addr)tp.stack_base, (Addr)tp.stack_base + tp.stack_size);

   /* Assume the clone will succeed, and tell any tool that wants to
      know that this thread has come into existence.  If the clone
      fails, we'll send out a ll_exit notification for it at the out:
      label below, to clean up. */
   VG_TRACK ( pre_thread_ll_create, tid, ctid );

   if (debug)
      VG_(printf)("clone child has SETTLS: tls at %#lx\n", (Addr)tp.tls_base);
   sys_set_thread_area( ctid, &idx, tp.tls_base );
   ctst->arch.vex.guest_GS = (idx << 3) | 3;   /* GSEL(GUGS_SEL, SEL_UPL) */
   tp.tls_base = 0;	/* Don't have the kernel do it too */

   /* start the thread with everything blocked */
   VG_(sigprocmask)(VKI_SIG_SETMASK, &blockall, &savedmask);

   /* Set the client state for scheduler to run libthr's trampoline */
   ctst->arch.vex.guest_ESP = (Addr)tp.stack_base + tp.stack_size - 8;
   ctst->arch.vex.guest_EIP = (Addr)tp.start_func;
   *(UWord *)(ctst->arch.vex.guest_ESP + 4) = (UWord)tp.arg;	/* Client arg */
   *(UWord *)(ctst->arch.vex.guest_ESP + 0) = 0;		/* fake return addr */

   /* Set up valgrind's trampoline on its own stack */
   stk = ML_(allocstack)(ctid);
   tp.stack_base = (void *)ctst->os_state.valgrind_stack_base;
   tp.stack_size = (Addr)stk - (Addr)tp.stack_base;
   /* This is for thr_new() to run valgrind's trampoline */
   tp.start_func = (void *)ML_(start_thread_NORETURN);
   tp.arg = &VG_(threads)[ctid];

   /* Create the new thread */
   res = VG_(do_syscall2)(__NR_thr_new, (UWord)&tp, sizeof(tp));

   VG_(sigprocmask)(VKI_SIG_SETMASK, &savedmask, NULL);

   if (sr_isError(res)) {
      /* clone failed */
      VG_(cleanup_thread)(&ctst->arch);
      ctst->status = VgTs_Empty;
      /* oops.  Better tell the tool the thread exited in a hurry :-) */
      VG_TRACK( pre_thread_ll_exit, ctid );
   } else {

      POST_MEM_WRITE((Addr)tp.parent_tid, sizeof(long));
      POST_MEM_WRITE((Addr)tp.child_tid, sizeof(long));
      POST_MEM_WRITE((Addr)ctst->arch.vex.guest_ESP, 8);

      /* Thread creation was successful; let the child have the chance
         to run */
      *flags |= SfYieldAfter;
   }

   /* "Complete" the syscall so that the wrapper doesn't call the kernel again. */
   SET_STATUS_from_SysRes(res);
}


PRE(sys_rfork)
{
   PRINT("sys_rfork ( %lx )",ARG1);
   PRE_REG_READ1(int, "rfork",
                 unsigned int, flags);

#if 0
   cloneflags = ARG1;

   if (!ML_(client_signal_OK)(ARG1 & VKI_CSIGNAL)) {
      SET_STATUS_Failure( VKI_EINVAL );
      return;
   }

   SET_STATUS_from_SysRes( do_clone(tid, ARG1));

   if (SUCCESS) {
      *flags |= SfYieldAfter;
   }
#else
   VG_(message)(Vg_UserMsg, "No rfork for you!");
   VG_(unimplemented)
         ("Valgrind does not support rfork() yet.");
   SET_STATUS_Failure( VKI_ENOSYS );
#endif
}

PRE(sys_sigreturn)
{
   PRINT("sys_sigreturn ( %#lx )", ARG1);
   PRE_REG_READ1(long, "sigreturn",
                 struct vki_ucontext *, ucp);

   PRE_MEM_READ( "sigreturn(ucp)", ARG1, sizeof(struct vki_ucontext) );
   PRE_MEM_WRITE( "sigreturn(ucp)", ARG1, sizeof(struct vki_ucontext) );
}

PRE(sys_fake_sigreturn)
{
   /* See comments on PRE(sys_rt_sigreturn) in syswrap-amd64-linux.c for
      an explanation of what follows. */

   ThreadState* tst;
   struct vki_ucontext *uc;
   PRINT("sys_sigreturn ( )");

   vg_assert(VG_(is_valid_tid)(tid));
   vg_assert(tid >= 1 && tid < VG_N_THREADS);
   vg_assert(VG_(is_running_thread)(tid));

   /* Adjust esp to point to start of frame; skip back up over handler
      ret addr */
   tst = VG_(get_ThreadState)(tid);
   tst->arch.vex.guest_ESP -= sizeof(Addr);	/* QQQ should be redundant */

   uc = (struct vki_ucontext *)ARG1;
   if (uc == NULL || uc->uc_mcontext.len != sizeof(uc->uc_mcontext)) {
      SET_STATUS_Failure(VKI_EINVAL);
      return;
   }

   /* This is only so that the EIP is (might be) useful to report if
      something goes wrong in the sigreturn */
   ML_(fixup_guest_state_to_restart_syscall)(&tst->arch);

   /* Restore register state from frame and remove it */
   VG_(sigframe_destroy)(tid);

   /*
    * Signal handler might have changed the signal mask.  Respect that.
    */
   tst->sig_mask = uc->uc_sigmask;
   tst->tmp_sig_mask = uc->uc_sigmask;

   /* Tell the driver not to update the guest state with the "result",
      and set a bogus result to keep it happy. */
   *flags |= SfNoWriteResult;
   SET_STATUS_Success(0);

   /* Check to see if any signals arose as a result of this. */
   *flags |= SfPollAfter;
}

#if 0	/* QQQ keep for 6.x signals */
PRE(sys_rt_sigreturn)
{
   /* See comments on PRE(sys_rt_sigreturn) in syswrap-amd64-linux.c for
      an explanation of what follows. */

   ThreadState* tst;
   PRINT("sys_rt_sigreturn ( )");

   vg_assert(VG_(is_valid_tid)(tid));
   vg_assert(tid >= 1 && tid < VG_N_THREADS);
   vg_assert(VG_(is_running_thread)(tid));

   /* Adjust esp to point to start of frame; skip back up over handler
      ret addr */
   tst = VG_(get_ThreadState)(tid);
   tst->arch.vex.guest_ESP -= sizeof(Addr);

   /* This is only so that the EIP is (might be) useful to report if
      something goes wrong in the sigreturn */
   ML_(fixup_guest_state_to_restart_syscall)(&tst->arch);

   /* Restore register state from frame and remove it */
   VG_(sigframe_destroy)(tid, True);

   /* Tell the driver not to update the guest state with the "result",
      and set a bogus result to keep it happy. */
   *flags |= SfNoWriteResult;
   SET_STATUS_Success(0);

   /* Check to see if any signals arose as a result of this. */
   *flags |= SfPollAfter;
}
#endif

static void restore_mcontext(ThreadState *tst, struct vki_mcontext *sc)
{
   tst->arch.vex.guest_EAX     = sc->eax;
   tst->arch.vex.guest_ECX     = sc->ecx;
   tst->arch.vex.guest_EDX     = sc->edx;
   tst->arch.vex.guest_EBX     = sc->ebx;
   tst->arch.vex.guest_EBP     = sc->ebp;
   tst->arch.vex.guest_ESP     = sc->esp;
   tst->arch.vex.guest_ESI     = sc->esi;
   tst->arch.vex.guest_EDI     = sc->edi;
   tst->arch.vex.guest_EIP     = sc->eip;
   tst->arch.vex.guest_CS      = sc->cs;
   tst->arch.vex.guest_SS      = sc->ss;
   tst->arch.vex.guest_DS      = sc->ds;
   tst->arch.vex.guest_ES      = sc->es;
   tst->arch.vex.guest_FS      = sc->fs;
   tst->arch.vex.guest_GS      = sc->gs;
   /*
    * XXX: missing support for other flags.
    */
   if (sc->eflags & 0x0001)
      LibVEX_GuestX86_put_eflag_c(1, &tst->arch.vex);
   else
      LibVEX_GuestX86_put_eflag_c(0, &tst->arch.vex);
}

static void fill_mcontext(ThreadState *tst, struct vki_mcontext *sc)
{
   sc->eax = tst->arch.vex.guest_EAX;
   sc->ecx = tst->arch.vex.guest_ECX;
   sc->edx = tst->arch.vex.guest_EDX;
   sc->ebx = tst->arch.vex.guest_EBX;
   sc->ebp = tst->arch.vex.guest_EBP;
   sc->esp = tst->arch.vex.guest_ESP;
   sc->esi = tst->arch.vex.guest_ESI;
   sc->edi = tst->arch.vex.guest_EDI;
   sc->eip = tst->arch.vex.guest_EIP;
   sc->cs = tst->arch.vex.guest_CS;
   sc->ss = tst->arch.vex.guest_SS;
   sc->ds = tst->arch.vex.guest_DS;
   sc->es = tst->arch.vex.guest_ES;
   sc->fs = tst->arch.vex.guest_FS;
   sc->gs = tst->arch.vex.guest_GS;
   sc->eflags = LibVEX_GuestX86_get_eflags(&tst->arch.vex);
/*
   not yet.
   VG_(memcpy)(&sc->fpstate, fpstate, sizeof(*fpstate));
*/
   sc->fpformat = VKI_FPFMT_NODEV;
   sc->ownedfp = VKI_FPOWNED_NONE;
   sc->len = sizeof(*sc);
   VG_(memset)(sc->spare2, 0, sizeof(sc->spare2));
}


PRE(sys_getcontext)
{
   ThreadState* tst;
   struct vki_ucontext *uc;
   
   PRINT("sys_getcontext ( %#lx )", ARG1);
   PRE_REG_READ1(long, "getcontext",
                 struct vki_ucontext *, ucp);
   PRE_MEM_WRITE( "getcontext(ucp)", ARG1, sizeof(struct vki_ucontext) );
   uc = (struct vki_ucontext *)ARG1;
   if (uc == NULL) {
      SET_STATUS_Failure(VKI_EINVAL);
      return;
   }
   tst = VG_(get_ThreadState)(tid);
   fill_mcontext(tst, &uc->uc_mcontext);
   uc->uc_mcontext.eax = 0;
   uc->uc_mcontext.edx = 0;
   uc->uc_mcontext.eflags &= ~0x0001;   /* PSL_C */
   uc->uc_sigmask = tst->sig_mask;
   VG_(memset)(uc->__spare__, 0, sizeof(uc->__spare__));
   SET_STATUS_Success(0);
}

PRE(sys_setcontext)
{
   ThreadState* tst;
   struct vki_ucontext *uc;

   PRINT("sys_setcontext ( %#lx )", ARG1);
   PRE_REG_READ1(long, "setcontext",
                 struct vki_ucontext *, ucp);

   PRE_MEM_READ( "setcontext(ucp)", ARG1, sizeof(struct vki_ucontext) );
   PRE_MEM_WRITE( "setcontext(ucp)", ARG1, sizeof(struct vki_ucontext) );

   vg_assert(VG_(is_valid_tid)(tid));
   vg_assert(tid >= 1 && tid < VG_N_THREADS);
   vg_assert(VG_(is_running_thread)(tid));

   tst = VG_(get_ThreadState)(tid);
   uc = (struct vki_ucontext *)ARG1;
   if (uc == NULL || uc->uc_mcontext.len != sizeof(uc->uc_mcontext)) {
      SET_STATUS_Failure(VKI_EINVAL);
      return;
   }
   
   restore_mcontext(tst, &uc->uc_mcontext);
   tst->sig_mask = uc->uc_sigmask;
                                  
   /* Tell the driver not to update the guest state with the "result",
      and set a bogus result to keep it happy. */
   *flags |= SfNoWriteResult;
   SET_STATUS_Success(0);

   /* Check to see if some any signals arose as a result of this. */
   *flags |= SfPollAfter;
}

PRE(sys_swapcontext)
{
   struct vki_ucontext *ucp, *oucp;
   ThreadState* tst;

   PRINT("sys_swapcontext ( %#lx, %#lx )", ARG1, ARG2);
   PRE_REG_READ2(long, "swapcontext",
                 struct vki_ucontext *, oucp, struct vki_ucontext *, ucp);
 
   PRE_MEM_READ( "swapcontext(ucp)", ARG2, sizeof(struct vki_ucontext) );
   PRE_MEM_WRITE( "swapcontext(oucp)", ARG1, sizeof(struct vki_ucontext) );
 
   oucp = (struct vki_ucontext *)ARG1;
   ucp = (struct vki_ucontext *)ARG2;
   if (oucp == NULL || ucp == NULL || ucp->uc_mcontext.len != sizeof(ucp->uc_mcontext)) {
      SET_STATUS_Failure(VKI_EINVAL);
      return;
   }
   tst = VG_(get_ThreadState)(tid);

   /*
    * Save the context.
    */
   fill_mcontext(tst, &oucp->uc_mcontext);
   oucp->uc_mcontext.eax = 0;
   oucp->uc_mcontext.edx = 0;
   oucp->uc_mcontext.eflags &= ~0x0001; /* PSL_C */
   oucp->uc_sigmask = tst->sig_mask;
   VG_(memset)(oucp->__spare__, 0, sizeof(oucp->__spare__));
 
   /*
    * Switch to new one.
    */
   restore_mcontext(tst, &ucp->uc_mcontext);
   tst->sig_mask = ucp->uc_sigmask;

   /* Tell the driver not to update the guest state with the "result",
      and set a bogus result to keep it happy. */
   *flags |= SfNoWriteResult;
   SET_STATUS_Success(0);

   /* Check to see if some any signals arose as a result of this. */
   *flags |= SfPollAfter;
}

/* This is here because on x86 the off_t is passed in 2 regs. Don't ask about pad.  */

/* caddr_t mmap(caddr_t addr, size_t len, int prot, int flags, int fd, int pad, off_t pos); */
/*              ARG1           ARG2       ARG3      ARG4       ARG5    ARG6     ARG7+ARG8 */

PRE(sys_mmap)
{
   SysRes r;

   PRINT("sys_mmap ( %#lx, %lu, %ld, %ld, %ld, pad%ld, lo0x%lx hi0x%lx)",
         ARG1, (UWord)ARG2, ARG3, ARG4, ARG5, ARG6, ARG7, ARG8 );
   PRE_REG_READ8(long, "mmap",
                 char *, addr, unsigned long, len, int, prot,  int, flags,
                 int, fd,  int, pad, unsigned long, lo, unsigned long, hi);

   r = ML_(generic_PRE_sys_mmap)( tid, ARG1, ARG2, ARG3, ARG4, ARG5, ARG7 + ((Off64T)ARG8 << 32) );
   SET_STATUS_from_SysRes(r);
}

PRE(sys_mmap7)
{
   SysRes r;

   PRINT("sys_mmap ( %#lx, %lu, %ld, %ld, %ld, lo0x%lx hi0x%lx)",
         ARG1, (UWord)ARG2, ARG3, ARG4, ARG5, ARG6, ARG7 );
   PRE_REG_READ7(long, "mmap",
                 char *, addr, unsigned long, len, int, prot,  int, flags,
                 int, fd, unsigned long, lo, unsigned long, hi);

   r = ML_(generic_PRE_sys_mmap)( tid, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6 + ((Off64T)ARG7 << 32) );
   SET_STATUS_from_SysRes(r);
}

PRE(sys_lseek)
{
   PRINT("sys_lseek ( %ld, 0x%lx, 0x%lx, %ld )", ARG1,ARG3,ARG4,ARG5);
   PRE_REG_READ5(long, "lseek",
                 unsigned int, fd, int, pad, unsigned int, offset_low,
                 unsigned int, offset_high, unsigned int, whence);
}

PRE(sys_lseek7)
{
   PRINT("sys_lseek ( %ld, 0x%lx, 0x%lx, %ld )", ARG1,ARG2,ARG3,ARG4);
   PRE_REG_READ4(long, "lseek",
                 unsigned int, fd, unsigned int, offset_low,
                 unsigned int, offset_high, unsigned int, whence);
}

PRE(sys_pread)
{
   *flags |= SfMayBlock;
   PRINT("sys_read ( %ld, %#lx, %lu, %lu, %lu )", ARG1, ARG2, ARG3, ARG5, ARG6);
   PRE_REG_READ6(ssize_t, "read",
                 unsigned int, fd, char *, buf, vki_size_t, count,
                 int, pad, unsigned int, off_low, unsigned int, off_high);

   if (!ML_(fd_allowed)(ARG1, "read", tid, False))
      SET_STATUS_Failure( VKI_EBADF );
   else
      PRE_MEM_WRITE( "read(buf)", ARG2, ARG3 );
}

POST(sys_pread)
{
   vg_assert(SUCCESS);
   POST_MEM_WRITE( ARG2, RES );
}

PRE(sys_pread7)
{
   *flags |= SfMayBlock;
   PRINT("sys_read ( %ld, %#lx, %lu, %lu, %lu )", ARG1, ARG2, ARG3, ARG4, ARG5);
   PRE_REG_READ5(ssize_t, "read",
                 unsigned int, fd, char *, buf, vki_size_t, count,
                 unsigned int, off_low, unsigned int, off_high);

   if (!ML_(fd_allowed)(ARG1, "read", tid, False))
      SET_STATUS_Failure( VKI_EBADF );
   else
      PRE_MEM_WRITE( "read(buf)", ARG2, ARG3 );
}

POST(sys_pread7)
{
   vg_assert(SUCCESS);
   POST_MEM_WRITE( ARG2, RES );
}

PRE(sys_pwrite)
{
   Bool ok;
   *flags |= SfMayBlock;
   PRINT("sys_write ( %ld, %#lx, %lu, %lu, %lu )", ARG1, ARG2, ARG3, ARG5, ARG6);
   PRE_REG_READ6(ssize_t, "write",
                 unsigned int, fd, const char *, buf, vki_size_t, count,
                 int, pad, unsigned int, off_low, unsigned int, off_high);
   /* check to see if it is allowed.  If not, try for an exemption from
      --sim-hints=enable-outer (used for self hosting). */
   ok = ML_(fd_allowed)(ARG1, "write", tid, False);
   if (!ok && ARG1 == 2/*stderr*/
           && VG_(strstr)(VG_(clo_sim_hints),"enable-outer"))
      ok = True;
   if (!ok)
      SET_STATUS_Failure( VKI_EBADF );
   else
      PRE_MEM_READ( "write(buf)", ARG2, ARG3 );
}

PRE(sys_pwrite7)
{
   Bool ok;
   *flags |= SfMayBlock;
   PRINT("sys_write ( %ld, %#lx, %lu, %lu, %lu )", ARG1, ARG2, ARG3, ARG4, ARG5);
   PRE_REG_READ5(ssize_t, "write",
                 unsigned int, fd, const char *, buf, vki_size_t, count,
                 unsigned int, off_low, unsigned int, off_high);
   /* check to see if it is allowed.  If not, try for an exemption from
      --sim-hints=enable-outer (used for self hosting). */
   ok = ML_(fd_allowed)(ARG1, "write", tid, False);
   if (!ok && ARG1 == 2/*stderr*/
           && VG_(strstr)(VG_(clo_sim_hints),"enable-outer"))
      ok = True;
   if (!ok)
      SET_STATUS_Failure( VKI_EBADF );
   else
      PRE_MEM_READ( "write(buf)", ARG2, ARG3 );
}

PRE(sys_ftruncate)
{
   *flags |= SfMayBlock;
   PRINT("sys_ftruncate ( %ld, %lu, %lu )", ARG1,ARG3,ARG4);
   PRE_REG_READ4(long, "ftruncate", unsigned int, fd, int, pad,
		  unsigned int, length_low, unsigned int, length_high);
}

PRE(sys_ftruncate7)
{
   *flags |= SfMayBlock;
   PRINT("sys_ftruncate ( %ld, %lu, %lu )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "ftruncate", unsigned int, fd,
		  unsigned int, length_low, unsigned int, length_high);
}

PRE(sys_truncate)
{
   *flags |= SfMayBlock;
   PRINT("sys_truncate ( %#lx(%s), %lu, %lu )", ARG1,(char *)ARG1,ARG3,ARG4);
   PRE_REG_READ4(long, "truncate",
                 const char *, path, int, pad,
		 unsigned int, length_low, unsigned int, length_high);
   PRE_MEM_RASCIIZ( "truncate(path)", ARG1 );
}

PRE(sys_truncate7)
{
   *flags |= SfMayBlock;
   PRINT("sys_truncate ( %#lx(%s), %lu, %lu )", ARG1,(char *)ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "truncate",
                 const char *, path,
		 unsigned int, length_low, unsigned int, length_high);
   PRE_MEM_RASCIIZ( "truncate(path)", ARG1 );
}

PRE(sys_sysarch)
{
   ThreadState *tst;
   Int idx;
   void **p;

   PRINT("sys_sysarch ( %ld, %#lx )", ARG1, ARG2);
   PRE_REG_READ2(int, "sysarch",
		 int, number, void *, args);
   switch (ARG1) {
   case VKI_I386_SET_GSBASE:
      PRINT("sys_i386_set_gsbase ( %#lx )", ARG2);
      PRE_REG_READ1(int, "i386_set_gsbase", void *, base)

      /* On FreeBSD, the syscall loads the %gs selector for us, so do it now. */
      tst = VG_(get_ThreadState)(tid);
      p = (void**)ARG2;
      tst->arch.vex.guest_GS = (1 << 3) | 3;   /* GSEL(GUGS_SEL, SEL_UPL) */
      /* "do" the syscall ourselves; the kernel never sees it */
      idx = 1;
      SET_STATUS_from_SysRes( sys_set_thread_area( tid, &idx, *p ) );

      break;
   case VKI_I386_GET_GSBASE:
      PRINT("sys_i386_get_gsbase ( %#lx )", ARG2);
      PRE_REG_READ1(int, "i386_get_gsbase", void *, basep)
      PRE_MEM_WRITE( "i386_get_gsbase(basep)", ARG2, sizeof(void *) );

      /* "do" the syscall ourselves; the kernel never sees it */
      SET_STATUS_from_SysRes( sys_get_thread_area( tid, 2, (void **)ARG2 ) );

      if (SUCCESS) {
	 POST_MEM_WRITE( ARG2, sizeof(void *) );
      }
      break;
   default:
      VG_(message) (Vg_UserMsg, "unhandled sysarch cmd %ld", ARG1);
      VG_(unimplemented) ("unhandled sysarch cmd");
      break;
   }
}

#undef PRE
#undef POST

#endif /* defined(VGP_x86_linux) */


/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
