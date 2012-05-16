
/*--------------------------------------------------------------------*/
/*--- Platform-specific syscalls stuff.    syswrap-amd64-freebsd.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2005 Nicholas Nethercote
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

#if defined(VGP_amd64_freebsd)

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
#include "pub_core_options.h"
#include "pub_core_scheduler.h"
#include "pub_core_sigframe.h"
#include "pub_core_signals.h"
#include "pub_core_syscall.h"
#include "pub_core_syswrap.h"
#include "pub_core_tooliface.h"
#include "pub_core_stacks.h"        // VG_(register_stack)

#include "priv_types_n_macros.h"
#include "priv_syswrap-generic.h"    /* for decls of generic wrappers */
#include "priv_syswrap-freebsd.h"    /* for decls of freebsd-ish wrappers */
#include "priv_syswrap-main.h"

/* ---------------------------------------------------------------------
   clone() handling
   ------------------------------------------------------------------ */

/* Call f(arg1), but first switch stacks, using 'stack' as the new
   stack, and use 'retaddr' as f's return-to address.  Also, clear all
   the integer registers before entering f. */
__attribute__((noreturn))
void ML_(call_on_new_stack_0_1) ( Addr stack,
			          Addr retaddr,
			          void (*f)(Word),
                                  Word arg1 );
// %rdi == stack
// %rsi == retaddr
// %rdx == f
// %rcx == arg1
asm(
".text\n"
".globl vgModuleLocal_call_on_new_stack_0_1\n"
"vgModuleLocal_call_on_new_stack_0_1:\n"
"   movq   %rdi, %rsp\n"   // set stack
"   pushq  %rsi\n"         // retaddr to stack
"   pushq  %rdx\n"         // f to stack
"   pushq  %rcx\n"         // arg1 to stack
"   movq $0, %rax\n"       // zero all GP regs
"   movq $0, %rbx\n"
"   movq $0, %rcx\n"
"   movq $0, %rdx\n"
"   movq $0, %rsi\n"
"   movq $0, %rdi\n"
"   movq $0, %rbp\n"
"   movq $0, %r8\n"
"   movq $0, %r9\n"
"   movq $0, %r10\n"
"   movq $0, %r11\n"
"   movq $0, %r12\n"
"   movq $0, %r13\n"
"   movq $0, %r14\n"
"   movq $0, %r15\n"
"   popq   %rdi\n"         // arg1 to correct arg reg
"   ret\n"                 // jump to f
"   ud2\n"                 // should never get here
".previous\n"
);


/* ---------------------------------------------------------------------
   More thread stuff
   ------------------------------------------------------------------ */

void VG_(cleanup_thread) ( ThreadArchState *arch )
{
}

/* ---------------------------------------------------------------------
   PRE/POST wrappers for amd64/FreeBSD-specific syscalls
   ------------------------------------------------------------------ */

#define PRE(name)       DEFN_PRE_TEMPLATE(freebsd, name)
#define POST(name)      DEFN_POST_TEMPLATE(freebsd, name)

PRE(sys_thr_new)
{
   static const Bool debug = False;

   ThreadId     ctid = VG_(alloc_ThreadState)();
   ThreadState* ptst = VG_(get_ThreadState)(tid);
   ThreadState* ctst = VG_(get_ThreadState)(ctid);
   SysRes       res;
   vki_sigset_t blockall, savedmask;
   struct vki_thr_param tp;
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
   PRE_MEM_WRITE("thr_new(parent_tidptr)", (Addr)tp.parent_tid, sizeof(long));
   PRE_MEM_WRITE("thr_new(child_tidptr)", (Addr)tp.child_tid, sizeof(long));

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

   /* Make thr_new appear to have returned Success(0) in the
      child. */
   ctst->arch.vex.guest_RAX = 0;
   ctst->arch.vex.guest_RDX = 0;
   LibVEX_GuestAMD64_put_rflag_c(0, &ctst->arch.vex);

   ctst->os_state.parent = tid;

   /* inherit signal mask */
   ctst->sig_mask = ptst->sig_mask;
   ctst->tmp_sig_mask = ptst->sig_mask;

   /* Linux has to guess, we don't */
   ctst->client_stack_highest_word = (Addr)tp.stack_base + tp.stack_size;
   ctst->client_stack_szB = tp.stack_size;
   VG_(register_stack)((Addr)tp.stack_base, (Addr)tp.stack_base + tp.stack_size);

   /* Assume the thr_new will succeed, and tell any tool that wants to
      know that this thread has come into existence.  If the thr_new
      fails, we'll send out a ll_exit notification for it at the out:
      label below, to clean up. */
   VG_TRACK ( pre_thread_ll_create, tid, ctid );

   if (debug)
      VG_(printf)("clone child has SETTLS: tls at %#lx\n", (Addr)tp.tls_base);
   ctst->arch.vex.guest_FS_ZERO = (UWord)tp.tls_base;
   tp.tls_base = 0;	/* Don't have the kernel do it too */

   /* start the thread with everything blocked */
   VG_(sigprocmask)(VKI_SIG_SETMASK, &blockall, &savedmask);

   /* Set the client state for scheduler to run libthr's trampoline */
   ctst->arch.vex.guest_RDI = (Addr)tp.arg;
   /* XXX: align on 16-byte boundary? */
   ctst->arch.vex.guest_RSP = (Addr)tp.stack_base + tp.stack_size - 8;
   ctst->arch.vex.guest_RIP = (Addr)tp.start_func;

   /* But this is for thr_new() to run valgrind's trampoline */
   tp.start_func = (void *)ML_(start_thread_NORETURN);
   tp.arg = &VG_(threads)[ctid];

   /* And valgrind's trampoline on its own stack */
   stk = ML_(allocstack)(ctid);
   if (stk == (Addr)NULL) {
      res = VG_(mk_SysRes_Error)( VKI_ENOMEM );
      goto fail;
   }
   tp.stack_base = (void *)ctst->os_state.valgrind_stack_base;
   tp.stack_size = (Addr)stk - (Addr)tp.stack_base;

   /* Create the new thread */
   res = VG_(do_syscall2)(__NR_thr_new, (UWord)&tp, sizeof(tp));

   VG_(sigprocmask)(VKI_SIG_SETMASK, &savedmask, NULL);

fail:
   if (sr_isError(res)) {
      /* thr_new failed */
      VG_(cleanup_thread)(&ctst->arch);
      ctst->status = VgTs_Empty;
      /* oops.  Better tell the tool the thread exited in a hurry :-) */
      VG_TRACK( pre_thread_ll_exit, ctid );
   } else {

      POST_MEM_WRITE((Addr)tp.parent_tid, sizeof(long));
      POST_MEM_WRITE((Addr)tp.child_tid, sizeof(long));

      /* Thread creation was successful; let the child have the chance
         to run */
      *flags |= SfYieldAfter;
   }

   /* "Complete" the syscall so that the wrapper doesn't call the kernel again. */
   SET_STATUS_from_SysRes(res);
}

PRE(sys_rfork)
{
   PRINT("sys_rfork ( %#lx )", ARG1 );
   PRE_REG_READ1(long, "rfork", int, flags);

   VG_(message)(Vg_UserMsg, "rfork() not implemented");
   VG_(unimplemented)("Valgrind does not support rfork().");

   SET_STATUS_Failure(VKI_ENOSYS);
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
   ThreadState* tst;
   struct vki_ucontext *uc;
   int rflags;

   PRINT("sys_sigreturn ( %#lx )", ARG1);
   PRE_REG_READ1(long, "sigreturn",
                 struct vki_ucontext *, ucp);

   PRE_MEM_READ( "sigreturn(ucp)", ARG1, sizeof(struct vki_ucontext) );
   PRE_MEM_WRITE( "sigreturn(ucp)", ARG1, sizeof(struct vki_ucontext) );

   vg_assert(VG_(is_valid_tid)(tid));
   vg_assert(tid >= 1 && tid < VG_N_THREADS);
   vg_assert(VG_(is_running_thread)(tid));

   /* Adjust esp to point to start of frame; skip back up over handler
      ret addr */
   tst = VG_(get_ThreadState)(tid);
   tst->arch.vex.guest_RSP -= sizeof(Addr);

   uc = (struct vki_ucontext *)ARG1;
   if (uc == NULL || uc->uc_mcontext.len != sizeof(uc->uc_mcontext)) {
      SET_STATUS_Failure(VKI_EINVAL);
      return;
   }
 
   /* This is only so that the EIP is (might be) useful to report if
      something goes wrong in the sigreturn */
   ML_(fixup_guest_state_to_restart_syscall)(&tst->arch);

   VG_(sigframe_destroy)(tid);

   /* For unclear reasons, it appears we need the syscall to return
      without changing %EAX.  Since %EAX is the return value, and can
      denote either success or failure, we must set up so that the
      driver logic copies it back unchanged.  Also, note %EAX is of
      the guest registers written by VG_(sigframe_destroy). */
   rflags = LibVEX_GuestAMD64_get_rflags(&tst->arch.vex);
   SET_STATUS_from_SysRes( VG_(mk_SysRes_amd64_freebsd)( tst->arch.vex.guest_RAX,
       tst->arch.vex.guest_RDX, (rflags & 1) != 0 ? True : False) );

   /*
    * Signal handler might have changed the signal mask.  Respect that.
    */
   tst->sig_mask = uc->uc_sigmask;
   tst->tmp_sig_mask = uc->uc_sigmask;

   /* Tell the driver not to update the guest state with the "result",
      and set a bogus result to keep it happy. */
   *flags |= SfNoWriteResult;
   SET_STATUS_Success(0);

   /* Check to see if some any signals arose as a result of this. */
   *flags |= SfPollAfter;
}

static void restore_mcontext(ThreadState *tst, struct vki_mcontext *sc)
{
   tst->arch.vex.guest_RAX     = sc->rax;
   tst->arch.vex.guest_RCX     = sc->rcx;
   tst->arch.vex.guest_RDX     = sc->rdx;
   tst->arch.vex.guest_RBX     = sc->rbx;
   tst->arch.vex.guest_RBP     = sc->rbp;
   tst->arch.vex.guest_RSP     = sc->rsp;
   tst->arch.vex.guest_RSI     = sc->rsi;
   tst->arch.vex.guest_RDI     = sc->rdi;
   tst->arch.vex.guest_R8      = sc->r8;
   tst->arch.vex.guest_R9      = sc->r9;
   tst->arch.vex.guest_R10     = sc->r10;
   tst->arch.vex.guest_R11     = sc->r11;
   tst->arch.vex.guest_R12     = sc->r12;
   tst->arch.vex.guest_R13     = sc->r13;
   tst->arch.vex.guest_R14     = sc->r14;
   tst->arch.vex.guest_R15     = sc->r15;
   tst->arch.vex.guest_RIP     = sc->rip;
   /*
    * XXX: missing support for other flags.
    */
   if (sc->rflags & 0x0001)
      LibVEX_GuestAMD64_put_rflag_c(1, &tst->arch.vex);
   else
      LibVEX_GuestAMD64_put_rflag_c(0, &tst->arch.vex);
}

static void fill_mcontext(ThreadState *tst, struct vki_mcontext *sc)
{
   sc->rax = tst->arch.vex.guest_RAX;
   sc->rcx = tst->arch.vex.guest_RCX;
   sc->rdx = tst->arch.vex.guest_RDX;
   sc->rbx = tst->arch.vex.guest_RBX;
   sc->rbp = tst->arch.vex.guest_RBP;
   sc->rsp = tst->arch.vex.guest_RSP;
   sc->rsi = tst->arch.vex.guest_RSI;
   sc->rdi = tst->arch.vex.guest_RDI;
   sc->r8 = tst->arch.vex.guest_R8;
   sc->r9 = tst->arch.vex.guest_R9;
   sc->r10 = tst->arch.vex.guest_R10;
   sc->r11 = tst->arch.vex.guest_R11;
   sc->r12 = tst->arch.vex.guest_R12;
   sc->r13 = tst->arch.vex.guest_R13;
   sc->r14 = tst->arch.vex.guest_R14;
   sc->r15 = tst->arch.vex.guest_R15;
   sc->rip = tst->arch.vex.guest_RIP;
/*
   Not supported by VEX.
   sc->cs = tst->arch.vex.guest_CS;
   sc->ss = tst->arch.vex.guest_SS;
   sc->ds = tst->arch.vex.guest_DS;
   sc->es = tst->arch.vex.guest_ES;
   sc->fs = tst->arch.vex.guest_FS;
   sc->gs = tst->arch.vex.guest_GS;
*/
   sc->rflags = LibVEX_GuestAMD64_get_rflags(&tst->arch.vex);
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
   uc->uc_mcontext.rax = 0;
   uc->uc_mcontext.rdx = 0;
   uc->uc_mcontext.rflags &= ~0x0001;	/* PSL_C */
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
   oucp->uc_mcontext.rax = 0;
   oucp->uc_mcontext.rdx = 0;
   oucp->uc_mcontext.rflags &= ~0x0001;	/* PSL_C */
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
/*              ARG1           ARG2       ARG3      ARG4       ARG5    ARG6     ARG7 */

PRE(sys_mmap)
{
   SysRes r;

   PRINT("sys_mmap ( %#lx, %lu, %ld, %ld, %ld, pad%ld, 0x%lx)",
         ARG1, (UWord)ARG2, ARG3, ARG4, ARG5, ARG6, ARG7 );
   PRE_REG_READ7(long, "mmap",
                 char *, addr, unsigned long, len, int, prot,  int, flags,
                 int, fd,  int, pad, unsigned long, pos);

   r = ML_(generic_PRE_sys_mmap)( tid, ARG1, ARG2, ARG3, ARG4, ARG5, ARG7 );
   SET_STATUS_from_SysRes(r);
}

/* FreeBSD-7 introduces a "regular" version of mmap etc. */
PRE(sys_mmap7)
{
   SysRes r;

   PRINT("sys_mmap ( %#lx, %lu, %ld, %ld, %ld, 0x%lx)",
         ARG1, (UWord)ARG2, ARG3, ARG4, ARG5, ARG6 );
   PRE_REG_READ6(long, "mmap",
                 char *, addr, unsigned long, len, int, prot,  int, flags,
                 int, fd,  unsigned long, pos);

   r = ML_(generic_PRE_sys_mmap)( tid, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6 );
   SET_STATUS_from_SysRes(r);
}

PRE(sys_lseek)
{
   PRINT("sys_lseek ( %ld, 0x%lx, %#lx, %ld )", ARG1,ARG2,ARG3,ARG4);
   PRE_REG_READ4(long, "lseek",
                 unsigned int, fd, int, pad, unsigned long, offset,
                 unsigned int, whence);
}

PRE(sys_lseek7)
{
   PRINT("sys_lseek ( %ld, 0x%lx, %ld )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "lseek",
                 unsigned int, fd, unsigned long, offset,
                 unsigned int, whence);
}

PRE(sys_pread)
{
   *flags |= SfMayBlock;
   PRINT("sys_read ( %ld, %#lx, %lu, %lu, %lu )", ARG1, ARG2, ARG3, ARG4, ARG5);
   PRE_REG_READ5(ssize_t, "read",
                 unsigned int, fd, char *, buf, vki_size_t, count,
                 int, pad, unsigned long, off);

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
   PRINT("sys_read ( %ld, %#lx, %lu, %lu )", ARG1, ARG2, ARG3, ARG4);
   PRE_REG_READ4(ssize_t, "read",
                 unsigned int, fd, char *, buf, vki_size_t, count,
                 unsigned long, off);

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
   PRINT("sys_write ( %ld, %#lx, %lu, %lu, %lu )", ARG1, ARG2, ARG3, ARG4, ARG5);
   PRE_REG_READ5(ssize_t, "write",
                 unsigned int, fd, const char *, buf, vki_size_t, count,
                 int, pad, unsigned long, off);
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
   PRINT("sys_write ( %ld, %#lx, %lu, %lu )", ARG1, ARG2, ARG3, ARG4);
   PRE_REG_READ4(ssize_t, "write",
                 unsigned int, fd, const char *, buf, vki_size_t, count,
                 unsigned long, off);
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
   PRINT("sys_ftruncate ( %ld, %lu )", ARG1,ARG3);
   PRE_REG_READ3(long, "ftruncate", unsigned int, fd, int, pad,
		  unsigned int, length);
}

PRE(sys_ftruncate7)
{
   *flags |= SfMayBlock;
   PRINT("sys_ftruncate ( %ld, %lu )", ARG1,ARG2);
   PRE_REG_READ2(long, "ftruncate", unsigned int, fd,
		  unsigned long, length);
}

PRE(sys_truncate)
{
   *flags |= SfMayBlock;
   PRINT("sys_truncate ( %#lx(%s), %lu )", ARG1,(char *)ARG1,ARG3);
   PRE_REG_READ3(long, "truncate",
                 const char *, path, int, pad, unsigned int, length);
   PRE_MEM_RASCIIZ( "truncate(path)", ARG1 );
}

PRE(sys_truncate7)
{
   *flags |= SfMayBlock;
   PRINT("sys_truncate ( %#lx(%s), %lu )", ARG1,(char *)ARG1,ARG2);
   PRE_REG_READ2(long, "truncate",
                 const char *, path, unsigned long, length);
   PRE_MEM_RASCIIZ( "truncate(path)", ARG1 );
}

PRE(sys_sysarch)
{
   ThreadState *tst;
   void **p;

   PRINT("sys_sysarch ( %ld, %#lx )", ARG1, ARG2);
   PRE_REG_READ2(int, "sysarch",
                 int, number, void *, args);
   switch (ARG1) {
   case VKI_AMD64_SET_FSBASE:
      PRINT("sys_amd64_set_fsbase ( %#lx )", ARG2);
      PRE_REG_READ1(long, "amd64_set_fsbase", void *, base)

      /* On FreeBSD, the syscall loads the %gs selector for us, so do it now. */
      tst = VG_(get_ThreadState)(tid);
      p = (void**)ARG2;
      tst->arch.vex.guest_FS_ZERO = (UWord)*p;
      /* "do" the syscall ourselves; the kernel never sees it */
      SET_STATUS_Success2((ULong)*p, tst->arch.vex.guest_RDX );

      break;
   case VKI_AMD64_GET_FSBASE:
      PRINT("sys_amd64_get_fsbase ( %#lx )", ARG2);
      PRE_REG_READ1(int, "amd64_get_fsbase", void *, basep)
      PRE_MEM_WRITE( "amd64_get_fsbase(basep)", ARG2, sizeof(void *) );

      /* "do" the syscall ourselves; the kernel never sees it */
      tst = VG_(get_ThreadState)(tid);
      SET_STATUS_Success2( tst->arch.vex.guest_FS_ZERO, tst->arch.vex.guest_RDX );
      POST_MEM_WRITE( ARG2, sizeof(void *) );
      break;
   default:
      VG_(message) (Vg_UserMsg, "unhandled sysarch cmd %ld", ARG1);
      VG_(unimplemented) ("unhandled sysarch cmd");
      break;
   }
}

#undef PRE
#undef POST

#endif /* defined(VGP_amd64_freebsd) */

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
