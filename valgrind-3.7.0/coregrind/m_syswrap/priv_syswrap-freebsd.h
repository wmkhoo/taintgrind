
/*--------------------------------------------------------------------*/
/*--- FreeBSD-specific syscalls stuff.          priv_syswrap-freebsd.h ---*/
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

#ifndef __PRIV_SYSWRAP_FREEBSD_H
#define __PRIV_SYSWRAP_FREEBSD_H

/* requires #include "priv_types_n_macros.h" */

// Clone-related functions
extern Word ML_(start_thread_NORETURN) ( void* arg );
extern Addr ML_(allocstack)            ( ThreadId tid );
extern void ML_(call_on_new_stack_0_1) ( Addr stack, Addr retaddr,
			                 void (*f)(Word), Word arg1 );
extern SysRes ML_(do_fork) ( ThreadId tid );
extern SysRes ML_(do_vfork) ( ThreadId tid );
extern SysRes ML_(do_rfork) ( ThreadId tid, Int flags );


DECL_TEMPLATE(freebsd, sys_syscall);
DECL_TEMPLATE(freebsd, sys_exit);
DECL_TEMPLATE(freebsd, sys_getfsstat4);
DECL_TEMPLATE(freebsd, sys_getfsstat);
DECL_TEMPLATE(freebsd, sys_mount);
DECL_TEMPLATE(freebsd, sys_unmount);
DECL_TEMPLATE(freebsd, sys_ptrace);
DECL_TEMPLATE(freebsd, sys_recvmsg);
DECL_TEMPLATE(freebsd, sys_sendmsg);
DECL_TEMPLATE(freebsd, sys_recvfrom);
DECL_TEMPLATE(freebsd, sys_accept);
DECL_TEMPLATE(freebsd, sys_getpeername);
DECL_TEMPLATE(freebsd, sys_getsockname);
DECL_TEMPLATE(freebsd, sys_chflags);
DECL_TEMPLATE(freebsd, sys_fchflags);
DECL_TEMPLATE(freebsd, sys_pipe);
DECL_TEMPLATE(freebsd, sys_ktrace);
DECL_TEMPLATE(freebsd, sys_getlogin);
DECL_TEMPLATE(freebsd, sys_setlogin);
DECL_TEMPLATE(freebsd, sys_reboot);
DECL_TEMPLATE(freebsd, sys_revoke);
DECL_TEMPLATE(freebsd, sys_sbrk);
DECL_TEMPLATE(freebsd, sys_sstk);
DECL_TEMPLATE(freebsd, sys_swapon);
DECL_TEMPLATE(freebsd, sys_getdtablesize);
DECL_TEMPLATE(freebsd, sys_socket);
DECL_TEMPLATE(freebsd, sys_connect);
DECL_TEMPLATE(freebsd, sys_bind);
DECL_TEMPLATE(freebsd, sys_setsockopt);
DECL_TEMPLATE(freebsd, sys_listen);
DECL_TEMPLATE(freebsd, sys_getsockopt);
DECL_TEMPLATE(freebsd, sys_mkfifo);
DECL_TEMPLATE(freebsd, sys_sendto);
DECL_TEMPLATE(freebsd, sys_shutdown);
DECL_TEMPLATE(freebsd, sys_socketpair);
DECL_TEMPLATE(freebsd, sys_adjtime);
DECL_TEMPLATE(freebsd, sys_quotactl);
DECL_TEMPLATE(freebsd, sys_nfssvc);
DECL_TEMPLATE(freebsd, sys_getfh);
DECL_TEMPLATE(freebsd, sys_getdomainname);
DECL_TEMPLATE(freebsd, sys_setdomainname);
DECL_TEMPLATE(freebsd, sys_uname);
DECL_TEMPLATE(freebsd, sys_sysarch);
DECL_TEMPLATE(freebsd, sys_rtprio);
DECL_TEMPLATE(freebsd, sys_semsys);
DECL_TEMPLATE(freebsd, sys_msgsys);
DECL_TEMPLATE(freebsd, sys_shmsys);
DECL_TEMPLATE(freebsd, sys_pread);
DECL_TEMPLATE(freebsd, sys_pwrite);
DECL_TEMPLATE(freebsd, sys_ntp_adjtime);
DECL_TEMPLATE(freebsd, sys_setegid);
DECL_TEMPLATE(freebsd, sys_seteuid);
DECL_TEMPLATE(freebsd, sys_stat);
DECL_TEMPLATE(freebsd, sys_fstat);
DECL_TEMPLATE(freebsd, sys_lstat);
DECL_TEMPLATE(freebsd, sys_pathconf);
DECL_TEMPLATE(freebsd, sys_fpathconf);
DECL_TEMPLATE(freebsd, sys_getdirentries);
DECL_TEMPLATE(freebsd, sys_mmap);
DECL_TEMPLATE(freebsd, sys___syscall);
DECL_TEMPLATE(freebsd, sys_lseek);
DECL_TEMPLATE(freebsd, sys_truncate);
DECL_TEMPLATE(freebsd, sys_ftruncate);
DECL_TEMPLATE(freebsd, sys___sysctl);
DECL_TEMPLATE(freebsd, sys_undelete);
DECL_TEMPLATE(freebsd, sys_futimes);
DECL_TEMPLATE(freebsd, sys_nfs_fhopen);
DECL_TEMPLATE(freebsd, sys___semctl7);
DECL_TEMPLATE(freebsd, sys___semctl);
DECL_TEMPLATE(freebsd, sys_semget);
DECL_TEMPLATE(freebsd, sys_semop);
DECL_TEMPLATE(freebsd, sys_msgctl);
DECL_TEMPLATE(freebsd, sys_msgget);
DECL_TEMPLATE(freebsd, sys_msgsnd);
DECL_TEMPLATE(freebsd, sys_msgrcv);
DECL_TEMPLATE(freebsd, sys_shmat);
DECL_TEMPLATE(freebsd, sys_shmctl);
DECL_TEMPLATE(freebsd, sys_shmctl7);
DECL_TEMPLATE(freebsd, sys_shmdt);
DECL_TEMPLATE(freebsd, sys_shmget);
DECL_TEMPLATE(freebsd, sys_clock_gettime);
DECL_TEMPLATE(freebsd, sys_clock_settime);
DECL_TEMPLATE(freebsd, sys_clock_getres);
DECL_TEMPLATE(freebsd, sys_minherit);
DECL_TEMPLATE(freebsd, sys_rfork);
DECL_TEMPLATE(freebsd, sys_issetugid);
DECL_TEMPLATE(freebsd, sys_lchmod);
DECL_TEMPLATE(freebsd, sys_lutimes);
DECL_TEMPLATE(freebsd, sys_netbsd_msync);
DECL_TEMPLATE(freebsd, sys_nstat);
DECL_TEMPLATE(freebsd, sys_nfstat);
DECL_TEMPLATE(freebsd, sys_nlstat);
DECL_TEMPLATE(freebsd, sys_fhstatfs);
DECL_TEMPLATE(freebsd, sys_fhopen);
DECL_TEMPLATE(freebsd, sys_fhstat);
DECL_TEMPLATE(freebsd, sys_modnext);
DECL_TEMPLATE(freebsd, sys_modstat);
DECL_TEMPLATE(freebsd, sys_modfnext);
DECL_TEMPLATE(freebsd, sys_modfind);
DECL_TEMPLATE(freebsd, sys_kldload);
DECL_TEMPLATE(freebsd, sys_kldunload);
DECL_TEMPLATE(freebsd, sys_kldfind);
DECL_TEMPLATE(freebsd, sys_kldnext);
DECL_TEMPLATE(freebsd, sys_kldstat);
DECL_TEMPLATE(freebsd, sys_kldfirstmod);
DECL_TEMPLATE(freebsd, sys_setresuid);
DECL_TEMPLATE(freebsd, sys_setresgid);
DECL_TEMPLATE(freebsd, sys_aio_return);
DECL_TEMPLATE(freebsd, sys_aio_suspend);
DECL_TEMPLATE(freebsd, sys_aio_cancel);
DECL_TEMPLATE(freebsd, sys_aio_error);
DECL_TEMPLATE(freebsd, sys_aio_read);
DECL_TEMPLATE(freebsd, sys_aio_write);
DECL_TEMPLATE(freebsd, sys_lio_listio);
DECL_TEMPLATE(freebsd, sys_yield);
DECL_TEMPLATE(freebsd, sys_thr_sleep);
DECL_TEMPLATE(freebsd, sys_thr_wakeup);
DECL_TEMPLATE(freebsd, sys_munlockall);
DECL_TEMPLATE(freebsd, sys___getcwd);
DECL_TEMPLATE(freebsd, sys_sched_setparam);
DECL_TEMPLATE(freebsd, sys_sched_getparam);
DECL_TEMPLATE(freebsd, sys_sched_setscheduler);
DECL_TEMPLATE(freebsd, sys_sched_getscheduler);
DECL_TEMPLATE(freebsd, sys_sched_yield);
DECL_TEMPLATE(freebsd, sys_sched_get_priority_max);
DECL_TEMPLATE(freebsd, sys_sched_get_priority_min);
DECL_TEMPLATE(freebsd, sys_sched_rr_get_interval);
DECL_TEMPLATE(freebsd, sys_utrace);
DECL_TEMPLATE(freebsd, sys_kldsym);
DECL_TEMPLATE(freebsd, sys_jail);
DECL_TEMPLATE(freebsd, sys_sigprocmask);
DECL_TEMPLATE(freebsd, sys_sigsuspend);
DECL_TEMPLATE(freebsd, sys_sigaction);
DECL_TEMPLATE(freebsd, sys_sigpending);
DECL_TEMPLATE(freebsd, sys_sigreturn);
DECL_TEMPLATE(freebsd, sys_fake_sigreturn);
DECL_TEMPLATE(freebsd, sys_sigtimedwait);
DECL_TEMPLATE(freebsd, sys_sigwaitinfo);
DECL_TEMPLATE(freebsd, sys_getcontext);
DECL_TEMPLATE(freebsd, sys_setcontext);
DECL_TEMPLATE(freebsd, sys_swapcontext);
DECL_TEMPLATE(freebsd, sys___acl_get_file);
DECL_TEMPLATE(freebsd, sys___acl_set_file);
DECL_TEMPLATE(freebsd, sys___acl_get_fd);
DECL_TEMPLATE(freebsd, sys___acl_set_fd);
DECL_TEMPLATE(freebsd, sys___acl_delete_file);
DECL_TEMPLATE(freebsd, sys___acl_delete_fd);
DECL_TEMPLATE(freebsd, sys___acl_aclcheck_file);
DECL_TEMPLATE(freebsd, sys___acl_aclcheck_fd);
DECL_TEMPLATE(freebsd, sys___acl_get_link);
DECL_TEMPLATE(freebsd, sys___acl_set_link);
DECL_TEMPLATE(freebsd, sys___acl_delete_link);
DECL_TEMPLATE(freebsd, sys___acl_aclcheck_link);
DECL_TEMPLATE(freebsd, sys_extattrctl);
DECL_TEMPLATE(freebsd, sys_extattr_set_file);
DECL_TEMPLATE(freebsd, sys_extattr_get_file);
DECL_TEMPLATE(freebsd, sys_extattr_delete_file);
DECL_TEMPLATE(freebsd, sys_aio_waitcomplete);
DECL_TEMPLATE(freebsd, sys_getresuid);
DECL_TEMPLATE(freebsd, sys_getresgid);
DECL_TEMPLATE(freebsd, sys_kqueue);
DECL_TEMPLATE(freebsd, sys_kevent);
DECL_TEMPLATE(freebsd, sys_sendfile);
DECL_TEMPLATE(freebsd, sys_statfs6);
DECL_TEMPLATE(freebsd, sys_fstatfs6);
DECL_TEMPLATE(freebsd, sys_fhstatfs6);
DECL_TEMPLATE(freebsd, sys_thr_exit);
DECL_TEMPLATE(freebsd, sys_thr_self);
DECL_TEMPLATE(freebsd, sys_thr_set_name);
DECL_TEMPLATE(freebsd, sys_rtprio_thread);
DECL_TEMPLATE(freebsd, sys_fork);
DECL_TEMPLATE(freebsd, sys_vfork);
DECL_TEMPLATE(freebsd, sys_modfind);
DECL_TEMPLATE(freebsd, sys_modstat);
DECL_TEMPLATE(freebsd, sys_lkmnosys0);
DECL_TEMPLATE(freebsd, sys_lkmnosys1);
DECL_TEMPLATE(freebsd, sys_lkmnosys2);
DECL_TEMPLATE(freebsd, sys_lkmnosys3);
DECL_TEMPLATE(freebsd, sys_lkmnosys4);
DECL_TEMPLATE(freebsd, sys_lkmnosys5);
DECL_TEMPLATE(freebsd, sys_lkmnosys6);
DECL_TEMPLATE(freebsd, sys_lkmnosys7);
DECL_TEMPLATE(freebsd, sys_lkmnosys8);
DECL_TEMPLATE(freebsd, sys_sigaction4);
DECL_TEMPLATE(freebsd, sys_mmap7);
DECL_TEMPLATE(freebsd, sys_lseek7);
DECL_TEMPLATE(freebsd, sys_truncate7);
DECL_TEMPLATE(freebsd, sys_ftruncate7);
DECL_TEMPLATE(freebsd, sys_pread7);
DECL_TEMPLATE(freebsd, sys_pwrite7);
DECL_TEMPLATE(freebsd, sys__umtx_op);
DECL_TEMPLATE(freebsd, sys__umtx_lock);
DECL_TEMPLATE(freebsd, sys__umtx_unlock);
DECL_TEMPLATE(freebsd, sys_thr_kill2);
DECL_TEMPLATE(freebsd, sys_shm_open);
DECL_TEMPLATE(freebsd, sys_shm_unlink);
DECL_TEMPLATE(freebsd, sys_eaccess);
DECL_TEMPLATE(freebsd, sys_cpuset);
DECL_TEMPLATE(freebsd, sys_cpuset_setid);
DECL_TEMPLATE(freebsd, sys_cpuset_getid);
DECL_TEMPLATE(freebsd, sys_cpuset_getaffinity);
DECL_TEMPLATE(freebsd, sys_cpuset_setaffinity);
DECL_TEMPLATE(freebsd, sys_faccessat);
DECL_TEMPLATE(freebsd, sys_fchmodat);
DECL_TEMPLATE(freebsd, sys_fchownat);
DECL_TEMPLATE(freebsd, sys_fexecve);
DECL_TEMPLATE(freebsd, sys_fstatat);
DECL_TEMPLATE(freebsd, sys_futimesat);
DECL_TEMPLATE(freebsd, sys_linkat);
DECL_TEMPLATE(freebsd, sys_mkdirat);
DECL_TEMPLATE(freebsd, sys_mkfifoat);
DECL_TEMPLATE(freebsd, sys_mknodat);
DECL_TEMPLATE(freebsd, sys_openat);
DECL_TEMPLATE(freebsd, sys_readlinkat);
DECL_TEMPLATE(freebsd, sys_renameat);
DECL_TEMPLATE(freebsd, sys_symlinkat);
DECL_TEMPLATE(freebsd, sys_unlinkat);
DECL_TEMPLATE(freebsd, sys_posix_openpt);
DECL_TEMPLATE(freebsd, sys_kenv);
DECL_TEMPLATE(freebsd, sys_uuidgen);
DECL_TEMPLATE(freebsd, sys_thr_new);
DECL_TEMPLATE(freebsd, sys_thr_kill);
DECL_TEMPLATE(freebsd, sys_thr_kill2);
DECL_TEMPLATE(freebsd, sys_fcntl);
DECL_TEMPLATE(freebsd, sys_ioctl);
#endif   // __PRIV_SYSWRAP_FREEBSD_H

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
