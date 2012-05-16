
/*--------------------------------------------------------------------*/
/*--- Dumping core.                         coredump-x86-freebsd.c ---*/
/*--------------------------------------------------------------------*/
 
/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2008 Julian Seward 
      jseward@acm.org

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

#include "pub_core_basics.h"
#include "pub_core_vki.h"
#include "pub_core_libcbase.h"
#include "pub_core_coredump.h"
#include "pub_core_threadstate.h"

#include "priv_elf.h"

void ML_(fill_elfregs_from_tst)(struct vki_user_regs_struct* regs, 
                                const ThreadArchState* arch)
{
   regs->eflags = LibVEX_GuestX86_get_eflags( &((ThreadArchState*)arch)->vex );
   regs->esp    = arch->vex.guest_ESP;
   regs->eip    = arch->vex.guest_EIP;

   regs->ebx    = arch->vex.guest_EBX;
   regs->ecx    = arch->vex.guest_ECX;
   regs->edx    = arch->vex.guest_EDX;
   regs->esi    = arch->vex.guest_ESI;
   regs->edi    = arch->vex.guest_EDI;
   regs->ebp    = arch->vex.guest_EBP;
   regs->eax    = arch->vex.guest_EAX;

   regs->cs     = arch->vex.guest_CS;
   regs->ds     = arch->vex.guest_DS;
   regs->ss     = arch->vex.guest_SS;
   regs->es     = arch->vex.guest_ES;
   regs->fs     = arch->vex.guest_FS;
   regs->gs     = arch->vex.guest_GS;
}

void ML_(fill_elffpregs_from_tst)(vki_elf_fpregset_t* fpu,
                                  const ThreadArchState* arch)
{
}

void ML_(fill_elffpxregs_from_tst)(vki_elf_fpxregset_t* xfpu,
                                   const ThreadArchState* arch)
{
   VG_(memset)(&xfpu->sv_xmm, 0, sizeof(xfpu->sv_xmm));
#  define DO(n)  VG_(memcpy)(&xfpu->sv_xmm + n * 4, &arch->vex.guest_XMM##n, sizeof(arch->vex.guest_XMM##n))
   DO(0);  DO(1);  DO(2);  DO(3);  DO(4);  DO(5);  DO(6);  DO(7);
#  undef DO
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
