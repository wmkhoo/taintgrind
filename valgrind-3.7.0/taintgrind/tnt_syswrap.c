
/*--------------------------------------------------------------------*/
/*--- Wrappers for tainting syscalls                               ---*/
/*---                                                tnt_syswrap.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Tainter, a Valgrind tool for
   tracking marked/tainted data through memory.

   Copyright (C) 2010 Wei Ming Khoo
   wmk26@cam.ac.uk

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

#include "pub_tool_basics.h"
#include "pub_tool_vki.h"
#include "pub_tool_vkiscnums.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_machine.h"
#include "pub_tool_aspacemgr.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_stacktrace.h"   // for VG_(get_and_pp_StackTrace)

#include "valgrind.h"

#include "tnt_include.h"

#define MAX_PATH 256
static
void resolve_fd(UWord fd, Char *path, Int max) 
{
   Char src[MAX_PATH];
   Int len = 0;

   // TODO: Cache resolved fds by also catching open()s and close()s
   VG_(sprintf)(src, "/proc/%d/fd/%d", VG_(getpid)(), (int)fd);
   len = VG_(readlink)(src, path, max);

   // Just give emptiness on error.
   if (len == -1) len = 0;
   path[len] = '\0';
}

/* enforce an arbitrary maximum */
#define MAXIMUM_FDS 256
static Bool tainted_fds[VG_N_THREADS][MAXIMUM_FDS];
static UInt read_offset = 0;

void TNT_(syscall_llseek)(ThreadId tid, UWord* args, UInt nArgs,
                                  SysRes res) {
// int  _llseek(int fildes, ulong offset_high, ulong offset_low, loff_t *result,, uint whence);
   Int   fd           = args[0];
   ULong offset_high  = args[1];
   ULong offset_low   = args[2];
   UInt  result       = args[3];
   UInt  whence       = args[4];
   ULong offset;

   if (fd >= MAXIMUM_FDS || tainted_fds[tid][fd] == False)
      return;

   VG_(printf)("syscall _llseek %d %d ", tid, fd);
   VG_(printf)("0x%x 0x%x 0x%x 0x%x\n", (UInt)offset_high, (UInt)offset_low, result, whence);

   offset = (offset_high<<32) | offset_low;

   if( whence == 0/*SEEK_SET*/ )
      read_offset = 0 + (UInt)offset;
   else if( whence == 1/*SEEK_CUR*/ )
      read_offset += (UInt)offset;
   else //if( whence == 2/*SEEK_END*/ )
      tl_assert(0);
}

Bool TNT_(syscall_allowed_check)(ThreadId tid, int syscallno) {
	if (in_sandbox && !allowed_syscalls[syscallno]) {
		HChar fnname[128];
		UInt pc = VG_(get_IP)(tid);
		VG_(describe_IP) ( pc, fnname, 128 );
		char* just_fnname = VG_(strstr)(fnname, ":");
		just_fnname += 2;
//		VALGRIND_PRINTF_BACKTRACE("*** Thread %d performed system call %s (%d) in method %s, but it is not allowed to. ***\n\n", tid, syscallnames[syscallno], syscallno, just_fnname);
		VG_(printf)("*** Thread %d performed system call %s (%d) in a sandbox, but it is not allowed to. ***\n", tid, syscallnames[syscallno], syscallno);
		VG_(get_and_pp_StackTrace)(tid, STACK_TRACE_SIZE);
		VG_(printf)("\n");
		return False;
	}
	return True;
}

void TNT_(syscall_read)(ThreadId tid, UWord* args, UInt nArgs,
                                  SysRes res) {
// ssize_t  read(int fildes, void *buf, size_t nbyte);
   Int   fd           = args[0];
   Char *data         = (Char *)args[1];
   UInt  curr_offset  = read_offset;
   Int   curr_len     = sr_Res(res);
   UInt  taint_offset = TNT_(clo_taint_start);
   Int   taint_len    = TNT_(clo_taint_len);
   UWord addr;
   Int   len;
   Int   i;

   if (in_sandbox) {
	   if (shared_fds[fd] != fd) {
		   HChar fdpath[MAX_PATH];
		   VG_(resolve_filename)(fd, fdpath, MAX_PATH-1);
		   HChar fnname[128];
		   UInt pc = VG_(get_IP)(tid);
		   VG_(describe_IP) ( pc, fnname, 128 );
		   char* just_fnname = VG_(strstr)(fnname, ":");
		   just_fnname += 2;
           VG_(printf)("*** Thread %d read from %s (fd: %d) in method %s, but it is not allowed to. ***\n", tid, fdpath, fd, just_fnname);
           VG_(get_and_pp_StackTrace)(tid, STACK_TRACE_SIZE);
           VG_(printf)("\n");
		   return;
	   }
   }

   if (curr_len == 0) return;

   TNT_(make_mem_defined)( (UWord)data, curr_len );

   if (fd >= MAXIMUM_FDS || tainted_fds[tid][fd] == False)
      return;

   if(1){
      //VG_(printf)("taint_offset: 0x%x\ttaint_len: 0x%x\n", taint_offset, taint_len);
      //VG_(printf)("curr_offset : 0x%x\tcurr_len : 0x%x\n", curr_offset, curr_len);
      VG_(printf)("syscall read %d %d ", tid, fd);
      VG_(printf)("0x%x 0x%x 0x%x 0x%x\n", curr_offset, curr_len, (Int)data,
          *(Char *)data);
   }

   if( TNT_(clo_taint_all) ){
      // Turn instrumentation on
      TNT_(instrument_start) = True;
      addr = (UWord)data;
      len  = curr_len;
   }else

   /* Here we determine what bytes to taint
      We have 4 variables -
      taint_offset    Starting file offset to taint
      taint_len       Number of bytes to taint
      curr_offset     Starting file offset currently read
      curr_len        Number of bytes currently read
      We have to deal with 4 cases: (= refers to the region to be tainted)
      Case 1:
                          taint_len
      taint_offset   |-----------------|
                          curr_len
      curr_offset |---=================---|
      Case 2:
                          taint_len
      taint_offset   |-----------------------|
                          curr_len
      curr_offset |---====================|
      Case 3:
                          taint_len
      taint_offset |----------------------|
                          curr_len
      curr_offset    |====================---|
      Case 4:
                          taint_len
      taint_offset |-----------------------|
                          curr_len
      curr_offset    |====================|
   */

   if( taint_offset >= curr_offset &&
       taint_offset <= curr_offset + curr_len ){
       if( (taint_offset + taint_len) <= (curr_offset + curr_len) ){
         // Case 1
         // Turn instrumentation on
         TNT_(instrument_start) = True;
         addr = (UWord)(data + taint_offset - curr_offset);
         len  = taint_len;
      }else{
          // Case 2
          TNT_(instrument_start) = True;
          addr = (UWord)(data + taint_offset - curr_offset);
          len  = curr_len - taint_offset + curr_offset;
      }

   }else if( ( ( taint_offset + taint_len ) >= curr_offset ) &&
             ( ( taint_offset + taint_len ) <= (curr_offset + curr_len ) ) ){
      // Case 3
      TNT_(instrument_start) = True;
      addr = (UWord)data;
      len  = taint_len - curr_offset + taint_offset;
   }else if( ( taint_offset <= curr_offset ) &&
       ( taint_offset + taint_len ) >= ( curr_offset + curr_len ) ){
      // Case 4
      TNT_(instrument_start) = True;
      addr = (UWord)data;
      len  = curr_len;
   }else{
      // Update file position
      read_offset += curr_len;
      return;
   }

   TNT_(make_mem_tainted)( addr, len );
//   if(isPread)
//      VG_(printf)("syscall pread %d %d ", tid, fd);
//   else
//      VG_(printf)("syscall read %d %d ", tid, fd);
//   VG_(printf)("0x%x 0x%x 0x%x 0x%x\n", curr_offset, curr_len, (Int)data, len);

   for( i=0; i<len; i++) 
      VG_(printf)("taint_byte 0x%08lx 0x%x\n", addr+i, *(Char *)(addr+i));

   // Update file position
   read_offset += curr_len;
}

void TNT_(syscall_pread)(ThreadId tid, UWord* args, UInt nArgs,
                                  SysRes res) {
// ssize_t pread(int fildes, void *buf, size_t nbyte, size_t offset);
   Int   fd           = args[0];
   Char *data         = (Char *)args[1];
   UInt  curr_offset  = (Int)args[3];
   Int   curr_len     = sr_Res(res);
   UInt  taint_offset = TNT_(clo_taint_start);
   Int   taint_len    = TNT_(clo_taint_len);
   UWord addr;
   Int   len;
   Int   i;

   if (curr_len == 0) return;

   TNT_(make_mem_defined)( (UWord)data, curr_len );

   if (fd >= MAXIMUM_FDS || tainted_fds[tid][fd] == False)
      return;

   if(1){
      //VG_(printf)("taint_offset: 0x%x\ttaint_len: 0x%x\n", taint_offset, taint_len);
      //VG_(printf)("curr_offset : 0x%x\tcurr_len : 0x%x\n", curr_offset, curr_len);
      VG_(printf)("syscall pread %d %d ", tid, fd);
      VG_(printf)("0x%x 0x%x 0x%x\n", curr_offset, curr_len, (Int)data);
   }

   if( TNT_(clo_taint_all) ){
      // Turn instrumentation on
      TNT_(instrument_start) = True;
      addr = (UWord)data;
      len  = curr_len;
   }else

   /* Here we determine what bytes to taint
      We have 4 variables -
      taint_offset    Starting file offset to taint
      taint_len       Number of bytes to taint
      curr_offset     Starting file offset currently read
      curr_len        Number of bytes currently read
      We have to deal with 4 cases: (= refers to the region to be tainted)
      Case 1:
                          taint_len
      taint_offset   |-----------------|
                          curr_len
      curr_offset |---=================---|
      Case 2:
                          taint_len
      taint_offset   |-----------------------|
                          curr_len
      curr_offset |---====================|
      Case 3:
                          taint_len
      taint_offset |----------------------|
                          curr_len
      curr_offset    |====================---|
      Case 4:
                          taint_len
      taint_offset |-----------------------|
                          curr_len
      curr_offset    |====================|
   */

   if( taint_offset >= curr_offset &&
       taint_offset <= curr_offset + curr_len ){
       if( (taint_offset + taint_len) <= (curr_offset + curr_len) ){
         // Case 1
         // Turn instrumentation on
         TNT_(instrument_start) = True;
         addr = (UWord)(data + taint_offset - curr_offset);
         len  = taint_len;
      }else{
          // Case 2
          TNT_(instrument_start) = True;
          addr = (UWord)(data + taint_offset - curr_offset);
          len  = curr_len - taint_offset + curr_offset;
      }

   }else if( ( ( taint_offset + taint_len ) >= curr_offset ) &&
             ( ( taint_offset + taint_len ) <= (curr_offset + curr_len ) ) ){
      // Case 3
      TNT_(instrument_start) = True;
      addr = (UWord)data;
      len  = taint_len - curr_offset + taint_offset;
   }else if( ( taint_offset <= curr_offset ) &&
       ( taint_offset + taint_len ) >= ( curr_offset + curr_len ) ){
      // Case 4
      TNT_(instrument_start) = True;
      addr = (UWord)data;
      len  = curr_len;
   }else{
      return;
   }

   TNT_(make_mem_tainted)( addr, len );
//   if(isPread)
//      VG_(printf)("syscall pread %d %d ", tid, fd);
//   else
//      VG_(printf)("syscall read %d %d ", tid, fd);
//   VG_(printf)("0x%x 0x%x 0x%x 0x%x\n", curr_offset, curr_len, (Int)data, len);

   for( i=0; i<len; i++) 
      VG_(printf)("taint_byte 0x%08lx 0x%x\n", addr+i, *(Char *)(addr+i));
}

void TNT_(syscall_open)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
//  int open (const char *filename, int flags[, mode_t mode])
   HChar fdpath[MAX_PATH];
   Int fd = sr_Res(res);

   // check if we have already forked a sandbox
   if (shared_open) {
	   shared_open = 0;
   }
   else if (have_forked_sandbox && !in_sandbox) {
	   UInt pc = VG_(get_IP)(tid);
	   HChar fnname[128];
	   VG_(describe_IP) ( pc, fnname, 128 );
	   char* just_fnname = VG_(strstr)(fnname, ":");
	   just_fnname += 2;
	   VG_(printf)("*** Thread %d opened a file after the sandbox was created, hence it will not be accessible to the sandbox. Please annotate it. ***\n", tid, just_fnname);
	   VG_(get_and_pp_StackTrace)(tid, STACK_TRACE_SIZE);
	   VG_(printf)("\n");
   }

    // Nothing to do if no file tainting
    if ( VG_(strlen)( TNT_(clo_file_filter)) == 0 )
        return;

    if (fd > -1 && fd < MAXIMUM_FDS) {

        //resolve_fd(fd, fdpath, MAX_PATH-1);
	VG_(resolve_filename)(fd, fdpath, MAX_PATH-1);

        if( TNT_(clo_taint_all) ){
            // Turn instrumentation on
            TNT_(instrument_start) = True;


            tainted_fds[tid][fd] = True;
            VG_(printf)("syscall open %d %s %lx %d\n", tid, fdpath, args[1], fd);
            read_offset = 0;

        } else if ( VG_(strncmp)(fdpath, TNT_(clo_file_filter), 
                            VG_(strlen)( TNT_(clo_file_filter))) == 0 ) {
            // Turn instrumentation on
            TNT_(instrument_start) = True;

            tainted_fds[tid][fd] = True;
            VG_(printf)("syscall open %d %s %lx %d\n", tid, fdpath, args[1], fd);
            read_offset = 0;

        } else if ( TNT_(clo_file_filter)[0] == '*' &&
            VG_(strncmp)( fdpath + VG_(strlen)(fdpath) 
                        - VG_(strlen)( TNT_(clo_file_filter) ) + 1, 
                          TNT_(clo_file_filter) + 1, 
                          VG_(strlen)( TNT_(clo_file_filter)) - 1 ) == 0 ) {
            // Turn instrumentation on
            TNT_(instrument_start) = True;

            tainted_fds[tid][fd] = True;
            VG_(printf)("syscall open %d %s %lx %d\n", tid, fdpath, args[1], fd);
            read_offset = 0;
        } else
            tainted_fds[tid][fd] = False;
    }
}

void TNT_(syscall_close)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
//   int close (int filedes)
   Int fd = args[0];

   if (fd > -1 && fd < MAXIMUM_FDS){
     if (tainted_fds[tid][fd] == True)
         VG_(printf)("syscall close %d %d\n", tid, fd);

     shared_fds[fd] = 0;
     tainted_fds[tid][fd] = False;
   }
}

void TNT_(syscall_write)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {

	Int fd = args[0];
	if (in_sandbox) {
	   if (shared_fds[fd] != fd) {
		   HChar fdpath[MAX_PATH];
		   VG_(resolve_filename)(fd, fdpath, MAX_PATH-1);
		   UInt pc = VG_(get_IP)(tid);
		   HChar fnname[128];
		   VG_(describe_IP) ( pc, fnname, 128 );
		   char* just_fnname = VG_(strstr)(fnname, ":");
		   just_fnname += 2;
		   VG_(printf)("*** Thread %d wrote to %s (fd: %d) in method %s, but it is not allowed to. ***\n", tid, fdpath, fd, just_fnname);
		   VG_(get_and_pp_StackTrace)(tid, STACK_TRACE_SIZE);
		   VG_(printf)("\n");
		   return;
	   }
	}

}




/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
