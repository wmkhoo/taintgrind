
/*--------------------------------------------------------------------*/
/*--- Wrappers for tainting syscalls                               ---*/
/*---                                                tnt_syswrap.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Taintgrind, a Valgrind tool for
   tracking marked/tainted data through memory.

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
#include "pub_tool_debuginfo.h"	   // VG_(describe_IP), VG_(get_fnname)

#include "valgrind.h"

#include "tnt_include.h"

// macros
#define KRED "\e[31m"
#define KGRN "\e[32m"
#define KMAG "\e[35m"
#define KNRM "\e[0m"

static
void resolve_filename(UWord fd, HChar *path, Int max)
{
   HChar src[FD_MAX_PATH];
   Int len = 0;

   // TODO: Cache resolved fds by also catching open()s and close()s
   VG_(sprintf)(src, "/proc/%d/fd/%d", VG_(getpid)(), (int)fd);
   len = VG_(readlink)(src, path, max);

   // Just give emptiness on error.
   if (len == -1) len = 0;
   path[len] = '\0';
}

/* enforce an arbitrary maximum */
#define VG_N_THREADS 500 
static Bool tainted_fds[VG_N_THREADS][FD_MAX];

void TNT_(setup_tainted_map)( void ) {
  ThreadId t = 0;
  VG_(memset)(tainted_fds, False, sizeof(tainted_fds));
  /* Taint stdin if specified */
  if (TNT_(clo_taint_stdin))
    for(t=0; t < VG_N_THREADS; ++t)
      tainted_fds[t][0] = True;
}

static UInt read_offset = 0;

void TNT_(syscall_lseek)(ThreadId tid, UWord* args, UInt nArgs,
                                  SysRes res) {
// off_t lseek(int fd, off_t offset, int whence);
   Int   fd      = args[0];
   ULong offset  = args[1];
   UInt  whence  = args[2];
   Bool  verbose = False;

   if (fd >= FD_MAX || tainted_fds[tid][fd] == False)
      return;

   Int   retval       = sr_Res(res);

   if ( verbose )
   {
      VG_(printf)("syscall _lseek %d %d ", tid, fd);
      VG_(printf)("offset: 0x%x whence: 0x%x ", (UInt)offset, whence);
      VG_(printf)("retval: 0x%x read_offset: 0x%x\n", retval, read_offset);
   }

   if( whence == 0/*SEEK_SET*/ )
      read_offset = 0 + (UInt)offset;
   else if( whence == 1/*SEEK_CUR*/ )
      read_offset += (UInt)offset;
   else if( whence == 2/*SEEK_END*/ )
      read_offset = retval;
   else {
      VG_(printf)("whence %x\n", whence);
      tl_assert(0);
   }
}

void TNT_(syscall_llseek)(ThreadId tid, UWord* args, UInt nArgs,
                                  SysRes res) {
// int  _llseek(int fildes, ulong offset_high, ulong offset_low, loff_t *result,, uint whence);
   Int   fd           = args[0];
   ULong offset_high  = args[1];
   ULong offset_low   = args[2];
   UInt  result       = args[3];
   UInt  whence       = args[4];
   ULong offset;
   Bool  verbose      = False;

   if (fd >= FD_MAX || tainted_fds[tid][fd] == False)
      return;

   Int   retval       = sr_Res(res);

   if ( verbose )
   {
      VG_(printf)("syscall _llseek %d %d ", tid, fd);
      VG_(printf)("0x%x 0x%x 0x%x 0x%x\n", (UInt)offset_high, (UInt)offset_low, result, whence);
      VG_(printf)("0x%x\n", retval);
   }

   offset = (offset_high<<32) | offset_low;

   if( whence == 0/*SEEK_SET*/ )
      read_offset = 0 + (UInt)offset;
   else if( whence == 1/*SEEK_CUR*/ )
      read_offset += (UInt)offset;
   else {//if( whence == 2/*SEEK_END*/ )
      VG_(printf)("whence %x\n", whence);
      tl_assert(0);
   }
}

Bool TNT_(syscall_allowed_check)(ThreadId tid, int syscallno) {
	if (IN_SANDBOX && IS_SYSCALL_ALLOWED(syscallno)) {
		const HChar *fnname;

		TNT_(get_fnname)(tid, &fnname);
		VG_(printf)("*** Sandbox performed system call %s (%d) in method %s, but it is not allowed to. ***\n", syscallnames[syscallno], syscallno, fnname);
		VG_(get_and_pp_StackTrace)(tid, STACK_TRACE_SIZE);
		VG_(printf)("\n");
		return False;
	}
	return True;
}

static
void read_common ( UInt taint_offset, Int taint_len,
                   UInt curr_offset, Int curr_len,
                   HChar *data ) {
   UWord addr;
   Int   len;

   if( TNT_(clo_taint_all) ){
      addr = (UWord)data;
      len  = curr_len;
   }else

      //VG_(printf)("curr_offset 0x%x\n", curr_offset);
      //VG_(printf)("curr_len    0x%x\n", curr_len);
      //VG_(printf)("tnt_offset 0x%x\n", taint_offset);
      //VG_(printf)("tnt_len    0x%x\n", taint_len);

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
         addr = (UWord)(data + taint_offset - curr_offset);
         len  = taint_len;
      }else{
         // Case 2
         addr = (UWord)(data + taint_offset - curr_offset);
         len  = curr_len - taint_offset + curr_offset;
      }

   }else if( ( ( taint_offset + taint_len ) >= curr_offset ) &&
             ( ( taint_offset + taint_len ) <= (curr_offset + curr_len ) ) ){
      // Case 3
      addr = (UWord)data;
      len  = taint_len - curr_offset + taint_offset;
   }else if( ( taint_offset <= curr_offset ) &&
       ( taint_offset + taint_len ) >= ( curr_offset + curr_len ) ){
      // Case 4
      addr = (UWord)data;
      len  = curr_len;
   }else{
      return;
   }

   if ( TNT_(clo_smt2) )
      TNT_(make_mem_tainted_named)( addr, len, "read" );
   else
      TNT_(make_mem_tainted)( addr, len );
}

void TNT_(syscall_read)(ThreadId tid, UWord* args, UInt nArgs,
                                  SysRes res) {
// ssize_t  read(int fildes, void *buf, size_t nbyte);
   Int   fd           = args[0];
   HChar *data        = (HChar *)args[1];
   UInt  curr_offset  = read_offset;
   Int   curr_len     = sr_Res(res);
   UInt  taint_offset = TNT_(clo_taint_start);
   Int   taint_len    = TNT_(clo_taint_len);
   Bool  verbose      = False;

   TNT_(check_fd_access)(tid, fd, FD_READ);

   if (curr_len == 0) return;

   TNT_(make_mem_untainted)( (UWord)data, curr_len );

   if (fd >= FD_MAX || tainted_fds[tid][fd] == False)
      return;

   if(verbose){
      //VG_(printf)("taint_offset: 0x%x\ttaint_len: 0x%x\n", taint_offset, taint_len);
      //VG_(printf)("curr_offset : 0x%x\tcurr_len : 0x%x\n", curr_offset, curr_len);
      VG_(printf)("syscall read %d %d ", tid, fd);
#ifdef VGA_amd64
      VG_(printf)("0x%x 0x%x 0x%llx 0x%x\n", curr_offset, curr_len, (ULong)data,
          *(HChar *)data);
#else
      VG_(printf)("0x%x 0x%x 0x%x 0x%x\n", curr_offset, curr_len, (UInt)data,
          *(HChar *)data);
#endif
   }
   if ( !TNT_(clo_smt2) ) {
      Int success = TNT_(describe_data)(data, varname, VARNAMESIZE);
      if ( istty ) VG_(printf)("%s", KMAG);
      if (TNT_(clo_compact))
         VG_(printf)("0xFFFFFFFF ");
      else
         VG_(printf)("0xFFFFFFFF: _syscall_read ");
      if ( istty ) VG_(printf)("%s", KNRM);
      VG_(printf)("| Read:%d | ", curr_len);
      if ( istty ) VG_(printf)("%s", KRED);
      VG_(printf)("0x%x", curr_offset);
      if ( istty ) VG_(printf)("%s", KNRM);
      if (success)    VG_(printf)( " | %s:%x\n", varname, data);
      else            VG_(printf)( " | %s\n", varname );
   }
   read_common ( taint_offset, taint_len, curr_offset, curr_len, data );

   // Update file position
   read_offset += curr_len;

   // DEBUG
   //tnt_read = 1;
}

void TNT_(syscall_pread)(ThreadId tid, UWord* args, UInt nArgs,
                                  SysRes res) {
// ssize_t pread(int fildes, void *buf, size_t nbyte, size_t offset);
   Int   fd           = args[0];
   HChar *data        = (HChar *)args[1];
   UInt  curr_offset  = (Int)args[3];
   Int   curr_len     = sr_Res(res);
   UInt  taint_offset = TNT_(clo_taint_start);
   Int   taint_len    = TNT_(clo_taint_len);
   Bool  verbose      = False;

   if (curr_len == 0) return;

   TNT_(make_mem_untainted)( (UWord)data, curr_len );

   if (fd >= FD_MAX || tainted_fds[tid][fd] == False)
      return;

   if(verbose){
      //VG_(printf)("taint_offset: 0x%x\ttaint_len: 0x%x\n", taint_offset, taint_len);
      //VG_(printf)("curr_offset : 0x%x\tcurr_len : 0x%x\n", curr_offset, curr_len);
      VG_(printf)("syscall pread %d %d ", tid, fd);

#ifdef VGA_amd64
      VG_(printf)("0x%x 0x%x 0x%llx\n", curr_offset, curr_len, (ULong)data);
#else
      VG_(printf)("0x%x 0x%x 0x%x\n", curr_offset, curr_len, (UInt)data);
#endif

   }
   if ( !TNT_(clo_smt2) ) {
      Int success = TNT_(describe_data)(data, varname, VARNAMESIZE);
      if ( istty ) VG_(printf)("%s", KMAG);
      if (TNT_(clo_compact))
         VG_(printf)("0xFFFFFFFF ");
      else
         VG_(printf)("0xFFFFFFFF: _syscall_pread ");
      if ( istty ) VG_(printf)("%s", KNRM);
      VG_(printf)("| Read:%d | ", curr_len);
      if ( istty ) VG_(printf)("%s", KRED);
      VG_(printf)("0x%x", curr_offset);
      if ( istty ) VG_(printf)("%s", KNRM);
      if (success)    VG_(printf)( " | %s:%x\n", varname, data);
      else            VG_(printf)( " | %s\n", varname );
   }
   read_common ( taint_offset, taint_len, curr_offset, curr_len, data );
}


void TNT_(syscall_open)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
//  int open (const char *filename, int flags[, mode_t mode])
   HChar fdpath[FD_MAX_PATH];
   Int fd = sr_Res(res);
   Bool verbose = False;

   // check if we have already created a sandbox
   if (have_created_sandbox && !IN_SANDBOX) {
#ifdef VGO_freebsd
	   VG_(resolve_filename)(fd, fdpath, FD_MAX_PATH-1);
#elif defined VGO_linux
	   resolve_filename(fd, fdpath, FD_MAX_PATH-1);
#elif defined VGO_darwin
	   resolve_filename(fd, fdpath, FD_MAX_PATH-1);
#else
#error OS unknown
#endif
	   const HChar *fnname;
	   TNT_(get_fnname)(tid, &fnname);
	   VG_(printf)("*** The file %s (fd: %d) was opened in method %s after a sandbox was created, hence it will not be accessible to the sandbox. It will need to be passed to the sandbox using sendmsg. ***\n", fdpath, fd, fnname);
	   VG_(get_and_pp_StackTrace)(tid, STACK_TRACE_SIZE);
	   VG_(printf)("\n");
   }

    // Nothing to do if no file tainting
    if ( VG_(strlen)( TNT_(clo_file_filter)) == 0  && (fd != 0 || !TNT_(clo_taint_stdin)) )
        return;

    if (fd > -1 && fd < FD_MAX) {

#ifdef VGO_freebsd
	VG_(resolve_filename)(fd, fdpath, FD_MAX_PATH-1);
#elif defined VGO_linux
        resolve_filename(fd, fdpath, FD_MAX_PATH-1);
#elif defined VGO_darwin
        resolve_filename(fd, fdpath, FD_MAX_PATH-1);
#else
#error OS unknown
#endif

        if( TNT_(clo_taint_all) ){

            tainted_fds[tid][fd] = True;
            if ( verbose )
               VG_(printf)("syscall open %d %s %lx %d\n", tid, fdpath, args[1], fd);
            read_offset = 0;

        } else if ( VG_(strncmp)(fdpath, TNT_(clo_file_filter), 
                            VG_(strlen)( TNT_(clo_file_filter))) == 0 ) {

            tainted_fds[tid][fd] = True;
            if ( verbose )
               VG_(printf)("syscall open %d %s %lx %d\n", tid, fdpath, args[1], fd);
            read_offset = 0;

        } else if ( TNT_(clo_file_filter)[0] == '*' &&
            VG_(strncmp)( fdpath + VG_(strlen)(fdpath) 
                        - VG_(strlen)( TNT_(clo_file_filter) ) + 1, 
                          TNT_(clo_file_filter) + 1, 
                          VG_(strlen)( TNT_(clo_file_filter)) - 1 ) == 0 ) {

            tainted_fds[tid][fd] = True;
            if ( verbose )
               VG_(printf)("syscall open %d %s %lx %d\n", tid, fdpath, args[1], fd);
            read_offset = 0;
        } else if (TNT_(clo_taint_stdin)) {
            tainted_fds[tid][fd] = True;
            if ( verbose )
               VG_(printf)("syscall open %d %s %lx %d\n", tid, fdpath, args[1], fd);
        } else
            tainted_fds[tid][fd] = False;
    }
}

void TNT_(syscall_close)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
//   int close (int filedes)
   Int fd = args[0];

   if (fd > -1 && fd < FD_MAX){
     //if (tainted_fds[tid][fd] == True)
     //    VG_(printf)("syscall close %d %d\n", tid, fd);

     shared_fds[fd] = 0;
     tainted_fds[tid][fd] = False;
   }
}

void TNT_(syscall_write)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int fd = args[0];
	TNT_(check_fd_access)(tid, fd, FD_WRITE);
}

void TNT_(get_fnname)(ThreadId tid, const HChar** buf) {
	   UInt pc = VG_(get_IP)(tid);
           DiEpoch  ep = VG_(current_DiEpoch)();
	   VG_(get_fnname)(ep, pc, buf);
}

void TNT_(check_fd_access)(ThreadId tid, UInt fd, Int fd_request) {
	if (IN_SANDBOX) {
		Bool allowed = shared_fds[fd] & fd_request;
//		VG_(printf)("checking if allowed to %s from fd %d ... %d\n", (fd_request == FD_READ ? "read" : "write"), fd, allowed);
		if (!allowed) {
			const HChar* access_str;
			switch (fd_request) {
				case FD_READ: {
					access_str = "read from";
					break;
				}
				case FD_WRITE: {
					access_str = "wrote to";
					break;
				}
				default: {
					tl_assert(0);
					break;
				}
			}
			HChar fdpath[FD_MAX_PATH];
#ifdef VGO_freebsd
			VG_(resolve_filename)(fd, fdpath, FD_MAX_PATH-1);
#elif defined VGO_linux
			resolve_filename(fd, fdpath, FD_MAX_PATH-1);
#elif defined VGO_darwin
			resolve_filename(fd, fdpath, FD_MAX_PATH-1);
#else
#error OS unknown
#endif
			const HChar *fnname;
			TNT_(get_fnname)(tid, &fnname);
			VG_(printf)("*** Sandbox %s %s (fd: %d) in method %s, but it is not allowed to. ***\n", access_str, fdpath, fd, fnname);
			VG_(get_and_pp_StackTrace)(tid, STACK_TRACE_SIZE);
			VG_(printf)("\n");
		}
	}
}

/*** Networking syscalls ***/

void TNT_(syscall_socketcall)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {

// int socketcall(int call, unsigned long *args);

  switch (args[0]) {
#ifdef VKI_SYS_SOCKET
    case VKI_SYS_SOCKET:
      //VG_(printf)("syscall_socketcall: SOCKET\n");
      TNT_(syscall_socket)(tid, args, nArgs, res);
      break;
#endif
#ifdef VKI_SYS_LISTEN
    case VKI_SYS_LISTEN:
      //TNT_(syscall_listen)(tid, res);
      break;
#endif
#ifdef VKI_SYS_ACCEPT
    case VKI_SYS_ACCEPT:
      //VG_(printf)("syscall_socketcall: ACCEPT\n");
      TNT_(syscall_accept)(tid, args, nArgs, res);
      break;
#endif
#ifdef VKI_SYS_CONNECT
    case VKI_SYS_CONNECT:
      //VG_(printf)("syscall_socketcall: CONNECT\n");
      // TODO: submit a syscall hooking patch to valgrind to avoid this.
      TNT_(syscall_connect)(tid, args, nArgs, res);
      break;
#endif
#ifdef VKI_SYS_GETPEERNAME
    case VKI_SYS_GETPEERNAME:
      //VG_(printf)("syscall_socketcall: GETPEERNAME\n");
      break;
#endif
#ifdef VKI_SYS_GETSOCKNAME
    case VKI_SYS_GETSOCKNAME:
      //VG_(printf)("syscall_socketcall: GETSOCKNAME\n");
      break;
#endif
#ifdef VKI_SYS_SOCKETPAIR
    case VKI_SYS_SOCKETPAIR:
      //VG_(printf)("syscall_socketcall: SOCKETPAIR\n");
      TNT_(syscall_socketpair)(tid, args, nArgs, res);
      break;
#endif
#ifdef VKI_SYS_RECV
    case VKI_SYS_RECV:
     // VG_(printf)("syscall_socketcall: RECV\n");
      TNT_(syscall_recv)(tid, args, nArgs, res);
      break;
#endif
#ifdef VKI_SYS_RECVMSG
    case VKI_SYS_RECVMSG:
      //VG_(printf)("syscall_socketcall: RECVMSG\n");
      TNT_(syscall_recvmsg)(tid, args, nArgs, res);
      break;
#endif
#ifdef VKI_SYS_RECVFROM
    case VKI_SYS_RECVFROM:
      //VG_(printf)("syscall_socketcall: RECVFROM\n");
      TNT_(syscall_recvfrom)(tid, args, nArgs, res);
      break;
#endif
#ifdef VKI_SYS_SHUTDOWN
    case VKI_SYS_SHUTDOWN:
     // VG_(printf)("syscall_socketcall: SHUTDOWN\n");
      break;
#endif
    default:
      return;
  }
}

void TNT_(syscall_socket)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
  Int fd = sr_Res(res);
  // Nothing to do if no network tainting
  if (!TNT_(clo_taint_network))
    return;

  if (fd > -1 && fd < FD_MAX) {
    tainted_fds[tid][fd] = True;
    //VG_(printf)("syscall_socket: tainting %d\n", fd);
  }
}

void TNT_(syscall_connect)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
  // Assume this is called directly after arguments have been populated.
  Int fd = args[0];

  // Nothing to do if no network tainting
  if (!TNT_(clo_taint_network))
    return;
  if (fd > -1 && fd < FD_MAX) {
    tainted_fds[tid][fd] = True;
    // VG_(printf)("syscall_connect: tainting %d\n", fd);
  }
}

void TNT_(syscall_socketpair)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
  // int socketpair(int domain, int type, int protocol, int sv[2]);

  // Assume this is called directly after arguments have been populated.
  Int fd = ((Int *)args[3])[0];

  // Nothing to do if no network tainting
  if (!TNT_(clo_taint_network))
    return;
  if (fd > -1 && fd < FD_MAX) {
    tainted_fds[tid][fd] = True;
    // VG_(printf)("syscall_socketpair: tainting fd %d\n", fd);
  }
}

void TNT_(syscall_accept)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
  Int fd = sr_Res(res);
  // Nothing to do if no network tainting
  if (!TNT_(clo_taint_network))
    return;
  if (fd > -1 && fd < FD_MAX) {
    tainted_fds[tid][fd] = True;
    // VG_(printf)("syscall_connect: tainting %d\n", fd);
  }
}

void TNT_(syscall_recv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
// ssize_t recv(int sockfd, void *buf, size_t len, int flags)
   Int fd = args[0];
   HChar *data = (HChar *)args[1];
   Int msglen  = sr_Res(res);
   //VG_(printf)("syscall recv %d 0x%x 0x%02x\n", tid, msglen, data[0]);

  if (fd > -1 && fd < FD_MAX && tainted_fds[tid][fd] == True && msglen > 0) {
    TNT_(make_mem_tainted)((UWord)data, msglen);
  }
}

void TNT_(syscall_recvfrom)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
// ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
//                 struct sockaddr *src_addr, socklen_t *addrlen)
// TODO: #include <arpa/inet.h> inet_ntop to pretty print IP address
   Int fd = args[0];
   HChar *data = (HChar *)args[1];
   Int msglen  = sr_Res(res);
   //VG_(printf)("syscall recvfrom %d 0x%x 0x%02x\n", tid, msglen, data[0]);

  if (fd > -1 && fd < FD_MAX && tainted_fds[tid][fd] == True && msglen > 0) {
    TNT_(make_mem_tainted)((UWord)data, msglen);
  }
}

/* Annoyingly uses the struct msghdr from sys/socket.h
 * XXX: scatter gather array and readv() not yet supported.d 
 */
void TNT_(syscall_recvmsg)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
  Int fd = args[0];
  struct vki_msghdr *msg = (struct vki_msghdr *)args[1];

  if (fd > -1 && fd < FD_MAX && tainted_fds[tid][fd] == True && sr_Res(res) > 0) {
    // XXX: if MSG_TRUNC, this will taint more memory than it should.
    TNT_(make_mem_tainted)((UWord)msg->msg_control, sr_Res(res));
  }
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
