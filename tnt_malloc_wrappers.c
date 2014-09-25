//--------------------------------------------------------------------*/
//--- malloc/free wrappers for Taintgrind    tnt_malloc_wrappers.c ---*/
//--------------------------------------------------------------------*/

/*
   This file is part of Taintgrind.
   usage of programs.

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

//------------------------------------------------------------//
//--- malloc() et al replacement wrappers for Taintgrind      ---//
//------------------------------------------------------------//
//--- Simplified version adapted from Massif.              ---//
//--- The main reason for replacing malloc etc. is to      ---//
//--- untaint data when free is called, and to copy taint  ---//
//--- state when realloc is called.                        ---//
//------------------------------------------------------------//

#include "pub_tool_basics.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_replacemalloc.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_xarray.h"

#include "tnt_include.h"

VgHashTable TNT_(malloc_list)  = NULL;   // HP_Chunks

static
void* record_block( ThreadId tid, void* p, SizeT req_szB, SizeT slop_szB )
{
   // Make new HP_Chunk node, add to malloc_list
   HP_Chunk* hc = VG_(malloc)("ms.main.rb.1", sizeof(HP_Chunk));
   hc->req_szB  = req_szB;
   hc->slop_szB = slop_szB;
   hc->data     = (Addr)p;
   VG_(HT_add_node)(TNT_(malloc_list), hc);

   // Untaint malloc'd block
   TNT_(make_mem_untainted)( (Addr)p, hc->req_szB + hc->slop_szB ); 

   return p;
}

static __inline__
void* alloc_and_record_block ( ThreadId tid, SizeT req_szB, SizeT req_alignB,
                               Bool is_zeroed )
{
   SizeT actual_szB, slop_szB;
   void* p;

   if ((SSizeT)req_szB < 0) return NULL;

   // Allocate and zero if necessary.
   p = VG_(cli_malloc)( req_alignB, req_szB );
   if (!p) {
      return NULL;
   }
   if (is_zeroed) VG_(memset)(p, 0, req_szB);
   actual_szB = VG_(malloc_usable_size)(p);
   tl_assert(actual_szB >= req_szB);
   slop_szB = actual_szB - req_szB;

   // Record block.
   record_block(tid, p, req_szB, slop_szB);

   return p;
}

static __inline__
void unrecord_block ( void* p )
{
   // Remove HP_Chunk from malloc_list
   HP_Chunk* hc = VG_(HT_remove)(TNT_(malloc_list), (UWord)p);
   if (NULL == hc) {
      return;   // must have been a bogus free()
   }

   // Untaint freed block
   TNT_(make_mem_untainted)( (Addr)p, hc->req_szB + hc->slop_szB ); 

   // Actually free the chunk, and the heap block (if necessary)
   VG_(free)( hc );  hc = NULL;
}

static __inline__
void* realloc_block ( ThreadId tid, void* p_old, SizeT new_req_szB )
{
   HP_Chunk* hc;
   void*     p_new;
   SizeT     old_req_szB, old_slop_szB, new_slop_szB, new_actual_szB;

   // Remove the old block
   hc = VG_(HT_remove)(TNT_(malloc_list), (UWord)p_old);
   if (hc == NULL) {
      return NULL;   // must have been a bogus realloc()
   }

   old_req_szB  = hc->req_szB;
   old_slop_szB = hc->slop_szB;

   // Actually do the allocation, if necessary.
   if (new_req_szB <= old_req_szB + old_slop_szB) {
      // New size is smaller or same;  block not moved.
      p_new = p_old;
      new_slop_szB = old_slop_szB + (old_req_szB - new_req_szB);

   } else {
      // New size is bigger;  make new block, copy shared contents, free old.
      p_new = VG_(cli_malloc)(VG_(clo_alignment), new_req_szB);
      if (!p_new) {
         // Nb: if realloc fails, NULL is returned but the old block is not
         // touched.  What an awful function.
         return NULL;
      }
      VG_(memcpy)(p_new, p_old, old_req_szB);

      VG_(cli_free)(p_old);
      new_actual_szB = VG_(malloc_usable_size)(p_new);
      tl_assert(new_actual_szB >= new_req_szB);
      new_slop_szB = new_actual_szB - new_req_szB;

      // Copy taint state
      TNT_(copy_address_range_state)( (Addr)p_old, (Addr)p_new, new_actual_szB );
   }

   if (p_new) {
      // Update HP_Chunk.
      hc->data     = (Addr)p_new;
      hc->req_szB  = new_req_szB;
      hc->slop_szB = new_slop_szB;
   }

   // Now insert the new hc (with a possibly new 'data' field) into
   // malloc_list.  If this realloc() did not increase the memory size, we
   // will have removed and then re-added hc unnecessarily.  But that's ok
   // because shrinking a block with realloc() is (presumably) much rarer
   // than growing it, and this way simplifies the growing case.
   VG_(HT_add_node)(TNT_(malloc_list), hc);
   return p_new;
}


void* TNT_(malloc) ( ThreadId tid, SizeT szB )
{
   return alloc_and_record_block( tid, szB, VG_(clo_alignment), /*is_zeroed*/False );
}

void* TNT_(__builtin_new) ( ThreadId tid, SizeT szB )
{
   return alloc_and_record_block( tid, szB, VG_(clo_alignment), /*is_zeroed*/False );
}

void* TNT_(__builtin_vec_new) ( ThreadId tid, SizeT szB )
{
   return alloc_and_record_block( tid, szB, VG_(clo_alignment), /*is_zeroed*/False );
}

void* TNT_(calloc) ( ThreadId tid, SizeT m, SizeT szB )
{
   return alloc_and_record_block( tid, m*szB, VG_(clo_alignment), /*is_zeroed*/True );
}

void *TNT_(memalign) ( ThreadId tid, SizeT alignB, SizeT szB )
{
   return alloc_and_record_block( tid, szB, alignB, False );
}

void TNT_(free) ( ThreadId tid __attribute__((unused)), void* p )
{
   unrecord_block(p);
   VG_(cli_free)(p);
}

void TNT_(__builtin_delete) ( ThreadId tid, void* p )
{
   unrecord_block(p);
   VG_(cli_free)(p);
}

void TNT_(__builtin_vec_delete) ( ThreadId tid, void* p )
{
   unrecord_block(p);
   VG_(cli_free)(p);
}

void* TNT_(realloc) ( ThreadId tid, void* p_old, SizeT new_szB )
{
   return realloc_block(tid, p_old, new_szB);
}

SizeT TNT_(malloc_usable_size) ( ThreadId tid, void* p )
{                                                            
   HP_Chunk* hc = VG_(HT_lookup)( TNT_(malloc_list), (UWord)p );

   return ( hc ? hc->req_szB + hc->slop_szB : 0 );
}                                                            

//--------------------------------------------------------------------//
//--- end                                                          ---//
//--------------------------------------------------------------------//
