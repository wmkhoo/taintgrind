
/*--------------------------------------------------------------------*/
/*--- Taintgrind: The taint analysis Valgrind tool.        tnt_main.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Taintgrind, the taint analysis Valgrind tool.

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
#include "pub_tool_tooliface.h"

#include "pub_tool_vki.h"           // keeps libcproc.h happy
#include "pub_tool_aspacemgr.h"     // VG_(am_shadow_alloc)
#include "pub_tool_debuginfo.h"     // VG_(get_fnname_w_offset)
#include "pub_tool_hashtable.h"     // For tnt_include.h, VgHashtable
#include "pub_tool_libcassert.h"    // tl_assert
#include "pub_tool_libcbase.h"      // VG_STREQN
#include "pub_tool_libcprint.h"     // VG_(message)
#include "pub_tool_libcproc.h"      // VG_(getenv)
#include "pub_tool_replacemalloc.h" // VG_(replacement_malloc_process_cmd_line_option)
#include "pub_tool_machine.h"       // VG_(get_IP)
#include "pub_tool_mallocfree.h"    // VG_(out_of_memory_NORETURN)
#include "pub_tool_options.h"       // VG_STR/BHEX/BINT_CLO
#include "pub_tool_oset.h"          // OSet operations
#include "pub_tool_threadstate.h"   // VG_(get_running_tid)

#include "tnt_include.h"
#include "tnt_strings.h"

/*------------------------------------------------------------*/
/*--- Fast-case knobs                                      ---*/
/*------------------------------------------------------------*/

// Comment these out to disable the fast cases (don't just set them to zero).

#define PERF_FAST_LOADV    1
#define PERF_FAST_STOREV   1

#define PERF_FAST_SARP     1

/*---------- Taintgrind DEBUG statements---------*/
//#define DBG_MEM
//#define DBG_LOAD
//#define DBG_STORE
//#define DBG_COPY_ADDR_RANGE_STATE

/* --------------- Basic configuration --------------- */

/* Only change this.  N_PRIMARY_MAP *must* be a power of 2. */

#if VG_WORDSIZE == 4

/* cover the entire address space */
#  define N_PRIMARY_BITS  16

#else

/* Just handle the first 32G fast and the rest via auxiliary
   primaries.  If you change this, Memcheck will assert at startup.
   See the definition of UNALIGNED_OR_HIGH for extensive comments. */
#  define N_PRIMARY_BITS  19

#endif


/* Do not change this. */
#define N_PRIMARY_MAP  ( ((UWord)1) << N_PRIMARY_BITS)

/* Do not change this. */
#define MAX_PRIMARY_ADDRESS (Addr)((((Addr)65536) * N_PRIMARY_MAP)-1)

// These represent eight bits of memory.
#define VA_BITS2_NOACCESS      0x0      // 00b
#define VA_BITS2_TAINTED       0x1      // 01b
#define VA_BITS2_UNTAINTED     0x2      // 10b
#define VA_BITS2_PARTUNTAINTED 0x3      // 11b

// These represent 16 bits of memory.
#define VA_BITS4_NOACCESS     0x0      // 00_00b
#define VA_BITS4_TAINTED      0x5      // 01_01b
#define VA_BITS4_UNTAINTED    0xa      // 10_10b

// These represent 32 bits of memory.
#define VA_BITS8_NOACCESS     0x00     // 00_00_00_00b
#define VA_BITS8_TAINTED      0x55     // 01_01_01_01b
#define VA_BITS8_UNTAINTED    0xaa     // 10_10_10_10b

// These represent 64 bits of memory.
#define VA_BITS16_NOACCESS    0x0000   // 00_00_00_00b x 2
#define VA_BITS16_TAINTED     0x5555   // 01_01_01_01b x 2
#define VA_BITS16_UNTAINTED   0xaaaa   // 10_10_10_10b x 2

#define SM_CHUNKS             16384
#define SM_OFF(aaa)           (((aaa) & 0xffff) >> 2)
#define SM_OFF_16(aaa)        (((aaa) & 0xffff) >> 3)

// Paranoia:  it's critical for performance that the requested inlining
// occurs.  So try extra hard.
#define INLINE    inline __attribute__((always_inline))

static INLINE Addr start_of_this_sm ( Addr a ) {
   return (a & (~SM_MASK));
}
static INLINE Bool is_start_of_sm ( Addr a ) {
   return (start_of_this_sm(a) == a);
}

typedef
   struct {
      UChar vabits8[SM_CHUNKS];
   }
   SecMap;

// 3 distinguished secondary maps, one for no-access, one for
// accessible but undefined, and one for accessible and defined.
// Distinguished secondaries may never be modified.
#define SM_DIST_NOACCESS   0
#define SM_DIST_TAINTED    1
#define SM_DIST_UNTAINTED  2

static SecMap sm_distinguished[3];

static INLINE Bool is_distinguished_sm ( SecMap* sm ) {
   return sm >= &sm_distinguished[0] && sm <= &sm_distinguished[2];
}

// Forward declaration
Int  ctoi( Char c );
Int  ctoi_test( Char c );
Int  atoi( Char *s );
Char decode_char( UInt num );
void decode_string( UInt *enc, Char *aStr );
void post_decode_string( Char *aStr );
void post_decode_string_load( Char *aStr );
void post_decode_string_primops( Char *aStr );
void post_decode_string_binops( Char *aStr );
void post_decode_string_store( Char *aStr );
void post_decode_string_mux0x( Char *aStr );
Int get_and_check_reg( Char *reg );
Int get_and_check_tvar( Char *tmp );

static void update_SM_counts(SecMap* oldSM, SecMap* newSM); //285

/* dist_sm points to one of our three distinguished secondaries.  Make
   a copy of it so that we can write to it.
*/
static SecMap* copy_for_writing ( SecMap* dist_sm )
{
   SecMap* new_sm;
   tl_assert(dist_sm == &sm_distinguished[0]
          || dist_sm == &sm_distinguished[1]
          || dist_sm == &sm_distinguished[2]);

   new_sm = VG_(am_shadow_alloc)(sizeof(SecMap));
   if (new_sm == NULL)
      VG_(out_of_memory_NORETURN)( "memcheck:allocate new SecMap",
                                   sizeof(SecMap) );
   VG_(memcpy)(new_sm, dist_sm, sizeof(SecMap));
   update_SM_counts(dist_sm, new_sm);
   return new_sm;
}

/* --------------- Stats --------------- */

static Int   n_issued_SMs      = 0;
static Int   n_deissued_SMs    = 0;
static Int   n_noaccess_SMs    = N_PRIMARY_MAP; // start with many noaccess DSMs
static Int   n_undefined_SMs   = 0;
static Int   n_defined_SMs     = 0;
static Int   n_non_DSM_SMs     = 0;
static Int   max_noaccess_SMs  = 0;
static Int   max_undefined_SMs = 0;
static Int   max_defined_SMs   = 0;
static Int   max_non_DSM_SMs   = 0;

/* # searches initiated in auxmap_L1, and # base cmps required */
static ULong n_auxmap_L1_searches  = 0;
static ULong n_auxmap_L1_cmps      = 0;
/* # of searches that missed in auxmap_L1 and therefore had to
   be handed to auxmap_L2. And the number of nodes inserted. */
static ULong n_auxmap_L2_searches  = 0;
static ULong n_auxmap_L2_nodes     = 0;

//static Int   n_sanity_cheap     = 0;
//static Int   n_sanity_expensive = 0;

static Int   n_secVBit_nodes   = 0;
static Int   max_secVBit_nodes = 0;

static void update_SM_counts(SecMap* oldSM, SecMap* newSM)
{
   if      (oldSM == &sm_distinguished[SM_DIST_NOACCESS ]) n_noaccess_SMs --;
   else if (oldSM == &sm_distinguished[SM_DIST_TAINTED]) n_undefined_SMs--;
   else if (oldSM == &sm_distinguished[SM_DIST_UNTAINTED  ]) n_defined_SMs  --;
   else                                                  { n_non_DSM_SMs  --;
                                                           n_deissued_SMs ++; }

   if      (newSM == &sm_distinguished[SM_DIST_NOACCESS ]) n_noaccess_SMs ++;
   else if (newSM == &sm_distinguished[SM_DIST_TAINTED]) n_undefined_SMs++;
   else if (newSM == &sm_distinguished[SM_DIST_UNTAINTED  ]) n_defined_SMs  ++;
   else                                                  { n_non_DSM_SMs  ++;
                                                           n_issued_SMs   ++; }

   if (n_noaccess_SMs  > max_noaccess_SMs ) max_noaccess_SMs  = n_noaccess_SMs;
   if (n_undefined_SMs > max_undefined_SMs) max_undefined_SMs = n_undefined_SMs;
   if (n_defined_SMs   > max_defined_SMs  ) max_defined_SMs   = n_defined_SMs;
   if (n_non_DSM_SMs   > max_non_DSM_SMs  ) max_non_DSM_SMs   = n_non_DSM_SMs;
}

/* --------------- Primary maps --------------- */

/* The main primary map.  This covers some initial part of the address
   space, addresses 0 .. (N_PRIMARY_MAP << 16)-1.  The rest of it is
   handled using the auxiliary primary map.
*/
static SecMap* primary_map[N_PRIMARY_MAP];

/* An entry in the auxiliary primary map.  base must be a 64k-aligned
   value, and sm points at the relevant secondary map.  As with the
   main primary map, the secondary may be either a real secondary, or
   one of the three distinguished secondaries.  DO NOT CHANGE THIS
   LAYOUT: the first word has to be the key for OSet fast lookups.
*/
typedef
   struct {
      Addr    base;
      SecMap* sm;
   }
   AuxMapEnt;

/* Tunable parameter: How big is the L1 queue? */
#define N_AUXMAP_L1 24

/* Tunable parameter: How far along the L1 queue to insert
   entries resulting from L2 lookups? */
#define AUXMAP_L1_INSERT_IX 12

static struct {
          Addr       base;
          AuxMapEnt* ent; // pointer to the matching auxmap_L2 node
       }
       auxmap_L1[N_AUXMAP_L1];

static OSet* auxmap_L2 = NULL;
static void init_auxmap_L1_L2 ( void )
{
   Int i;
   for (i = 0; i < N_AUXMAP_L1; i++) {
      auxmap_L1[i].base = 0;
      auxmap_L1[i].ent  = NULL;
   }

   tl_assert(0 == offsetof(AuxMapEnt,base));
   tl_assert(sizeof(Addr) == sizeof(void*));
   auxmap_L2 = VG_(OSetGen_Create)( /*keyOff*/  offsetof(AuxMapEnt,base),
                                    /*fastCmp*/ NULL,
                                    VG_(malloc), "mc.iaLL.1", VG_(free) );
}

/* Check representation invariants; if OK return NULL; else a
   descriptive bit of text.  Also return the number of
   non-distinguished secondary maps referred to from the auxiliary
   primary maps. */

//static HChar* check_auxmap_L1_L2_sanity ( Word* n_secmaps_found )
//{
//   Word i, j;
   /* On a 32-bit platform, the L2 and L1 tables should
      both remain empty forever.

      On a 64-bit platform:
      In the L2 table:
       all .base & 0xFFFF == 0
       all .base > MAX_PRIMARY_ADDRESS
      In the L1 table:
       all .base & 0xFFFF == 0
       all (.base > MAX_PRIMARY_ADDRESS
            .base & 0xFFFF == 0
            and .ent points to an AuxMapEnt with the same .base)
           or
           (.base == 0 and .ent == NULL)
   */
//   *n_secmaps_found = 0;
//   if (sizeof(void*) == 4) {
      /* 32-bit platform */
//      if (VG_(OSetGen_Size)(auxmap_L2) != 0)
//         return "32-bit: auxmap_L2 is non-empty";
//      for (i = 0; i < N_AUXMAP_L1; i++)
//        if (auxmap_L1[i].base != 0 || auxmap_L1[i].ent != NULL)
//      return "32-bit: auxmap_L1 is non-empty";
//   } else {
      /* 64-bit platform */
//      UWord elems_seen = 0;
//      AuxMapEnt *elem, *res;
//      AuxMapEnt key;
      /* L2 table */
//      VG_(OSetGen_ResetIter)(auxmap_L2);
//      while ( (elem = VG_(OSetGen_Next)(auxmap_L2)) ) {
//         elems_seen++;
//         if (0 != (elem->base & (Addr)0xFFFF))
//            return "64-bit: nonzero .base & 0xFFFF in auxmap_L2";
//         if (elem->base <= MAX_PRIMARY_ADDRESS)
//            return "64-bit: .base <= MAX_PRIMARY_ADDRESS in auxmap_L2";
//         if (elem->sm == NULL)
//            return "64-bit: .sm in _L2 is NULL";
//         if (!is_distinguished_sm(elem->sm))
//            (*n_secmaps_found)++;
//      }
//      if (elems_seen != n_auxmap_L2_nodes)
//         return "64-bit: disagreement on number of elems in _L2";
      /* Check L1-L2 correspondence */
/*      for (i = 0; i < N_AUXMAP_L1; i++) {
         if (auxmap_L1[i].base == 0 && auxmap_L1[i].ent == NULL)
            continue;
         if (0 != (auxmap_L1[i].base & (Addr)0xFFFF))
            return "64-bit: nonzero .base & 0xFFFF in auxmap_L1";
         if (auxmap_L1[i].base <= MAX_PRIMARY_ADDRESS)
            return "64-bit: .base <= MAX_PRIMARY_ADDRESS in auxmap_L1";
         if (auxmap_L1[i].ent == NULL)
            return "64-bit: .ent is NULL in auxmap_L1";
         if (auxmap_L1[i].ent->base != auxmap_L1[i].base)
            return "64-bit: _L1 and _L2 bases are inconsistent";*/
         /* Look it up in auxmap_L2. */
/*         key.base = auxmap_L1[i].base;
         key.sm   = 0;
         res = VG_(OSetGen_Lookup)(auxmap_L2, &key);
         if (res == NULL)
            return "64-bit: _L1 .base not found in _L2";
         if (res != auxmap_L1[i].ent)
            return "64-bit: _L1 .ent disagrees with _L2 entry";
      }*/
      /* Check L1 contains no duplicates */
/*      for (i = 0; i < N_AUXMAP_L1; i++) {
         if (auxmap_L1[i].base == 0)
            continue;
         for (j = i+1; j < N_AUXMAP_L1; j++) {
            if (auxmap_L1[j].base == 0)
               continue;
            if (auxmap_L1[j].base == auxmap_L1[i].base)
               return "64-bit: duplicate _L1 .base entries";
         }
      }
   }
   return NULL;*/ /* ok */
//}

static void insert_into_auxmap_L1_at ( Word rank, AuxMapEnt* ent )
{
   Word i;
   tl_assert(ent);
   tl_assert(rank >= 0 && rank < N_AUXMAP_L1);
   for (i = N_AUXMAP_L1-1; i > rank; i--)
      auxmap_L1[i] = auxmap_L1[i-1];
   auxmap_L1[rank].base = ent->base;
   auxmap_L1[rank].ent  = ent;
}

static INLINE AuxMapEnt* maybe_find_in_auxmap ( Addr a )
{
   AuxMapEnt  key;
   AuxMapEnt* res;
   Word       i;

   tl_assert(a > MAX_PRIMARY_ADDRESS);
   a &= ~(Addr)0xFFFF;

   /* First search the front-cache, which is a self-organising
      list containing the most popular entries. */

   if (LIKELY(auxmap_L1[0].base == a))
      return auxmap_L1[0].ent;
   if (LIKELY(auxmap_L1[1].base == a)) {
      Addr       t_base = auxmap_L1[0].base;
      AuxMapEnt* t_ent  = auxmap_L1[0].ent;
      auxmap_L1[0].base = auxmap_L1[1].base;
      auxmap_L1[0].ent  = auxmap_L1[1].ent;
      auxmap_L1[1].base = t_base;
      auxmap_L1[1].ent  = t_ent;
      return auxmap_L1[0].ent;
   }

   n_auxmap_L1_searches++;

   for (i = 0; i < N_AUXMAP_L1; i++) {
      if (auxmap_L1[i].base == a) {
         break;
      }
   }
   tl_assert(i >= 0 && i <= N_AUXMAP_L1);

   n_auxmap_L1_cmps += (ULong)(i+1);

   if (i < N_AUXMAP_L1) {
      if (i > 0) {
         Addr       t_base = auxmap_L1[i-1].base;
         AuxMapEnt* t_ent  = auxmap_L1[i-1].ent;
         auxmap_L1[i-1].base = auxmap_L1[i-0].base;
         auxmap_L1[i-1].ent  = auxmap_L1[i-0].ent;
         auxmap_L1[i-0].base = t_base;
         auxmap_L1[i-0].ent  = t_ent;
         i--;
      }
      return auxmap_L1[i].ent;
   }

   n_auxmap_L2_searches++;

   /* First see if we already have it. */
   key.base = a;
   key.sm   = 0;

   res = VG_(OSetGen_Lookup)(auxmap_L2, &key);
   if (res)
      insert_into_auxmap_L1_at( AUXMAP_L1_INSERT_IX, res );
   return res;
}

static AuxMapEnt* find_or_alloc_in_auxmap ( Addr a )
{
   AuxMapEnt *nyu, *res;

   /* First see if we already have it. */
   res = maybe_find_in_auxmap( a );
   if (LIKELY(res))
      return res;

   /* Ok, there's no entry in the secondary map, so we'll have
      to allocate one. */
   a &= ~(Addr)0xFFFF;
   nyu = (AuxMapEnt*) VG_(OSetGen_AllocNode)( auxmap_L2, sizeof(AuxMapEnt) );
   tl_assert(nyu);
   nyu->base = a;
   nyu->sm   = &sm_distinguished[SM_DIST_NOACCESS];
   VG_(OSetGen_Insert)( auxmap_L2, nyu );
   insert_into_auxmap_L1_at( AUXMAP_L1_INSERT_IX, nyu );
   n_auxmap_L2_nodes++;
   return nyu;
}

/* --------------- SecMap fundamentals --------------- */ //586

// In all these, 'low' means it's definitely in the main primary map,
// 'high' means it's definitely in the auxiliary table.

static INLINE SecMap** get_secmap_low_ptr ( Addr a )
{
   UWord pm_off = a >> 16;
//#  if VG_DEBUG_MEMORY >= 1
   tl_assert(pm_off < N_PRIMARY_MAP);
//#  endif
   return &primary_map[ pm_off ];
}

static INLINE SecMap** get_secmap_high_ptr ( Addr a )
{
   AuxMapEnt* am = find_or_alloc_in_auxmap(a);
   return &am->sm;
}

static SecMap** get_secmap_ptr ( Addr a )
{
   return ( a <= MAX_PRIMARY_ADDRESS
          ? get_secmap_low_ptr(a)
          : get_secmap_high_ptr(a));
}

static INLINE SecMap* get_secmap_for_reading_low ( Addr a )
{
   return *get_secmap_low_ptr(a);
}

static INLINE SecMap* get_secmap_for_reading_high ( Addr a )
{
   return *get_secmap_high_ptr(a);
}

static INLINE SecMap* get_secmap_for_writing_low(Addr a)
{
   SecMap** p = get_secmap_low_ptr(a);
   if (UNLIKELY(is_distinguished_sm(*p)))
      *p = copy_for_writing(*p);
   return *p;
}

static INLINE SecMap* get_secmap_for_writing_high ( Addr a )
{
   SecMap** p = get_secmap_high_ptr(a);
   if (UNLIKELY(is_distinguished_sm(*p)))
      *p = copy_for_writing(*p);
   return *p;
}

/* Produce the secmap for 'a', either from the primary map or by
   ensuring there is an entry for it in the aux primary map.  The
   secmap may be a distinguished one as the caller will only want to
   be able to read it.
*/
static INLINE SecMap* get_secmap_for_reading ( Addr a )
{
   return ( a <= MAX_PRIMARY_ADDRESS
          ? get_secmap_for_reading_low (a)
          : get_secmap_for_reading_high(a) );
}

/* Produce the secmap for 'a', either from the primary map or by
   ensuring there is an entry for it in the aux primary map.  The
   secmap may not be a distinguished one, since the caller will want
   to be able to write it.  If it is a distinguished secondary, make a
   writable copy of it, install it, and return the copy instead.  (COW
   semantics).
*/
static SecMap* get_secmap_for_writing ( Addr a )
{
   return ( a <= MAX_PRIMARY_ADDRESS
          ? get_secmap_for_writing_low (a)
          : get_secmap_for_writing_high(a) );
}

/* If 'a' has a SecMap, produce it.  Else produce NULL.  But don't
   allocate one if one doesn't already exist.  This is used by the
   leak checker.
*/
/*static SecMap* maybe_get_secmap_for ( Addr a )
{
   if (a <= MAX_PRIMARY_ADDRESS) {
      return get_secmap_for_reading_low(a);
   } else {
      AuxMapEnt* am = maybe_find_in_auxmap(a);
      return am ? am->sm : NULL;
   }
}*/

/* --------------- Fundamental functions --------------- */

static INLINE
void insert_vabits2_into_vabits8 ( Addr a, UChar vabits2, UChar* vabits8 ) //682
{
   UInt shift =  (a & 3)  << 1;        // shift by 0, 2, 4, or 6
   *vabits8  &= ~(0x3     << shift);   // mask out the two old bits
   *vabits8  |=  (vabits2 << shift);   // mask  in the two new bits
}

static INLINE
void insert_vabits4_into_vabits8 ( Addr a, UChar vabits4, UChar* vabits8 )
{
   UInt shift;
   tl_assert(VG_IS_2_ALIGNED(a));      // Must be 2-aligned
   shift     =  (a & 2)   << 1;        // shift by 0 or 4
   *vabits8 &= ~(0xf      << shift);   // mask out the four old bits
   *vabits8 |=  (vabits4 << shift);    // mask  in the four new bits
}

static INLINE
UChar extract_vabits2_from_vabits8 ( Addr a, UChar vabits8 )
{
   UInt shift = (a & 3) << 1;          // shift by 0, 2, 4, or 6
   vabits8 >>= shift;                  // shift the two bits to the bottom
   return 0x3 & vabits8;               // mask out the rest
}

static INLINE
UChar extract_vabits4_from_vabits8 ( Addr a, UChar vabits8 )
{
   UInt shift;
   tl_assert(VG_IS_2_ALIGNED(a));      // Must be 2-aligned
   shift = (a & 2) << 1;               // shift by 0 or 4
   vabits8 >>= shift;                  // shift the four bits to the bottom
   return 0xf & vabits8;               // mask out the rest
}

// Note that these four are only used in slow cases.  The fast cases do
// clever things like combine the auxmap check (in
// get_secmap_{read,writ}able) with alignment checks.

// *** WARNING! ***
// Any time this function is called, if it is possible that vabits2
// is equal to VA_BITS2_PARTUNTAINTED, then the corresponding entry in the
// sec-V-bits table must also be set!
static INLINE
void set_vabits2 ( Addr a, UChar vabits2 ) //726
{
   SecMap* sm       = get_secmap_for_writing(a); // Taintgrind: only handle 32-bits
   UWord   sm_off   = SM_OFF(a);

#ifdef DBG_MEM
   // Taintgrind
//   if (vabits2 == VA_BITS2_TAINTED)
      VG_(printf)("set_vabits2 a:0x%08lx vabits2:0x%x sm->vabit8[sm_off]:0x%08x\n",
                  a, vabits2, (Int)&(sm->vabits8[sm_off]));
#endif

   insert_vabits2_into_vabits8( a, vabits2, &(sm->vabits8[sm_off]) );
}

// Needed by TNT_(instrument)
//static INLINE
UChar get_vabits2 ( Addr a )
{
   SecMap* sm       = get_secmap_for_reading(a); // Taintgrind: only handle 32-bits
   UWord   sm_off   = SM_OFF(a);
   UChar   vabits8  = sm->vabits8[sm_off];

#ifdef DBG_MEM
   // Taintgrind
   UChar result = extract_vabits2_from_vabits8(a, vabits8);
//   if (vabits2 == VA_BITS2_TAINTED)
      VG_(printf)("get_vabits2 a:0x%08lx vabits2:0x%x sm->vabit8[sm_off]:0x%08x\n",
                  a, result, (Int)&vabits8);
   return result;
#endif
   return extract_vabits2_from_vabits8(a, vabits8);
}

// *** WARNING! ***
// Any time this function is called, if it is possible that any of the
// 4 2-bit fields in vabits8 are equal to VA_BITS2_PARTUNTAINTED, then the
// corresponding entry(s) in the sec-V-bits table must also be set!
static INLINE
UChar get_vabits8_for_aligned_word32 ( Addr a ) //747
{
   SecMap* sm       = get_secmap_for_reading(a);
   UWord   sm_off   = SM_OFF(a);
   UChar   vabits8  = sm->vabits8[sm_off];
   return vabits8;
}

static INLINE
void set_vabits8_for_aligned_word32 ( Addr a, UChar vabits8 )
{
   SecMap* sm       = get_secmap_for_writing(a);
   UWord   sm_off   = SM_OFF(a);
   sm->vabits8[sm_off] = vabits8;
}


// Forward declarations
static UWord get_sec_vbits8(Addr a);
static void  set_sec_vbits8(Addr a, UWord vbits8);

// Returns False if there was an addressability error.
static INLINE
Bool set_vbits8 ( Addr a, UChar vbits8 ) //768
{
   Bool  ok      = True;
   UChar vabits2 = get_vabits2(a);
   if ( VA_BITS2_NOACCESS != vabits2 ) {
      // Addressable.  Convert in-register format to in-memory format.
      // Also remove any existing sec V bit entry for the byte if no
      // longer necessary.
      if      ( V_BITS8_UNTAINTED == vbits8 ) { vabits2 = VA_BITS2_UNTAINTED; }
      else if ( V_BITS8_TAINTED   == vbits8 ) { vabits2 = VA_BITS2_TAINTED;   }
      else                                    { vabits2 = VA_BITS2_PARTUNTAINTED;
                                                set_sec_vbits8(a, vbits8);  }
      set_vabits2(a, vabits2);

   } else {
      // Unaddressable!  Do nothing -- when writing to unaddressable
      // memory it acts as a black hole, and the V bits can never be seen
      // again.  So we don't have to write them at all.
      ok = False;
   }
   return ok;
}

// Returns False if there was an addressability error.  In that case, we put
// all defined bits into vbits8.
static INLINE
Bool get_vbits8 ( Addr a, UChar* vbits8 )
{
   Bool  ok      = True;
   UChar vabits2 = get_vabits2(a);

   // Convert the in-memory format to in-register format.
   if      ( VA_BITS2_UNTAINTED == vabits2 ) { *vbits8 = V_BITS8_UNTAINTED; }
   else if ( VA_BITS2_TAINTED   == vabits2 ) { *vbits8 = V_BITS8_TAINTED;   }
   else if ( VA_BITS2_NOACCESS  == vabits2 ) {
      *vbits8 = V_BITS8_UNTAINTED;    // Make V bits defined!
      ok = False;
   } else {
      tl_assert( VA_BITS2_PARTUNTAINTED == vabits2 );
      *vbits8 = get_sec_vbits8(a);
   }
   return ok;
}

/* --------------- Secondary V bit table ------------ */ //815
static OSet* secVBitTable;

// Stats
static ULong sec_vbits_new_nodes = 0;
static ULong sec_vbits_updates   = 0;

// This must be a power of two;  this is checked in tnt_pre_clo_init().
// The size chosen here is a trade-off:  if the nodes are bigger (ie. cover
// a larger address range) they take more space but we can get multiple
// partially-defined bytes in one if they are close to each other, reducing
// the number of total nodes.  In practice sometimes they are clustered (eg.
// perf/bz2 repeatedly writes then reads more than 20,000 in a contiguous
// row), but often not.  So we choose something intermediate.
#define BYTES_PER_SEC_VBIT_NODE     16

// We make the table bigger if more than this many nodes survive a GC.
#define MAX_SURVIVOR_PROPORTION  0.5

// Each time we make the table bigger, we increase it by this much.
#define TABLE_GROWTH_FACTOR      2

// This defines "sufficiently stale" -- any node that hasn't been touched in
// this many GCs will be removed.
#define MAX_STALE_AGE            2

// We GC the table when it gets this many nodes in it, ie. it's effectively
// the table size.  It can change.
static Int  secVBitLimit = 1024;

// The number of GCs done, used to age sec-V-bit nodes for eviction.
// Because it's unsigned, wrapping doesn't matter -- the right answer will
// come out anyway.
static UInt GCs_done = 0;

typedef
   struct {
      Addr  a;
      UChar vbits8[BYTES_PER_SEC_VBIT_NODE];
      UInt  last_touched;
   }
   SecVBitNode;

static OSet* createSecVBitTable(void)
{
   return VG_(OSetGen_Create)( offsetof(SecVBitNode, a),
                               NULL, // use fast comparisons
                               VG_(malloc), "mc.cSVT.1 (sec VBit table)",
                               VG_(free) );
}

static void gcSecVBitTable(void)
{
   OSet*        secVBitTable2;
   SecVBitNode* n;
   Int          i, n_nodes = 0, n_survivors = 0;

   GCs_done++;

   // Create the new table.
   secVBitTable2 = createSecVBitTable();

   // Traverse the table, moving fresh nodes into the new table.
   VG_(OSetGen_ResetIter)(secVBitTable);
   while ( (n = VG_(OSetGen_Next)(secVBitTable)) ) {
      Bool keep = False;
      if ( (GCs_done - n->last_touched) <= MAX_STALE_AGE ) {
         // Keep node if it's been touched recently enough (regardless of
         // freshness/staleness).
         keep = True;
      } else {
         // Keep node if any of its bytes are non-stale.  Using
         // get_vabits2() for the lookup is not very efficient, but I don't
         // think it matters.
         for (i = 0; i < BYTES_PER_SEC_VBIT_NODE; i++) {
            if (VA_BITS2_PARTUNTAINTED == get_vabits2(n->a + i)) {
               keep = True;      // Found a non-stale byte, so keep
               break;
            }
         }
      }

      if ( keep ) {
         // Insert a copy of the node into the new table.
         SecVBitNode* n2 =
            VG_(OSetGen_AllocNode)(secVBitTable2, sizeof(SecVBitNode));
         *n2 = *n;
         VG_(OSetGen_Insert)(secVBitTable2, n2);
      }
   }

   // Get the before and after sizes.
   n_nodes     = VG_(OSetGen_Size)(secVBitTable);
   n_survivors = VG_(OSetGen_Size)(secVBitTable2);

   // Destroy the old table, and put the new one in its place.
   VG_(OSetGen_Destroy)(secVBitTable);
   secVBitTable = secVBitTable2;

   if (VG_(clo_verbosity) > 1) {
      Char percbuf[6];
      VG_(percentify)(n_survivors, n_nodes, 1, 6, percbuf);
      VG_(message)(Vg_DebugMsg, "tnt_main.c: GC: %d nodes, %d survivors (%s)\n",
                   n_nodes, n_survivors, percbuf);
   }

   // Increase table size if necessary.
   if (n_survivors > (secVBitLimit * MAX_SURVIVOR_PROPORTION)) {
      secVBitLimit *= TABLE_GROWTH_FACTOR;
      if (VG_(clo_verbosity) > 1)
         VG_(message)(Vg_DebugMsg, "tnt_main.c: GC: increase table size to %d\n",
                      secVBitLimit);
   }
}

static UWord get_sec_vbits8(Addr a) //962
{
   Addr         aAligned = VG_ROUNDDN(a, BYTES_PER_SEC_VBIT_NODE);
   Int          amod     = a % BYTES_PER_SEC_VBIT_NODE;
   SecVBitNode* n        = VG_(OSetGen_Lookup)(secVBitTable, &aAligned);
   UChar        vbits8;
   tl_assert2(n, "get_sec_vbits8: no node for address %p (%p)\n", aAligned, a);
   // Shouldn't be fully defined or fully undefined -- those cases shouldn't
   // make it to the secondary V bits table.
   vbits8 = n->vbits8[amod];
   tl_assert(V_BITS8_UNTAINTED != vbits8 && V_BITS8_TAINTED != vbits8);
   return vbits8;
}

static void set_sec_vbits8(Addr a, UWord vbits8)
{
   Addr         aAligned = VG_ROUNDDN(a, BYTES_PER_SEC_VBIT_NODE);
   Int          i, amod  = a % BYTES_PER_SEC_VBIT_NODE;
   SecVBitNode* n        = VG_(OSetGen_Lookup)(secVBitTable, &aAligned);
   // Shouldn't be fully defined or fully undefined -- those cases shouldn't
   // make it to the secondary V bits table.
   tl_assert(V_BITS8_UNTAINTED != vbits8 && V_BITS8_TAINTED != vbits8);
   if (n) {
      n->vbits8[amod] = vbits8;     // update
      n->last_touched = GCs_done;
      sec_vbits_updates++;
   } else {
      // New node:  assign the specific byte, make the rest invalid (they
      // should never be read as-is, but be cautious).
      n = VG_(OSetGen_AllocNode)(secVBitTable, sizeof(SecVBitNode));
      n->a            = aAligned;
      for (i = 0; i < BYTES_PER_SEC_VBIT_NODE; i++) {
         n->vbits8[i] = V_BITS8_TAINTED;
      }
      n->vbits8[amod] = vbits8;
      n->last_touched = GCs_done;

      // Do a table GC if necessary.  Nb: do this before inserting the new
      // node, to avoid erroneously GC'ing the new node.
      if (secVBitLimit == VG_(OSetGen_Size)(secVBitTable)) {
         gcSecVBitTable();
      }

      // Insert the new node.
      VG_(OSetGen_Insert)(secVBitTable, n);
      sec_vbits_new_nodes++;

      n_secVBit_nodes = VG_(OSetGen_Size)(secVBitTable);
      if (n_secVBit_nodes > max_secVBit_nodes)
         max_secVBit_nodes = n_secVBit_nodes;
   }
}

/* --------------- Endianness helpers --------------- */

/* Returns the offset in memory of the byteno-th most significant byte
   in a wordszB-sized word, given the specified endianness. */
static INLINE UWord byte_offset_w ( UWord wordszB, Bool bigendian, //1019
                                    UWord byteno ) {
   return bigendian ? (wordszB-1-byteno) : byteno;
}


/* --------------- Load/store slow cases. --------------- *///1147

static
#ifndef PERF_FAST_LOADV
INLINE
#endif
ULong tnt_LOADVn_slow ( Addr a, SizeT nBits, Bool bigendian )
{
   /* Make up a 64-bit result V word, which contains the loaded data for
      valid addresses and Defined for invalid addresses.  Iterate over
      the bytes in the word, from the most significant down to the
      least. */
   ULong vbits64     = V_BITS64_TAINTED;
   SizeT szB         = nBits / 8;
   SSizeT i;                        // Must be signed.
   SizeT n_addrs_bad = 0;
   Addr  ai;
   Bool  partial_load_exemption_applies;
   UChar vbits8;
   Bool  ok;

   PROF_EVENT(30, "tnt_LOADVn_slow");

   /* ------------ BEGIN semi-fast cases ------------ */
   /* These deal quickly-ish with the common auxiliary primary map
      cases on 64-bit platforms.  Are merely a speedup hack; can be
      omitted without loss of correctness/functionality.  Note that in
      both cases the "sizeof(void*) == 8" causes these cases to be
      folded out by compilers on 32-bit platforms.  These are derived
      from LOADV64 and LOADV32.
   */
   if (LIKELY(sizeof(void*) == 8
                      && nBits == 64 && VG_IS_8_ALIGNED(a))) {
      SecMap* sm       = get_secmap_for_reading(a);
      UWord   sm_off16 = SM_OFF_16(a);
      UWord   vabits16 = ((UShort*)(sm->vabits8))[sm_off16];
      if (LIKELY(vabits16 == VA_BITS16_UNTAINTED))
         return V_BITS64_UNTAINTED;
      if (LIKELY(vabits16 == VA_BITS16_TAINTED))
         return V_BITS64_TAINTED;
      /* else fall into the slow case */
   }
   if (LIKELY(sizeof(void*) == 8
                      && nBits == 32 && VG_IS_4_ALIGNED(a))) {
      SecMap* sm = get_secmap_for_reading(a);
      UWord sm_off = SM_OFF(a);
      UWord vabits8 = sm->vabits8[sm_off];
      if (LIKELY(vabits8 == VA_BITS8_UNTAINTED))
         return ((UWord)0xFFFFFFFF00000000ULL | (UWord)V_BITS32_UNTAINTED);
      if (LIKELY(vabits8 == VA_BITS8_TAINTED))
         return ((UWord)0xFFFFFFFF00000000ULL | (UWord)V_BITS32_TAINTED);
      /* else fall into slow case */
   }
   /* ------------ END semi-fast cases ------------ */

   tl_assert(nBits == 64 || nBits == 32 || nBits == 16 || nBits == 8);

   for (i = szB-1; i >= 0; i--) {
      PROF_EVENT(31, "tnt_LOADVn_slow(loop)");
      ai = a + byte_offset_w(szB, bigendian, i);
      ok = get_vbits8(ai, &vbits8);
      if (!ok) n_addrs_bad++;
      vbits64 <<= 8;
      vbits64 |= vbits8;
   }

   /* This is a hack which avoids producing errors for code which
      insists in stepping along byte strings in aligned word-sized
      chunks, and there is a partially defined word at the end.  (eg,
      optimised strlen).  Such code is basically broken at least WRT
      semantics of ANSI C, but sometimes users don't have the option
      to fix it, and so this option is provided.  Note it is now
      defaulted to not-engaged.

      A load from a partially-addressible place is allowed if:
      - the command-line flag is set
      - it's a word-sized, word-aligned load
      - at least one of the addresses in the word *is* valid
   */
   partial_load_exemption_applies
      = /*TNT_(clo_partial_loads_ok)*/ 0 && szB == VG_WORDSIZE
                                   && VG_IS_WORD_ALIGNED(a)
                                   && n_addrs_bad < VG_WORDSIZE;

//   Taintgrind: TODO
//   if (n_addrs_bad > 0 && !partial_load_exemption_applies)
//      TNT_(record_address_error)( VG_(get_running_tid)(), a, szB, False );

#ifdef DBG_LOAD
   if( nBits == 8 &&
       vbits64
//       || (a & 0x80000000)
       )
      VG_(printf)("tnt_LOADn_slow 0x%08lx 0x%llx\n", a, vbits64);
//      VG_(printf)("tnt_LOADn_slow 0x%08lx\n", a);
#endif

   return vbits64;
}


static
#ifndef PERF_FAST_STOREV
INLINE
#endif
void tnt_STOREVn_slow ( Addr a, SizeT nBits, ULong vbytes, Bool bigendian )
{
   SizeT szB = nBits / 8;
   SizeT i, n_addrs_bad = 0;
   UChar vbits8;
   Addr  ai;
   Bool  ok;

   PROF_EVENT(35, "tnt_STOREVn_slow");

   /* ------------ BEGIN semi-fast cases ------------ */
   /* These deal quickly-ish with the common auxiliary primary map
      cases on 64-bit platforms.  Are merely a speedup hack; can be
      omitted without loss of correctness/functionality.  Note that in
      both cases the "sizeof(void*) == 8" causes these cases to be
      folded out by compilers on 32-bit platforms.  These are derived
      from STOREV64 and STOREV32.
   */
   if (LIKELY(sizeof(void*) == 8
                      && nBits == 64 && VG_IS_8_ALIGNED(a))) {
      SecMap* sm       = get_secmap_for_reading(a);
      UWord   sm_off16 = SM_OFF_16(a);
      UWord   vabits16 = ((UShort*)(sm->vabits8))[sm_off16];
      if (LIKELY( !is_distinguished_sm(sm) &&
                          (VA_BITS16_UNTAINTED == vabits16 ||
                           VA_BITS16_TAINTED   == vabits16) )) {
         /* Handle common case quickly: a is suitably aligned, */
         /* is mapped, and is addressible. */
         // Convert full V-bits in register to compact 2-bit form.
         if (LIKELY(V_BITS64_UNTAINTED == vbytes)) {
            ((UShort*)(sm->vabits8))[sm_off16] = (UShort)VA_BITS16_UNTAINTED;
            return;
         } else if (V_BITS64_TAINTED == vbytes) {
            ((UShort*)(sm->vabits8))[sm_off16] = (UShort)VA_BITS16_TAINTED;
            return;
         }
         /* else fall into the slow case */
      }
      /* else fall into the slow case */
   }
   if (LIKELY(sizeof(void*) == 8
                      && nBits == 32 && VG_IS_4_ALIGNED(a))) {
      SecMap* sm      = get_secmap_for_reading(a);
      UWord   sm_off  = SM_OFF(a);
      UWord   vabits8 = sm->vabits8[sm_off];
      if (LIKELY( !is_distinguished_sm(sm) &&
                          (VA_BITS8_UNTAINTED   == vabits8 ||
                           VA_BITS8_TAINTED == vabits8) )) {
         /* Handle common case quickly: a is suitably aligned, */
         /* is mapped, and is addressible. */
         // Convert full V-bits in register to compact 2-bit form.
         if (LIKELY(V_BITS32_UNTAINTED == (vbytes & 0xFFFFFFFF))) {
            sm->vabits8[sm_off] = VA_BITS8_UNTAINTED;
            return;
         } else if (V_BITS32_TAINTED == (vbytes & 0xFFFFFFFF)) {
            sm->vabits8[sm_off] = VA_BITS8_TAINTED;
            return;
         }
         /* else fall into the slow case */
      }
      /* else fall into the slow case */
   }
   /* ------------ END semi-fast cases ------------ */

   tl_assert(nBits == 64 || nBits == 32 || nBits == 16 || nBits == 8);

   /* Dump vbytes in memory, iterating from least to most significant
      byte.  At the same time establish addressibility of the location. */
   for (i = 0; i < szB; i++) {
      PROF_EVENT(36, "tnt_STOREVn_slow(loop)");
      ai     = a + byte_offset_w(szB, bigendian, i);
      vbits8 = vbytes & 0xff;
      ok     = set_vbits8(ai, vbits8);
      if (!ok) n_addrs_bad++;
      vbytes >>= 8;
   }

   /* If an address error has happened, report it. */
   // Taintgrind: TODO
//   if (n_addrs_bad > 0)
//      TNT_(record_address_error)( VG_(get_running_tid)(), a, szB, True );
}
                                                                 

/*------------------------------------------------------------*/
/*--- Setting permissions over address ranges.             ---*/
/*------------------------------------------------------------*/

static void set_address_range_perms ( Addr a, SizeT lenT, UWord vabits16,
                                      UWord dsm_num ) //1329
{
   UWord    sm_off, sm_off16;
   UWord    vabits2 = vabits16 & 0x3;
   SizeT    lenA, lenB, len_to_next_secmap;
   Addr     aNext;
   SecMap*  sm;
   SecMap** sm_ptr;
   SecMap*  example_dsm;

   PROF_EVENT(150, "set_address_range_perms");

   /* Check the V+A bits make sense. */
   tl_assert(VA_BITS16_NOACCESS  == vabits16 ||
             VA_BITS16_TAINTED   == vabits16 ||
             VA_BITS16_UNTAINTED == vabits16);

   // This code should never write PDBs;  ensure this.  (See comment above
   // set_vabits2().)
   tl_assert(VA_BITS2_PARTUNTAINTED != vabits2);

   if (lenT == 0)
      return;

   if (lenT > 256 * 1024 * 1024) {
      if (VG_(clo_verbosity) > 0 && !VG_(clo_xml)) {
         Char* s = "unknown???";
         if (vabits16 == VA_BITS16_NOACCESS ) s = "noaccess";
         if (vabits16 == VA_BITS16_TAINTED  ) s = "tainted";
         if (vabits16 == VA_BITS16_UNTAINTED) s = "untainted";
         VG_(message)(Vg_UserMsg, "Warning: set address range perms: "
                                  "large range [0x%lx, 0x%lx) (%s)\n",
                                  a, a + lenT, s);
      }
   }

#ifndef PERF_FAST_SARP
   /*------------------ debug-only case ------------------ */
   {
      // Endianness doesn't matter here because all bytes are being set to
      // the same value.
      // Nb: We don't have to worry about updating the sec-V-bits table
      // after these set_vabits2() calls because this code never writes
      // VA_BITS2_PARTUNTAINTED values.
      SizeT i;
      for (i = 0; i < lenT; i++) {
         set_vabits2(a + i, vabits2);
      }
      return;
   }
#endif

   /*------------------ standard handling ------------------ */

   /* Get the distinguished secondary that we might want
      to use (part of the space-compression scheme). */
   example_dsm = &sm_distinguished[dsm_num];

   // Break up total length (lenT) into two parts:  length in the first
   // sec-map (lenA), and the rest (lenB);   lenT == lenA + lenB.
   aNext = start_of_this_sm(a) + SM_SIZE;
   len_to_next_secmap = aNext - a;
   if ( lenT <= len_to_next_secmap ) {
      // Range entirely within one sec-map.  Covers almost all cases.
      PROF_EVENT(151, "set_address_range_perms-single-secmap");
      lenA = lenT;
      lenB = 0;
   } else if (is_start_of_sm(a)) {
      // Range spans at least one whole sec-map, and starts at the beginning
      // of a sec-map; skip to Part 2.
      PROF_EVENT(152, "set_address_range_perms-startof-secmap");
      lenA = 0;
      lenB = lenT;
      goto part2;
   } else {
      // Range spans two or more sec-maps, first one is partial.
      PROF_EVENT(153, "set_address_range_perms-multiple-secmaps");
      lenA = len_to_next_secmap;
      lenB = lenT - lenA;
   }

#ifdef DBG_MEM
   // Taintgrind
   VG_(printf)("set_address_range_perms(0) lenA:0x%x lenB:0x%x\n", (Int)lenA, (Int)lenB);
#endif

   //------------------------------------------------------------------------
   // Part 1: Deal with the first sec_map.  Most of the time the range will be
   // entirely within a sec_map and this part alone will suffice.  Also,
   // doing it this way lets us avoid repeatedly testing for the crossing of
   // a sec-map boundary within these loops.
   //------------------------------------------------------------------------

   // If it's distinguished, make it undistinguished if necessary.
   sm_ptr = get_secmap_ptr(a);
   if (is_distinguished_sm(*sm_ptr)) {
      if (*sm_ptr == example_dsm) {
         // Sec-map already has the V+A bits that we want, so skip.
         PROF_EVENT(154, "set_address_range_perms-dist-sm1-quick");
         a    = aNext;
         lenA = 0;
      } else {
         PROF_EVENT(155, "set_address_range_perms-dist-sm1");
         *sm_ptr = copy_for_writing(*sm_ptr);
      }
   }
   sm = *sm_ptr;

   // 1 byte steps
   while (True) {
      if (VG_IS_8_ALIGNED(a)) break;
      if (lenA < 1)           break;
      PROF_EVENT(156, "set_address_range_perms-loop1a");
      sm_off = SM_OFF(a);

#ifdef DBG_MEM
      // Taintgrind
      VG_(printf)("set_address_range_perms(1.1) a:0x%08lx vabits2:0x%lx sm->vabit8[sm_off]:0x%08x\n",
                  a, vabits2, (Int)&(sm->vabits8[sm_off]));
#endif
      insert_vabits2_into_vabits8( a, vabits2, &(sm->vabits8[sm_off]) );
      a    += 1;
      lenA -= 1;
   }
   // 8-aligned, 8 byte steps
   while (True) {
      if (lenA < 8) break;
      PROF_EVENT(157, "set_address_range_perms-loop8a");
      sm_off16 = SM_OFF_16(a);

#ifdef DBG_MEM
      // Taintgrind
      VG_(printf)("set_address_range_perms(1.2) sm->vabits8:0x%08x sm_off16:0x%lx vabits16:0x%08lx\n",
                 (Int) ((UShort*)(sm->vabits8)), sm_off16, vabits16);
#endif
      ((UShort*)(sm->vabits8))[sm_off16] = vabits16;
      a    += 8;
      lenA -= 8;
   }
   // 1 byte steps
   while (True) {
      if (lenA < 1) break;
      PROF_EVENT(158, "set_address_range_perms-loop1b");
      sm_off = SM_OFF(a);

#ifdef DBG_MEM
      // Taintgrind
      VG_(printf)("set_address_range_perms(1.3) a:0x%08lx vabits2:0x%lx sm->vabits8[sm_off]:0x%08x\n",
                  a, vabits2, (Int)&(sm->vabits8[sm_off]));
#endif
      insert_vabits2_into_vabits8( a, vabits2, &(sm->vabits8[sm_off]) );
      a    += 1;
      lenA -= 1;
   }

   // We've finished the first sec-map.  Is that it?
   if (lenB == 0)
      return;

   //------------------------------------------------------------------------
   // Part 2: Fast-set entire sec-maps at a time.
   //------------------------------------------------------------------------
  part2:
   // 64KB-aligned, 64KB steps.
   // Nb: we can reach here with lenB < SM_SIZE
   tl_assert(0 == lenA);
   while (True) {
      if (lenB < SM_SIZE) break;
      tl_assert(is_start_of_sm(a));
      PROF_EVENT(159, "set_address_range_perms-loop64K");
      sm_ptr = get_secmap_ptr(a);
      if (!is_distinguished_sm(*sm_ptr)) {
         PROF_EVENT(160, "set_address_range_perms-loop64K-free-dist-sm");
         // Free the non-distinguished sec-map that we're replacing.  This
         // case happens moderately often, enough to be worthwhile.
         VG_(am_munmap_valgrind)((Addr)*sm_ptr, sizeof(SecMap));
      }
      update_SM_counts(*sm_ptr, example_dsm);
      // Make the sec-map entry point to the example DSM
      *sm_ptr = example_dsm;
      lenB -= SM_SIZE;
      a    += SM_SIZE;
   }

   // We've finished the whole sec-maps.  Is that it?
   if (lenB == 0)
      return;

   //------------------------------------------------------------------------
   // Part 3: Finish off the final partial sec-map, if necessary.
   //------------------------------------------------------------------------

   tl_assert(is_start_of_sm(a) && lenB < SM_SIZE);

   // If it's distinguished, make it undistinguished if necessary.
   sm_ptr = get_secmap_ptr(a);
   if (is_distinguished_sm(*sm_ptr)) {
      if (*sm_ptr == example_dsm) {
         // Sec-map already has the V+A bits that we want, so stop.
         PROF_EVENT(161, "set_address_range_perms-dist-sm2-quick");
         return;
      } else {
         PROF_EVENT(162, "set_address_range_perms-dist-sm2");
         *sm_ptr = copy_for_writing(*sm_ptr);
      }
   }
   sm = *sm_ptr;

   // 8-aligned, 8 byte steps
   while (True) {
      if (lenB < 8) break;
      PROF_EVENT(163, "set_address_range_perms-loop8b");
      sm_off16 = SM_OFF_16(a);
      ((UShort*)(sm->vabits8))[sm_off16] = vabits16;
      a    += 8;
      lenB -= 8;
   }
   // 1 byte steps
   while (True) {
      if (lenB < 1) return;
      PROF_EVENT(164, "set_address_range_perms-loop1c");
      sm_off = SM_OFF(a);
      insert_vabits2_into_vabits8( a, vabits2, &(sm->vabits8[sm_off]) );
      a    += 1;
      lenB -= 1;
   }
}


/* --- Set permissions for arbitrary address ranges --- */

void TNT_(make_mem_noaccess) ( Addr a, SizeT len )
{
   PROF_EVENT(40, "TNT_(make_mem_noaccess)");
//   DEBUG("TNT_(make_mem_noaccess)(%p, %lu)\n", a, len);
   set_address_range_perms ( a, len, VA_BITS16_NOACCESS, SM_DIST_NOACCESS );
//   if (UNLIKELY( TNT_(clo_tnt_level) == 3 ))
//      ocache_sarp_Clear_Origins ( a, len );
}

void TNT_(make_mem_tainted) ( Addr a, SizeT len )//1608
{
   PROF_EVENT(42, "TNT_(make_mem_undefined)");
//   DEBUG("TNT_(make_mem_undefined)(%p, %lu)\n", a, len);
   set_address_range_perms ( a, len, VA_BITS16_TAINTED, SM_DIST_TAINTED );
//   if (UNLIKELY( TNT_(clo_tnt_level) == 3 ))
//      ocache_sarp_Clear_Origins ( a, len );
}

void TNT_(make_mem_defined) ( Addr a, SizeT len )
{
   PROF_EVENT(42, "TNT_(make_mem_defined)");
//   DEBUG("TNT_(make_mem_defined)(%p, %lu)\n", a, len);
   set_address_range_perms ( a, len, VA_BITS16_UNTAINTED, SM_DIST_UNTAINTED );
//   if (UNLIKELY( TNT_(clo_tnt_level) == 3 ))
//      ocache_sarp_Clear_Origins ( a, len );
}


/* --- Block-copy permissions (needed for implementing realloc() and
       sys_mremap). --- */

void TNT_(copy_address_range_state) ( Addr src, Addr dst, SizeT len ) //1687
{
   SizeT i, j;
   UChar vabits2, vabits8;
   Bool  aligned, nooverlap;

#ifdef DBG_COPY_ADDR_RANGE_STATE
   VG_(printf)( "copy_addr_range_state 0x%x 0x%x 0x%x\n", (Int)src, (Int)dst, (Int)len );
#endif
//   DEBUG("TNT_(copy_address_range_state)\n");
   PROF_EVENT(50, "TNT_(copy_address_range_state)");

   if (len == 0 || src == dst)
      return;

   aligned   = VG_IS_4_ALIGNED(src) && VG_IS_4_ALIGNED(dst);
   nooverlap = src+len <= dst || dst+len <= src;

   if (nooverlap && aligned) {

      /* Vectorised fast case, when no overlap and suitably aligned */
      /* vector loop */
      i = 0;
      while (len >= 4) {
         vabits8 = get_vabits8_for_aligned_word32( src+i );
         set_vabits8_for_aligned_word32( dst+i, vabits8 );
         if (LIKELY(VA_BITS8_UNTAINTED == vabits8
                            || VA_BITS8_TAINTED == vabits8
                            || VA_BITS8_NOACCESS == vabits8)) {
            /* do nothing */
         } else {
            /* have to copy secondary map info */
            if (VA_BITS2_PARTUNTAINTED == get_vabits2( src+i+0 ))
               set_sec_vbits8( dst+i+0, get_sec_vbits8( src+i+0 ) );
            if (VA_BITS2_PARTUNTAINTED == get_vabits2( src+i+1 ))
               set_sec_vbits8( dst+i+1, get_sec_vbits8( src+i+1 ) );
            if (VA_BITS2_PARTUNTAINTED == get_vabits2( src+i+2 ))
               set_sec_vbits8( dst+i+2, get_sec_vbits8( src+i+2 ) );
            if (VA_BITS2_PARTUNTAINTED == get_vabits2( src+i+3 ))
               set_sec_vbits8( dst+i+3, get_sec_vbits8( src+i+3 ) );
         }
         i += 4;
         len -= 4;
      }
      /* fixup loop */
      while (len >= 1) {
         vabits2 = get_vabits2( src+i );
         set_vabits2( dst+i, vabits2 );
         if (VA_BITS2_PARTUNTAINTED == vabits2) {
            set_sec_vbits8( dst+i, get_sec_vbits8( src+i ) );
         }
         i++;
         len--;
      }

   } else {

      /* We have to do things the slow way */
      if (src < dst) {
         for (i = 0, j = len-1; i < len; i++, j--) {
            PROF_EVENT(51, "TNT_(copy_address_range_state)(loop)");
            vabits2 = get_vabits2( src+j );
            set_vabits2( dst+j, vabits2 );
            if (VA_BITS2_PARTUNTAINTED == vabits2) {
               set_sec_vbits8( dst+j, get_sec_vbits8( src+j ) );
            }
         }
      }

      if (src > dst) {
         for (i = 0; i < len; i++) {
            PROF_EVENT(52, "TNT_(copy_address_range_state)(loop)");
            vabits2 = get_vabits2( src+i );
            set_vabits2( dst+i, vabits2 );
            if (VA_BITS2_PARTUNTAINTED == vabits2) {
               set_sec_vbits8( dst+i, get_sec_vbits8( src+i ) );
            }
         }
      }
   }

}

/*static
void tnt_new_mem_mmap ( Addr a, SizeT len, Bool rr, Bool ww, Bool xx, //3873
                       ULong di_handle )
{
   if (rr || ww || xx)
      TNT_(make_mem_defined)(a, len);
   else
      TNT_(make_mem_noaccess)(a, len);
}*/

//3311
void TNT_(helperc_MAKE_STACK_UNINIT) ( Addr base, UWord len, Addr nia )
{
   UInt otag;
   tl_assert(sizeof(UWord) == sizeof(SizeT));
   if (0)
      VG_(printf)("helperc_MAKE_STACK_UNINIT (%#lx,%lu,nia=%#lx)\n",
                  base, len, nia );

/*   if (UNLIKELY( MC_(clo_mc_level) == 3 )) {
      UInt ecu = convert_nia_to_ecu ( nia );
      tl_assert(VG_(is_plausible_ECU)(ecu));
      otag = ecu | MC_OKIND_STACK;
   } else {*/
      tl_assert(nia == 0);
      otag = 0;
/*   }*/

   /* Idea is: go fast when
         * 8-aligned and length is 128
         * the sm is available in the main primary map
         * the address range falls entirely with a single secondary map
      If all those conditions hold, just update the V+A bits by writing
      directly into the vabits array.  (If the sm was distinguished, this
      will make a copy and then write to it.)
   */

   if (LIKELY( len == 128 && VG_IS_8_ALIGNED(base) )) {
      /* Now we know the address range is suitably sized and aligned. */
      UWord a_lo = (UWord)(base);
      UWord a_hi = (UWord)(base + 128 - 1);
      tl_assert(a_lo < a_hi);             // paranoia: detect overflow
      if (a_hi <= MAX_PRIMARY_ADDRESS) {
         // Now we know the entire range is within the main primary map.
         SecMap* sm    = get_secmap_for_writing_low(a_lo);
         SecMap* sm_hi = get_secmap_for_writing_low(a_hi);
         /* Now we know that the entire address range falls within a
            single secondary map, and that that secondary 'lives' in
            the main primary map. */
         if (LIKELY(sm == sm_hi)) {
            // Finally, we know that the range is entirely within one secmap.
            UWord   v_off = SM_OFF(a_lo);
            UShort* p     = (UShort*)(&sm->vabits8[v_off]);
            p[ 0] = VA_BITS16_TAINTED;
            p[ 1] = VA_BITS16_TAINTED;
            p[ 2] = VA_BITS16_TAINTED;
            p[ 3] = VA_BITS16_TAINTED;
            p[ 4] = VA_BITS16_TAINTED;
            p[ 5] = VA_BITS16_TAINTED;
            p[ 6] = VA_BITS16_TAINTED;
            p[ 7] = VA_BITS16_TAINTED;
            p[ 8] = VA_BITS16_TAINTED;
            p[ 9] = VA_BITS16_TAINTED;
            p[10] = VA_BITS16_TAINTED;
            p[11] = VA_BITS16_TAINTED;
            p[12] = VA_BITS16_TAINTED;
            p[13] = VA_BITS16_TAINTED;
            p[14] = VA_BITS16_TAINTED;
            p[15] = VA_BITS16_TAINTED;
            return;
         }
      }
   }

   /* 288 bytes (36 ULongs) is the magic value for ELF ppc64. */
   if (LIKELY( len == 288 && VG_IS_8_ALIGNED(base) )) {
      /* Now we know the address range is suitably sized and aligned. */
      UWord a_lo = (UWord)(base);
      UWord a_hi = (UWord)(base + 288 - 1);
      tl_assert(a_lo < a_hi);             // paranoia: detect overflow
      if (a_hi <= MAX_PRIMARY_ADDRESS) {
         // Now we know the entire range is within the main primary map.
         SecMap* sm    = get_secmap_for_writing_low(a_lo);
         SecMap* sm_hi = get_secmap_for_writing_low(a_hi);
         /* Now we know that the entire address range falls within a
            single secondary map, and that that secondary 'lives' in
            the main primary map. */
         if (LIKELY(sm == sm_hi)) {
            // Finally, we know that the range is entirely within one secmap.
            UWord   v_off = SM_OFF(a_lo);
            UShort* p     = (UShort*)(&sm->vabits8[v_off]);
            p[ 0] = VA_BITS16_TAINTED;
            p[ 1] = VA_BITS16_TAINTED;
            p[ 2] = VA_BITS16_TAINTED;
            p[ 3] = VA_BITS16_TAINTED;
            p[ 4] = VA_BITS16_TAINTED;
            p[ 5] = VA_BITS16_TAINTED;
            p[ 6] = VA_BITS16_TAINTED;
            p[ 7] = VA_BITS16_TAINTED;
            p[ 8] = VA_BITS16_TAINTED;
            p[ 9] = VA_BITS16_TAINTED;
            p[10] = VA_BITS16_TAINTED;
            p[11] = VA_BITS16_TAINTED;
            p[12] = VA_BITS16_TAINTED;
            p[13] = VA_BITS16_TAINTED;
            p[14] = VA_BITS16_TAINTED;
            p[15] = VA_BITS16_TAINTED;
            p[16] = VA_BITS16_TAINTED;
            p[17] = VA_BITS16_TAINTED;
            p[18] = VA_BITS16_TAINTED;
            p[19] = VA_BITS16_TAINTED;
            p[20] = VA_BITS16_TAINTED;
            p[21] = VA_BITS16_TAINTED;
            p[22] = VA_BITS16_TAINTED;
            p[23] = VA_BITS16_TAINTED;
            p[24] = VA_BITS16_TAINTED;
            p[25] = VA_BITS16_TAINTED;
            p[26] = VA_BITS16_TAINTED;
            p[27] = VA_BITS16_TAINTED;
            p[28] = VA_BITS16_TAINTED;
            p[29] = VA_BITS16_TAINTED;
            p[30] = VA_BITS16_TAINTED;
            p[31] = VA_BITS16_TAINTED;
            p[32] = VA_BITS16_TAINTED;
            p[33] = VA_BITS16_TAINTED;
            p[34] = VA_BITS16_TAINTED;
            p[35] = VA_BITS16_TAINTED;
            return;
         }
      }
   }

   /* else fall into slow case */
//   TNT_(make_mem_undefined_w_otag)(base, len, otag);
   TNT_(make_mem_tainted)(base, len);
}


//3997
/*------------------------------------------------------------*/
/*--- Functions called directly from generated code:       ---*/
/*--- Load/store handlers.                                 ---*/
/*------------------------------------------------------------*/

/* If any part of '_a' indicated by the mask is 1, either '_a' is not
   naturally '_sz/8'-aligned, or it exceeds the range covered by the
   primary map.  This is all very tricky (and important!), so let's
   work through the maths by hand (below), *and* assert for these
   values at startup. */
#define MASK(_szInBytes) \
   ( ~((0x10000UL-(_szInBytes)) | ((N_PRIMARY_MAP-1) << 16)) )

/* MASK only exists so as to define this macro. */
#define UNALIGNED_OR_HIGH(_a,_szInBits) \
   ((_a) & MASK((_szInBits>>3)))

/* ------------------------ Size = 8 ------------------------ */

static INLINE
ULong tnt_LOADV64 ( Addr a, Bool isBigEndian )
{
   PROF_EVENT(200, "tnt_LOADV64");

#ifndef PERF_FAST_LOADV
   return tnt_LOADVn_slow( a, 64, isBigEndian );
#else
   {
      UWord   sm_off16, vabits16;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,64) )) {
         PROF_EVENT(201, "tnt_LOADV64-slow1");
         return (ULong)tnt_LOADVn_slow( a, 64, isBigEndian );
      }

      sm       = get_secmap_for_reading_low(a);
      sm_off16 = SM_OFF_16(a);
      vabits16 = ((UShort*)(sm->vabits8))[sm_off16];

      // Handle common case quickly: a is suitably aligned, is mapped, and
      // addressible.
      // Convert V bits from compact memory form to expanded register form.
      if (LIKELY(vabits16 == VA_BITS16_UNTAINTED)) {
         return V_BITS64_UNTAINTED;
      } else if (LIKELY(vabits16 == VA_BITS16_TAINTED)) {
         return V_BITS64_TAINTED;
      } else {
         /* Slow case: the 8 bytes are not all-defined or all-undefined. */
         PROF_EVENT(202, "tnt_LOADV64-slow2");
         return tnt_LOADVn_slow( a, 64, isBigEndian );
      }
   }
#endif
}

VG_REGPARM(1) ULong TNT_(helperc_LOADV64be) ( Addr a )
{
   return tnt_LOADV64(a, True);
}
VG_REGPARM(1) ULong TNT_(helperc_LOADV64le) ( Addr a )
{
   ULong result = tnt_LOADV64(a, False);

#ifdef DBG_LOAD
   // Taintgrind
   if( result
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_LOADV64le) 0x%08lx 0x%llx\n", a, result);
//      VG_(printf)("TNT_(helperc_LOADV64le) 64 0x%08lx\n", a);
#endif

   return result;
//   return tnt_LOADV64(a, False);
}


static INLINE
void tnt_STOREV64 ( Addr a, ULong vbits64, Bool isBigEndian )
{
   PROF_EVENT(210, "tnt_STOREV64");

#ifndef PERF_FAST_STOREV
   // XXX: this slow case seems to be marginally faster than the fast case!
   // Investigate further.
   tnt_STOREVn_slow( a, 64, vbits64, isBigEndian );
#else
   {
      UWord   sm_off16, vabits16;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,64) )) {
         PROF_EVENT(211, "tnt_STOREV64-slow1");
         tnt_STOREVn_slow( a, 64, vbits64, isBigEndian );
         return;
      }

      sm       = get_secmap_for_reading_low(a);
      sm_off16 = SM_OFF_16(a);
      vabits16 = ((UShort*)(sm->vabits8))[sm_off16];

      if (LIKELY( !is_distinguished_sm(sm) &&
                          (VA_BITS16_UNTAINTED   == vabits16 ||
                           VA_BITS16_TAINTED == vabits16) ))
      {
         /* Handle common case quickly: a is suitably aligned, */
         /* is mapped, and is addressible. */
         // Convert full V-bits in register to compact 2-bit form.
         if (V_BITS64_UNTAINTED == vbits64) {
            ((UShort*)(sm->vabits8))[sm_off16] = (UShort)VA_BITS16_UNTAINTED;
         } else if (V_BITS64_TAINTED == vbits64) {
            ((UShort*)(sm->vabits8))[sm_off16] = (UShort)VA_BITS16_TAINTED;
         } else {
            /* Slow but general case -- writing partially defined bytes. */
            PROF_EVENT(212, "tnt_STOREV64-slow2");
            tnt_STOREVn_slow( a, 64, vbits64, isBigEndian );
         }
      } else {
         /* Slow but general case. */
         PROF_EVENT(213, "tnt_STOREV64-slow3");
         tnt_STOREVn_slow( a, 64, vbits64, isBigEndian );
      }
   }
#endif
}

VG_REGPARM(1) void TNT_(helperc_STOREV64be) ( Addr a, ULong vbits64 )
{
#ifdef DBG_STORE
   // Taintgrind
   if( vbits64
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_STOREV64be) 0x%08lx 0x%llx\n", a, vbits64);
//      VG_(printf)("TNT_(helperc_STOREV64be) 64 0x%08lx\n", a);
#endif

   tnt_STOREV64(a, vbits64, True);
}
VG_REGPARM(1) void TNT_(helperc_STOREV64le) ( Addr a, ULong vbits64 )
{
#ifdef DBG_STORE
   // Taintgrind
   if( vbits64
//      || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_STOREV64le) 0x%08lx 0x%llx\n", a, vbits64);
//      VG_(printf)("TNT_(helperc_STOREV64le) 64 0x%08lx\n", a);
#endif

   tnt_STOREV64(a, vbits64, False);
}

/* ------------------------ Size = 4 ------------------------ */

static INLINE
UWord tnt_LOADV32 ( Addr a, Bool isBigEndian )
{
   PROF_EVENT(220, "tnt_LOADV32");

#ifndef PERF_FAST_LOADV
   return (UWord)tnt_LOADVn_slow( a, 32, isBigEndian );
#else
   {
      UWord   sm_off, vabits8;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,32) )) {
         PROF_EVENT(221, "tnt_LOADV32-slow1");
         return (UWord)tnt_LOADVn_slow( a, 32, isBigEndian );
      }

      sm      = get_secmap_for_reading_low(a);
      sm_off  = SM_OFF(a);
      vabits8 = sm->vabits8[sm_off];

      // Handle common case quickly: a is suitably aligned, is mapped, and the
      // entire word32 it lives in is addressible.
      // Convert V bits from compact memory form to expanded register form.
      // For 64-bit platforms, set the high 32 bits of retval to 1 (undefined).
      // Almost certainly not necessary, but be paranoid.
      if (LIKELY(vabits8 == VA_BITS8_UNTAINTED)) {
         return ((UWord)0xFFFFFFFF00000000ULL | (UWord)V_BITS32_UNTAINTED);
      } else if (LIKELY(vabits8 == VA_BITS8_TAINTED)) {
         return ((UWord)0xFFFFFFFF00000000ULL | (UWord)V_BITS32_TAINTED);
      } else {
         /* Slow case: the 4 bytes are not all-defined or all-undefined. */
         PROF_EVENT(222, "tnt_LOADV32-slow2");
         return (UWord)tnt_LOADVn_slow( a, 32, isBigEndian );
      }
   }
#endif
}

VG_REGPARM(1) UWord TNT_(helperc_LOADV32be) ( Addr a )
{
   UWord result = tnt_LOADV32(a, True);

#ifdef DBG_LOAD
   // Taintgrind
   if( result
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_LOADV32be) 0x%08lx 0x%lx\n", a, result);
//      VG_(printf)("TNT_(helperc_LOADV32be) 32 0x%08lx\n", a);
#endif

   return result;
//   return tnt_LOADV32(a, True);
}

VG_REGPARM(1) UWord TNT_(helperc_LOADV32le) ( Addr a )
{
   UWord result = tnt_LOADV32(a, False);

#ifdef DBG_LOAD
   // Taintgrind
   if( result
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_LOADV32le) 0x%08lx 0x%lx\n", a, result);
//      VG_(printf)("TNT_(helperc_LOADV32le) 32 0x%08lx\n", a);
#endif

   return result;
//   return tnt_LOADV32(a, False);
}


static INLINE
void tnt_STOREV32 ( Addr a, UWord vbits32, Bool isBigEndian )
{
   PROF_EVENT(230, "tnt_STOREV32");

#ifndef PERF_FAST_STOREV
   tnt_STOREVn_slow( a, 32, (ULong)vbits32, isBigEndian );
#else
   {
      UWord   sm_off, vabits8;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,32) )) {
         PROF_EVENT(231, "tnt_STOREV32-slow1");
         tnt_STOREVn_slow( a, 32, (ULong)vbits32, isBigEndian );
         return;
      }

      sm      = get_secmap_for_reading_low(a);
      sm_off  = SM_OFF(a);
      vabits8 = sm->vabits8[sm_off];

      // Cleverness:  sometimes we don't have to write the shadow memory at
      // all, if we can tell that what we want to write is the same as what is
      // already there.  The 64/16/8 bit cases also have cleverness at this
      // point, but it works a little differently to the code below.
      if (V_BITS32_UNTAINTED == vbits32) {
         if (vabits8 == (UInt)VA_BITS8_UNTAINTED) {
            return;
         } else if (!is_distinguished_sm(sm) && VA_BITS8_TAINTED == vabits8) {
            sm->vabits8[sm_off] = (UInt)VA_BITS8_UNTAINTED;
         } else {
            // not defined/undefined, or distinguished and changing state
            PROF_EVENT(232, "tnt_STOREV32-slow2");
            tnt_STOREVn_slow( a, 32, (ULong)vbits32, isBigEndian );
         }
      } else if (V_BITS32_TAINTED == vbits32) {
         if (vabits8 == (UInt)VA_BITS8_TAINTED) {
            return;
         } else if (!is_distinguished_sm(sm) && VA_BITS8_UNTAINTED == vabits8) {
            sm->vabits8[sm_off] = (UInt)VA_BITS8_TAINTED;
         } else {
            // not defined/undefined, or distinguished and changing state
            PROF_EVENT(233, "tnt_STOREV32-slow3");
            tnt_STOREVn_slow( a, 32, (ULong)vbits32, isBigEndian );
         }
      } else {
         // Partially defined word
         PROF_EVENT(234, "tnt_STOREV32-slow4");
         tnt_STOREVn_slow( a, 32, (ULong)vbits32, isBigEndian );
      }
   }
#endif
}

VG_REGPARM(2) void TNT_(helperc_STOREV32be) ( Addr a, UWord vbits32 )
{
#ifdef DBG_STORE
   // Taintgrind
   if( vbits32
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_STOREV32be) 0x%08lx 0x%lx\n", a, vbits32);
//      VG_(printf)("TNT_(helperc_STOREV32be) 32 0x%08lx\n", a);
#endif

   tnt_STOREV32(a, vbits32, True);
}
VG_REGPARM(2) void TNT_(helperc_STOREV32le) ( Addr a, UWord vbits32 )
{
#ifdef DBG_STORE
   // Taintgrind
   if( vbits32
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_STOREV32le) 0x%08lx 0x%lx\n", a, vbits32);
//      VG_(printf)("TNT_(helperc_STOREV32le) 32 0x%08lx\n", a);
#endif

   tnt_STOREV32(a, vbits32, False);
}


/* ------------------------ Size = 2 ------------------------ */

static INLINE
UWord tnt_LOADV16 ( Addr a, Bool isBigEndian )
{
   PROF_EVENT(240, "tnt_LOADV16");

#ifndef PERF_FAST_LOADV
   return (UWord)tnt_LOADVn_slow( a, 16, isBigEndian );
#else
   {
      UWord   sm_off, vabits8;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,16) )) {
         PROF_EVENT(241, "tnt_LOADV16-slow1");
         return (UWord)tnt_LOADVn_slow( a, 16, isBigEndian );
      }

      sm      = get_secmap_for_reading_low(a);
      sm_off  = SM_OFF(a);
      vabits8 = sm->vabits8[sm_off];
      // Handle common case quickly: a is suitably aligned, is mapped, and is
      // addressible.
      // Convert V bits from compact memory form to expanded register form
      if      (vabits8 == VA_BITS8_UNTAINTED  ) { return V_BITS16_UNTAINTED;   }
      else if (vabits8 == VA_BITS8_TAINTED) { return V_BITS16_TAINTED; }
      else {
         // The 4 (yes, 4) bytes are not all-defined or all-undefined, check
         // the two sub-bytes.
         UChar vabits4 = extract_vabits4_from_vabits8(a, vabits8);
         if      (vabits4 == VA_BITS4_UNTAINTED  ) { return V_BITS16_UNTAINTED;   }
         else if (vabits4 == VA_BITS4_TAINTED) { return V_BITS16_TAINTED; }
         else {
            /* Slow case: the two bytes are not all-defined or all-undefined. */
            PROF_EVENT(242, "tnt_LOADV16-slow2");
            return (UWord)tnt_LOADVn_slow( a, 16, isBigEndian );
         }
      }
   }
#endif
}

VG_REGPARM(1) UWord TNT_(helperc_LOADV16be) ( Addr a )
{
   return tnt_LOADV16(a, True);
}
VG_REGPARM(1) UWord TNT_(helperc_LOADV16le) ( Addr a )
{
   UWord result = tnt_LOADV16(a, False);

#ifdef DBG_LOAD
   // Taintgrind
   if( result
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_LOADV16le) 0x%08lx 0x%lx\n", a, result);
//      VG_(printf)("TNT_(helperc_LOADV16le) 16 0x%08lx\n", a);
#endif

   return result;
//   return tnt_LOADV16(a, False);
}


static INLINE
void tnt_STOREV16 ( Addr a, UWord vbits16, Bool isBigEndian )
{
   PROF_EVENT(250, "tnt_STOREV16");

#ifndef PERF_FAST_STOREV
   tnt_STOREVn_slow( a, 16, (ULong)vbits16, isBigEndian );
#else
   {
      UWord   sm_off, vabits8;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,16) )) {
         PROF_EVENT(251, "tnt_STOREV16-slow1");
         tnt_STOREVn_slow( a, 16, (ULong)vbits16, isBigEndian );
         return;
      }

      sm      = get_secmap_for_reading_low(a);
      sm_off  = SM_OFF(a);
      vabits8 = sm->vabits8[sm_off];
      if (LIKELY( !is_distinguished_sm(sm) &&
                          (VA_BITS8_UNTAINTED   == vabits8 ||
                           VA_BITS8_TAINTED == vabits8) ))
      {
         /* Handle common case quickly: a is suitably aligned, */
         /* is mapped, and is addressible. */
         // Convert full V-bits in register to compact 2-bit form.
         if (V_BITS16_UNTAINTED == vbits16) {
            insert_vabits4_into_vabits8( a, VA_BITS4_UNTAINTED ,
                                         &(sm->vabits8[sm_off]) );
         } else if (V_BITS16_TAINTED == vbits16) {
            insert_vabits4_into_vabits8( a, VA_BITS4_TAINTED,
                                         &(sm->vabits8[sm_off]) );
         } else {
            /* Slow but general case -- writing partially defined bytes. */
            PROF_EVENT(252, "tnt_STOREV16-slow2");
            tnt_STOREVn_slow( a, 16, (ULong)vbits16, isBigEndian );
         }
      } else {
         /* Slow but general case. */
         PROF_EVENT(253, "tnt_STOREV16-slow3");
         tnt_STOREVn_slow( a, 16, (ULong)vbits16, isBigEndian );
      }
   }
#endif
}

VG_REGPARM(2) void TNT_(helperc_STOREV16be) ( Addr a, UWord vbits16 )
{
#ifdef DBG_STORE
   // Taintgrind
   if( vbits16
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_STOREV16be) 0x%08lx 0x%lx\n", a, vbits16);
//      VG_(printf)("TNT_(helperc_STOREV16be) 16 0x%08lx\n", a);
#endif

   tnt_STOREV16(a, vbits16, True);
}
VG_REGPARM(2) void TNT_(helperc_STOREV16le) ( Addr a, UWord vbits16 )
{
#ifdef DBG_STORE
   // Taintgrind
   if( vbits16
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_STOREV16le) 0x%08lx 0x%lx\n", a, vbits16);
//      VG_(printf)("TNT_(helperc_STOREV16le) 16 0x%08lx\n", a);
#endif

   tnt_STOREV16(a, vbits16, False);
}


/* ------------------------ Size = 1 ------------------------ */
/* Note: endianness is irrelevant for size == 1 */

VG_REGPARM(1)
UWord TNT_(helperc_LOADV8) ( Addr a )
{
   PROF_EVENT(260, "tnt_LOADV8");

#ifndef PERF_FAST_LOADV
   return (UWord)tnt_LOADVn_slow( a, 8, False/*irrelevant*/ );
#else
   {
      UWord   sm_off, vabits8;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,8) )) {
         PROF_EVENT(261, "tnt_LOADV8-slow1");
         return (UWord)tnt_LOADVn_slow( a, 8, False/*irrelevant*/ );
      }

      sm      = get_secmap_for_reading_low(a);
      sm_off  = SM_OFF(a);
      vabits8 = sm->vabits8[sm_off];
      // Convert V bits from compact memory form to expanded register form
      // Handle common case quickly: a is mapped, and the entire
      // word32 it lives in is addressible.
      if      (vabits8 == VA_BITS8_UNTAINTED  ) { return V_BITS8_UNTAINTED;   }
      else if (vabits8 == VA_BITS8_TAINTED) {

#ifdef DBG_LOAD
         // Taintgrind
         VG_(printf)("TNT_(helperc_LOADV8) 0x%08lx 0x%x\n", a, V_BITS8_TAINTED);
         //VG_(printf)("TNT_(helperc_LOADV8) 8 0x%08lx\n", a);
#endif

         return V_BITS8_TAINTED; }
      else {
         // The 4 (yes, 4) bytes are not all-defined or all-undefined, check
         // the single byte.
         UChar vabits2 = extract_vabits2_from_vabits8(a, vabits8);
         if      (vabits2 == VA_BITS2_UNTAINTED  ) { return V_BITS8_UNTAINTED;   }
         else if (vabits2 == VA_BITS2_TAINTED) {

#ifdef DBG_LOAD
         // Taintgrind
         VG_(printf)("TNT_(helperc_LOADV8) 0x%08lx 0x%x\n", a, V_BITS8_TAINTED);
         //VG_(printf)("TNT_(helperc_LOADV8) 8 0x%08lx\n", a);
#endif

         return V_BITS8_TAINTED; }
         else {
            /* Slow case: the byte is not all-defined or all-undefined. */
            PROF_EVENT(262, "tnt_LOADV8-slow2");
            return (UWord)tnt_LOADVn_slow( a, 8, False/*irrelevant*/ );
         }
      }
   }
#endif
}


VG_REGPARM(2)
void TNT_(helperc_STOREV8) ( Addr a, UWord vbits8 )
{
#ifdef DBG_STORE
   // Taintgrind
   if( vbits8
//       || a & 0x80000000
     )
      VG_(printf)("TNT_(helperc_STOREV8) 0x%08lx 0x%lx\n", a, vbits8);
//      VG_(printf)("TNT_(helperc_STOREV8) 8 0x%08lx\n", a);
#endif

   PROF_EVENT(270, "tnt_STOREV8");

#ifndef PERF_FAST_STOREV
   tnt_STOREVn_slow( a, 8, (ULong)vbits8, False/*irrelevant*/ );
#else
   {
      UWord   sm_off, vabits8;
      SecMap* sm;

      if (UNLIKELY( UNALIGNED_OR_HIGH(a,8) )) {
         PROF_EVENT(271, "tnt_STOREV8-slow1");
         tnt_STOREVn_slow( a, 8, (ULong)vbits8, False/*irrelevant*/ );
         return;
      }

      sm      = get_secmap_for_reading_low(a);
      sm_off  = SM_OFF(a);
      vabits8 = sm->vabits8[sm_off];
      if (LIKELY
            ( !is_distinguished_sm(sm) &&
              ( (VA_BITS8_UNTAINTED == vabits8 || VA_BITS8_TAINTED == vabits8)
             || (VA_BITS2_NOACCESS != extract_vabits2_from_vabits8(a, vabits8))
              )
            )
         )
      {
         /* Handle common case quickly: a is mapped, the entire word32 it
            lives in is addressible. */
         // Convert full V-bits in register to compact 2-bit form.
         if (V_BITS8_UNTAINTED == vbits8) {
            insert_vabits2_into_vabits8( a, VA_BITS2_UNTAINTED,
                                          &(sm->vabits8[sm_off]) );
         } else if (V_BITS8_TAINTED == vbits8) {
            insert_vabits2_into_vabits8( a, VA_BITS2_TAINTED,
                                          &(sm->vabits8[sm_off]) );
         } else {
            /* Slow but general case -- writing partially defined bytes. */
            PROF_EVENT(272, "tnt_STOREV8-slow2");
            tnt_STOREVn_slow( a, 8, (ULong)vbits8, False/*irrelevant*/ );
         }
      } else {
         /* Slow but general case. */
         PROF_EVENT(273, "tnt_STOREV8-slow3");
         tnt_STOREVn_slow( a, 8, (ULong)vbits8, False/*irrelevant*/ );
      }
   }
#endif
}

Int ctoi_test( Char c ){
   switch(c){
   case '0':
   case '1':
   case '2':
   case '3':
   case '4':
   case '5':
   case '6':
   case '7':
   case '8':
   case '9':
   case 'a':
   case 'A':
   case 'b':
   case 'B':
   case 'c':
   case 'C':
   case 'd':
   case 'D':
   case 'e':
   case 'E':
   case 'f':
   case 'F':
      return 1;
   default:
      return 0;
   }
}

Int ctoi( Char c ){
   tl_assert( ctoi_test(c) );

   switch(c){
   case '0':
      return 0;
   case '1':
      return 1;
   case '2':
      return 2;
   case '3':
      return 3;
   case '4':
      return 4;
   case '5':
      return 5;
   case '6':
      return 6;
   case '7':
      return 7;
   case '8':
      return 8;
   case '9':
      return 9;
   case 'a':
   case 'A':
      return 0xa;
   case 'b':
   case 'B':
      return 0xb;
   case 'c':
   case 'C':
      return 0xc;
   case 'd':
   case 'D':
      return 0xd;
   case 'e':
   case 'E':
      return 0xe;
   case 'f':
   case 'F':
      return 0xf;
   default:
      tl_assert(0);
   }
}

Int atoi( Char *s ){
   Int result = 0;
   Int multiplier = 1;
   Int i;

   for( i = VG_(strlen)(s)-1; i>=0; i-- ){
      tl_assert( ctoi_test( s[i] ) );
      result += multiplier * ctoi(s[i]);
      // Assume decimal
      multiplier *= 10;
   }

   return result;
}

Char decode_char( UInt num ){
   switch( num ){
   case 0:
      return '0';
   case 1:
      return '1';
   case 2:
      return '2';
   case 3:
      return '3';
   case 4:
      return '4';
   case 5:
      return '5';
   case 6:
      return '6';
   case 7:
      return '7';
   case 8:
      return '8';
   case 9:
      return '9';
   case 0xa:
      return 'a';
   case 0xb:
      return 'b';
   case 0xc:
      return 'c';
   case 0xd:
      return 'd';
   case 0xe:
      return 'e';
   case 0xf:
      return 'f';
   case 0x10:
      return 'g';
   case 0x11:
      return 'i';
   case 0x12:
      return 'j';
   case 0x13:
      return 'l';
   case 0x14:
      return 'm';
   case 0x15:
      return 'n';
   case 0x16:
      return 'o';
   case 0x17:
      return 'p';
   case 0x18:
      return 's';
   case 0x19:
      return 't';
   case 0x1a:
      return 'u';
   case 0x1b:
      return 'x';
   case 0x1c:
      return '=';
   case 0x1d:
      return ' ';
   case 0x1e:
      return '_';
   default:
      return '\0';
   }
}

void decode_string( UInt *enc, Char *aStr ){
   Int start = 5;
   Int next_uint;
   Int shift;
   Int i;

   VG_(sprintf)( aStr, "0x1%X00%X ",
      (enc[0] & 0x08000000)? 9:5, (enc[0] & 0xf0000000) >> 28 );

   for( i = 0; i < 4; i++ ){
      shift = 32 - start - 5;

      while( shift > 0 ){
         next_uint = (enc[i] >> shift) & 0x1f;
         if( next_uint == 0x1f )
            return;
         VG_(sprintf)( aStr, "%s%c", aStr, decode_char( next_uint ) );
         start += 5;
         shift = 32 - start - 5;
      }

      next_uint = (enc[i] << (32 - 5 - shift)) >> 27;
      next_uint = (next_uint | ( enc[i+1] >> (32 + shift) ) ) & 0x1f;
      if( next_uint == 0x1f )
         return;
      VG_(sprintf)( aStr, "%s%c", aStr, decode_char( next_uint ) );
      start = -1*shift;
   }
}

void post_decode_string_load( Char *aStr ){
   Char aTmp1[128];
   Char aTmp2[128];
   Int i;
   Int irtype;
   Char *pChr;

   pChr = VG_(strchr)( aStr, '=' );

   tl_assert( pChr );

   VG_(strncpy)( aTmp1, aStr, pChr-aStr+1 );
   i = pChr-aStr;

   if( aStr[i+1] == ' '       && 
       ctoi_test( aStr[i+2] ) &&
       aStr[i+3] == ' '       ){
       irtype = ctoi( aStr[i+2] );
       i = i+3;
   }else
      tl_assert(0);

   if( irtype >= IRType_MAX ){
      VG_(printf)("%s\n", aStr);
      tl_assert( irtype < IRType_MAX );
   }

   VG_(strncpy)( aTmp2, aStr+i+1, 127 );

   tl_assert( VG_(strlen)(aTmp1) +
              VG_(strlen)(IRType_string[irtype & 0xf]) +
              VG_(strlen)(aTmp2) < 128 );
   
   VG_(sprintf)( aStr, "%s LD %s %s", aTmp1, IRType_string[irtype & 0xf], aTmp2 );
}

void post_decode_string_primops( Char *aStr ){
   Char aTmp1[128];
   Char aTmp2[128];
   Char *pChr;
   Int i;
   Int irop;

   pChr = VG_(strchr)( aStr, '=' );

   tl_assert( pChr );

   VG_(strncpy)( aTmp1, aStr, pChr-aStr+1 );
   i = pChr-aStr;

   if( aStr[i+1] == ' '       && 
       ctoi_test( aStr[i+2] ) &&
       aStr[i+3] == ' '       ){
       irop = ctoi( aStr[i+2] );
       i = i+3;
   }else if( aStr[i+1] == ' '       && 
             ctoi_test( aStr[i+2] ) &&
             ctoi_test( aStr[i+3] ) &&
             aStr[i+4] == ' '       ){
       irop = ctoi( aStr[i+2] ) * 0x10 +
              ctoi( aStr[i+3] );
       i = i+4;
   }else if( aStr[i+1] == ' '       && 
             ctoi_test( aStr[i+2] ) &&
             ctoi_test( aStr[i+3] ) &&
             ctoi_test( aStr[i+4] ) &&
             aStr[i+5] == ' '       ){
       irop = ctoi( aStr[i+2] ) * 0x100 +
              ctoi( aStr[i+3] ) * 0x10  +
              ctoi( aStr[i+4] );
       i = i+5;
   }else{
      VG_(printf)("%s\n", aStr);
      tl_assert(0);
   }

   if( irop > 707 ){
      VG_(printf)("%s\n", aStr);
      tl_assert( irop <= 707 );
   }

   VG_(strncpy)( aTmp2, aStr+i+1, 127 );

   tl_assert( VG_(strlen)(aTmp1) +
              VG_(strlen)(IROp_string[irop & 0xfff]) +
              VG_(strlen)(aTmp2) < 128 );
   
   VG_(sprintf)( aStr, "%s %s %s", aTmp1, IROp_string[irop & 0xfff], aTmp2 );
}

void post_decode_string_binops( Char *aStr ){
   Char aTmp1[128];
   Char aTmp2[128];
   Char aTmp3[128];
   Char *pEquals, *pSpace;
   Char *pTempVar, *pHex;

   // 0x15006 t20 = irop t25x1
   //             ^--pEquals
   // 0x15006 t28 = irop x0t20
   //             ^--pEquals
   pEquals = VG_(strstr)( aStr, " = " );

   tl_assert( pEquals );

   // 0x15006 t20 = irop t25x1
   //                   ^--pSpace
   // 0x15006 t28 = irop x0t20
   //                   ^--pSpace
   pSpace = VG_(strchr)( pEquals + 3, ' ' );
   pTempVar = VG_(strchr)( pSpace, 't' );
   pHex = VG_(strchr)( pSpace, 'x' );

   tl_assert( pSpace );
//   tl_assert( pTempVar );
   tl_assert( pHex );

   if( pTempVar && pTempVar < pHex ){

      // 0x15006 t20 = irop t25x1
      //                       ^--pHex
      VG_(strncpy)( aTmp1, aStr, pHex-aStr );
      aTmp1[pHex-aStr] = '\0';
      // aTmp1: 0x15006 t20 = irop t25

      VG_(strncpy)( aTmp2, pHex, VG_(strlen)(pHex) );
      aTmp2[VG_(strlen)(pHex)] = '\0';
      // aTmp2: x1

      tl_assert( VG_(strlen)(aTmp1) +
                 VG_(strlen)(aTmp2) + 2 < 128 );

      VG_(sprintf)( aStr, "%s 0%s", aTmp1, aTmp2 );
   }else if( pTempVar && pTempVar > pHex ){

      // 0x15006 t28 = irop x0t20
      //                   ^--pSpace
      VG_(strncpy)( aTmp1, aStr, pSpace-aStr );
      aTmp1[pSpace-aStr] = '\0';
      // aTmp1: 0x15006 t28 = irop

      VG_(strncpy)( aTmp2, pHex, pTempVar-pHex );
      aTmp2[pTempVar-pHex] = '\0';
      // aTmp2: x0

      VG_(strncpy)( aTmp3, pTempVar, VG_(strlen)(pTempVar) );
      aTmp3[VG_(strlen)(pTempVar)] = '\0';
      // aTmp3: t20

      tl_assert( VG_(strlen)(aTmp1) +
                 VG_(strlen)(aTmp2) +
                 VG_(strlen)(aTmp3) + 2 < 128 );

      VG_(sprintf)( aStr, "%s 0%s %s", aTmp1, aTmp2, aTmp3 );
   }
}

void post_decode_string_store( Char *aStr ){
   Char aTmp1[128];
   Char aTmp2[128];
   Char aTmp3[8];
   Int i;
   Int irtype;
   Char *pChr;

   VG_(strncpy)( aTmp3, aStr, 7 );
   aTmp3[7] = '\0';

   pChr = VG_(strchr)( aStr, '=' );

   tl_assert( pChr );

   VG_(strncpy)( aTmp1, aStr+8, pChr-aStr+1-8 );
   aTmp1[pChr-aStr+1-8] = '\0';

   i = pChr-aStr;

   if( aStr[i+1] == ' '       && 
       ctoi_test( aStr[i+2] ) &&
       aStr[i+3] == ' '       ){
       irtype = ctoi( aStr[i+2] );
       i = i+3;
   }else
      tl_assert(0);

   if( irtype >= IRType_MAX ){
      VG_(printf)("%s\n", aStr);
      tl_assert( irtype < IRType_MAX );
   }

   VG_(strncpy)( aTmp2, aStr+i+1, 127 );

   tl_assert( VG_(strlen)(aTmp3) +
              VG_(strlen)(aTmp1) +
              VG_(strlen)(IRType_string[irtype & 0xf]) +
              VG_(strlen)(aTmp2) < 128 );
   
   VG_(sprintf)( aStr, "%s ST %s %s %s", 
      aTmp3, aTmp1, aTmp2, IRType_string[irtype & 0xf] );
}

void post_decode_string_mux0x( Char *aStr ){
   Char aTmp1[128];
   Char aTmp2[128];
   Char *pChr;

   pChr = VG_(strchr)( aStr, '=' );

   tl_assert( pChr );

   VG_(strncpy)( aTmp1, aStr, pChr-aStr+1 );
   VG_(strncpy)( aTmp2, pChr+2, 127 );

   tl_assert( VG_(strlen)( aTmp1 ) +
              7 +
              VG_(strlen)( aTmp2 ) < 128 );

   VG_(sprintf)( aStr, "%s MUX0X %s", aTmp1, aTmp2 );
}

void post_decode_string( Char *aStr ){
   Char aTmp[128];
   Int i;
   Int count = 0;

   for( i=0; i<128; i++ ){
      if( aStr[i] == '=' ){
         aTmp[count++] = ' ';
         aTmp[count++] = aStr[i];
         aTmp[count++] = ' ';
      }else if( aStr[i] == '\0' ){
         aTmp[count] = aStr[i];
         break;
      }else
         aTmp[count++] = aStr[i];
   }
   
   VG_(sprintf)( aStr, "%s", aTmp );

   if( aStr[3] == '5' && aStr[6] == '4' ){
      post_decode_string_primops( aStr );
   }else if( aStr[3] == '5' && aStr[6] == '5' ){
      post_decode_string_primops( aStr );
   }else if( aStr[3] == '5' && aStr[6] == '6' ){
      post_decode_string_primops( aStr );
      post_decode_string_binops( aStr );
   }else if( aStr[3] == '5' && aStr[6] == '7' ){
      post_decode_string_primops( aStr );
   }else if( aStr[3] == '5' && aStr[6] == '8' ){
      post_decode_string_load( aStr );
   }else if( aStr[3] == '5' && aStr[6] == 'A' ){
      post_decode_string_mux0x( aStr );
   }else if( aStr[3] == '9' && aStr[6] == '6' ){
      post_decode_string_store( aStr );
   }
}


/*-----------------------------------------------
   Helper functions for taint information flows
-------------------------------------------------*/

// tmp variables go from t0, t1, t2,..., t255
// reg variables go from r0, r4, r8,..., r320
#define TVAR_I_MAX 256
#define REG_I_MAX 321
// These arrays are initialised to 0 in TNT_(clo_post_init)
int tvar_i[TVAR_I_MAX];
int reg_i[REG_I_MAX];

Int get_and_check_reg( Char *reg ){

   Int regnum = atoi( reg );
//   if( regnum % 4 ){
//      VG_(printf)("get_and_check_tvar: regnum %d mod 4 != 0\n", regnum );
//      tl_assert( !( regnum % 4 ) );
//   }
   if( regnum >= REG_I_MAX ){
      VG_(printf)("get_and_check_reg: regnum %d >= %d\n", regnum, REG_I_MAX );
      tl_assert( regnum < REG_I_MAX );
   }

   return regnum;
}

Int get_and_check_tvar( Char *tmp ){

   Int tmpnum = atoi( tmp );
   tl_assert( tmpnum < TVAR_I_MAX );
   return tmpnum;
}

VG_REGPARM(3)
void TNT_(helperc_0_tainted_enc32) (
   UInt enc0, 
   UInt enc1, 
   UInt enc2, 
   UInt enc3, 
   UInt value, 
   UInt taint ) {

   UInt  pc; 
   Char  fnname[300];
   Int   n_fnname = 300;
   Char  aTmp[128];
   UInt  enc[4] = { enc0, enc1, enc2, enc3 };

   if( TNT_(clo_critical_ins_only) &&
       ( enc[0] & 0xf8000000 ) != 0xB8000000 )
      return;

   if(!TNT_(do_print) && taint)
      TNT_(do_print) = 1;

   if(TNT_(do_print)){
      if((TNT_(clo_tainted_ins_only) && taint) ||
          !TNT_(clo_tainted_ins_only)){
         pc = VG_(get_IP)( VG_(get_running_tid)() );
         VG_(describe_IP) ( pc, fnname, n_fnname );

         decode_string( enc, aTmp );
         post_decode_string( aTmp );
         VG_(printf)("%s | %s | 0x%x | 0x%x | ", fnname, aTmp, value, taint );

         if( VG_(strstr)( aTmp, " get " ) != NULL /*&& taint*/ ){

            Char *pTmp, *pEquals, *pGet, *pSpace, *pReg;
            Char reg[16], tmp[16];
  
            // 0x15001 t53 = get 0 i8
            //         ^--pTmp
            //            ^--pEquals
            //              ^--pGet
            //                   ^--pReg
            //                    ^--pSpace 
            pTmp = VG_(strstr)( aTmp, " t" ); pTmp += 2;
            pEquals = VG_(strstr)( aTmp, " = " );
            VG_(strncpy)( tmp, pTmp, pEquals-pTmp );
            tmp[pEquals-pTmp] = '\0';
            pGet = VG_(strstr)( aTmp, " get " );
            pReg = pGet + 5;
            pSpace = VG_(strchr)( pReg, ' ' );
            VG_(strncpy)( reg, pReg, pSpace-pReg );
            reg[pSpace-pReg] = '\0';

            // Get indices
            Int regnum = get_and_check_reg( reg );
            Int tmpnum = get_and_check_tvar( tmp );
            tvar_i[tmpnum]++;

            VG_(printf)( "t%s.%d <- r%s.%d", tmp, tvar_i[tmpnum], reg, reg_i[regnum] );

         }else if( VG_(strstr)( aTmp, " put " ) != NULL /*&& taint*/ ){

            Char *pPut, *pSpace, *pReg;
            Char reg[16], tmp[16];
  
            // 0x19003 put 28 = t24
            //        ^--pPut
            //             ^--pReg
            //               ^--pSpace 
            //                   ^--pSpace + 4
            pPut = VG_(strstr)( aTmp, " put " );
            pReg = pPut + 5;
            pSpace = VG_(strchr)( pReg, ' ' );

            if( pSpace[3] == 't' ){
               VG_(strncpy)( reg, pReg, pSpace-pReg );
               reg[pSpace-pReg] = '\0';
               VG_(strncpy)( tmp, pSpace + 4, VG_(strlen)(pSpace + 4) );
               tmp[VG_(strlen)(pSpace + 4)] = '\0';

               // Get indices
               Int regnum = get_and_check_reg( reg );
               Int tmpnum = get_and_check_tvar( tmp );
               reg_i[regnum]++;

               VG_(printf)( "r%s.%d <- t%s.%d", reg, reg_i[regnum], tmp, tvar_i[tmpnum] );
            }else{
            // 0x19003 put 28 = 0xff
            //        ^--pPut
            //             ^--pReg
               VG_(strncpy)( reg, pReg, pSpace-pReg );
               reg[pSpace-pReg] = '\0';

               // Get indices
               Int regnum = get_and_check_reg( reg );
               reg_i[regnum]++;

               VG_(printf)( "r%s.%d", reg, reg_i[regnum] );
            }

         }else/* if( taint )*/{
            Char *pTmp1, *pTmp2, *pEquals;
            Char tmp1[16], tmp2[16];

            // 0x15003 t28 = t61
            //          ^--pTmp1
            //                ^--pTmp2
            pTmp1 = VG_(strstr)( aTmp, " t" ); pTmp1 += 2;
            pEquals = VG_(strstr)( aTmp, " = " );
            pTmp2 = pEquals + 4;

            if( pEquals != NULL && pEquals[3] == 't' ){

               VG_(strncpy)( tmp1, pTmp1, pEquals-pTmp1 );
               tmp1[pEquals-pTmp1] = '\0';
               VG_(strncpy)( tmp2, pTmp2, VG_(strlen)(pTmp2) );
               tmp2[VG_(strlen)(pTmp2)] = '\0';

               // Get indices
               Int tmpnum1 = get_and_check_tvar( tmp1 );
               Int tmpnum2 = get_and_check_tvar( tmp2 );
               tvar_i[tmpnum1]++;
               VG_(printf)("t%s.%d <- t%s.%d", tmp1, tvar_i[tmpnum1], tmp2, tvar_i[tmpnum2]);
            }else if( pEquals != NULL ){
            // 0x15003 t28 = 
            //          ^--pTmp1
               VG_(strncpy)( tmp1, pTmp1, pEquals-pTmp1 );
               tmp1[pEquals-pTmp1] = '\0';

               // Get indices
               Int tmpnum1 = get_and_check_tvar( tmp1 );
               tvar_i[tmpnum1]++;
               VG_(printf)("t%s.%d", tmp1, tvar_i[tmpnum1]);
            }
         }
         VG_(printf)("\n");
      }
   }
}

VG_REGPARM(3)
void TNT_(helperc_0_tainted_enc64) (
   ULong enc0, 
   ULong enc1, 
   ULong value, 
   ULong taint ) {

   ULong  pc; 
   Char  fnname[300];
   Int   n_fnname = 300;
   Char  aTmp[128];
   UInt  enc[4] = { (UInt)(enc0 >> 32), (UInt)(enc0 & 0xffffffff),
                    (UInt)(enc1 >> 32), (UInt)(enc1 & 0xffffffff) };

   if( TNT_(clo_critical_ins_only) &&
       ( enc[0] & 0xf8000000 ) != 0xB8000000 )
      return;

   if(!TNT_(do_print) && taint)
      TNT_(do_print) = 1;

   if(TNT_(do_print)){
      if((TNT_(clo_tainted_ins_only) && taint) ||
          !TNT_(clo_tainted_ins_only)){
         pc = VG_(get_IP)( VG_(get_running_tid)() );
         VG_(describe_IP) ( pc, fnname, n_fnname );

         decode_string( enc, aTmp );
         post_decode_string( aTmp );
         VG_(printf)("%s | %s | 0x%lx | 0x%lx | ", fnname, aTmp,
                           (long unsigned int)value,
                           (long unsigned int) taint );

         // Information flow
         if( VG_(strstr)( aTmp, " get " ) != NULL /*&& taint*/ ){

            Char *pTmp, *pEquals, *pGet, *pSpace, *pReg;
            Char reg[16], tmp[16];
  
            // 0x15001 t53 = get 0 i8
            //          ^--pTmp
            //            ^--pEquals
            //              ^--pGet
            //                   ^--pReg
            //                    ^--pSpace 
            pTmp = VG_(strstr)( aTmp, " t" ); pTmp += 2;
            pEquals = VG_(strstr)( aTmp, " = " );
            VG_(strncpy)( tmp, pTmp, pEquals-pTmp );
            tmp[pEquals-pTmp] = '\0';
            pGet = VG_(strstr)( aTmp, " get " );
            pReg = pGet + 5;
            pSpace = VG_(strchr)( pReg, ' ' );
            VG_(strncpy)( reg, pReg, pSpace-pReg );
            reg[pSpace-pReg] = '\0';

            // Get indices
            Int regnum = get_and_check_reg( reg );
            Int tmpnum = get_and_check_tvar( tmp );
            tvar_i[tmpnum]++;

            VG_(printf)( "t%s.%d <- r%s.%d", tmp, tvar_i[tmpnum], reg, reg_i[regnum] );
         }else if( VG_(strstr)( aTmp, " put " ) != NULL /*&& taint*/ ){

            Char *pPut, *pSpace, *pReg;
            Char reg[16], tmp[16];
  
            // 0x19003 put 28 = t24
            //        ^--pPut
            //             ^--pReg
            //               ^--pSpace 
            //                   ^--pSpace + 4
            pPut = VG_(strstr)( aTmp, " put " );
            pReg = pPut + 5;
            pSpace = VG_(strchr)( pReg, ' ' );

            if( pSpace[3] == 't' ){
               VG_(strncpy)( reg, pReg, pSpace-pReg );
               reg[pSpace-pReg] = '\0';
               VG_(strncpy)( tmp, pSpace + 4, VG_(strlen)(pSpace + 4) );
               tmp[VG_(strlen)(pSpace + 4)] = '\0';

               // Get indices
               Int regnum = get_and_check_reg( reg );
               Int tmpnum = get_and_check_tvar( tmp );
               reg_i[regnum]++;

               VG_(printf)("r%s.%d <- t%s.%d", reg, reg_i[regnum], tmp, tvar_i[tmpnum]);
            }else{
            // 0x19003 put 28 = 0xff
            //        ^--pPut
            //             ^--pReg
               VG_(strncpy)( reg, pReg, pSpace-pReg );
               reg[pSpace-pReg] = '\0';

               // Get indices
               Int regnum = get_and_check_reg( reg );
               reg_i[regnum]++;

               VG_(printf)( "r%s.%d", reg, reg_i[regnum] );
            }

         }else /*if( taint )*/{
            Char *pTmp1, *pTmp2, *pEquals;
            Char tmp1[16], tmp2[16];

            // 0x15003 t28 = t61
            //          ^--pTmp1
            //                ^--pTmp2
            pTmp1 = VG_(strstr)( aTmp, " t" ); pTmp1 += 2;
            pEquals = VG_(strstr)( aTmp, " = " );
            pTmp2 = pEquals + 4;

            if( pEquals != NULL && pEquals[3] == 't' ){

               VG_(strncpy)( tmp1, pTmp1, pEquals-pTmp1 );
               tmp1[pEquals-pTmp1] = '\0';
               VG_(strncpy)( tmp2, pTmp2, VG_(strlen)(pTmp2) );
               tmp2[VG_(strlen)(pTmp2)] = '\0';

               // Get indices
               Int tmpnum1 = get_and_check_tvar( tmp1 );
               Int tmpnum2 = get_and_check_tvar( tmp2 );
               tvar_i[tmpnum1]++;
               VG_(printf)("t%s.%d <- t%s.%d", tmp1, tvar_i[tmpnum1], tmp2, tvar_i[tmpnum2]);
            }else if( pEquals != NULL ){
            // 0x15003 t28 = 
            //          ^--pTmp1
               VG_(strncpy)( tmp1, pTmp1, pEquals-pTmp1 );
               tmp1[pEquals-pTmp1] = '\0';

               // Get indices
               Int tmpnum1 = get_and_check_tvar( tmp1 );
               tvar_i[tmpnum1]++;
               VG_(printf)("t%s.%d", tmp1, tvar_i[tmpnum1]);
            }
         }
         VG_(printf)("\n");
      }
   }
}

VG_REGPARM(3)
void TNT_(helperc_1_tainted_enc32) (
   UInt enc0, 
   UInt enc1, 
   UInt enc2, 
//   UInt enc3, 
   UInt value1, 
   UInt value2, 
   UInt taint1, 
   UInt taint2 ) {

   UInt  pc; 
   Char  fnname[300];
   Int   n_fnname = 300;
   Char  aTmp[128];
   UInt  enc[4] = { enc0, enc1, enc2/*0xffffffff*/, 0xffffffff };

   if( TNT_(clo_critical_ins_only)           &&
       ( enc[0] & 0xf8000000 ) != 0x68000000 &&
       ( enc[0] & 0xf8000000 ) != 0x80000000 )
      return;

   if( TNT_(clo_critical_ins_only)           &&
       ( enc[0] & 0xf8000000 ) == 0x68000000 &&
       !taint1 )
      return;

   if( TNT_(clo_critical_ins_only)           &&
       ( enc[0] & 0xf8000000 ) == 0x80000000 &&
       !taint2 )
      return;

   if(!TNT_(do_print) && (taint1 || taint2))
      TNT_(do_print) = 1;

   if(TNT_(do_print)){
      if((TNT_(clo_tainted_ins_only) && (taint1 || taint2)) ||
          !TNT_(clo_tainted_ins_only)){
         pc = VG_(get_IP)( VG_(get_running_tid)() );
         VG_(describe_IP) ( pc, fnname, n_fnname );

         decode_string( enc, aTmp );
         //VG_(printf)("decoded string %s\n", aTmp);
         post_decode_string( aTmp );

         VG_(printf)("%s | %s | 0x%x 0x%x | 0x%x 0x%x | ", 
            fnname, aTmp, value1, value2, taint1, taint2 );

         // Information flow
         if( VG_(strstr)( aTmp, " LD " ) != NULL /*&& taint1*/ ){
            Char objname[256];
            PtrdiffT pdt;
            VG_(memset)( objname, 0, 255 );
//            VG_(get_objname)( arg1, objname, 255 );
            VG_(get_datasym_and_offset)( value2, objname, 255, &pdt );

            if( objname[0] == '\0' ){
               VG_(sprintf)( objname, "%x_unknownobj", value2 );
            }

            Char *pTmp, *pEquals;
            Char tmp[16];

            // 0x15008 t35 = LD I32 0x805badc
            //         ^--pTmp
            //            ^--pEquals
            pTmp = VG_(strstr)( aTmp, " t" ); pTmp += 2;
            pEquals = VG_(strstr)( aTmp, " = " );
            VG_(strncpy)( tmp, pTmp, pEquals-pTmp );
            tmp[pEquals-pTmp] = '\0';

            // Get index
            Int tmpnum = get_and_check_tvar( tmp );
            tvar_i[tmpnum]++;

//            VG_(printf)( "t%s.%d <- %s", tmp, tvar_i[tmpnum], objname );
            VG_(printf)( "t%s.%d <- %s", tmp, tvar_i[tmpnum], objname );

            // Pointer tainting
            Char *pTmp2 = VG_(strstr)( pTmp + 1, " t" );
            if( pTmp2 != NULL ){
               Char tmp2[16];
               pTmp2 += 2;
            // 0x15008 t35 = LD I32 t34
            //                      ^--pTmp2
               VG_(strncpy)( tmp2, pTmp2, VG_(strlen)(pTmp2) );
               tmp2[VG_(strlen)(pTmp2)] = '\0';
               Int tmpnum2 = get_and_check_tvar( tmp2 );
               VG_(printf)( "; t%s.%d <*- t%s.%d", tmp, tvar_i[tmpnum], tmp2, tvar_i[tmpnum2] );
            }

         }else if( VG_(strstr)( aTmp, " ST " ) != NULL /*&& taint2*/ ){
            Char objname[256];
            PtrdiffT pdt;
            VG_(memset)( objname, 0, 255 );
            VG_(get_datasym_and_offset)( value1, objname, 255, &pdt );

            if( objname[0] == '\0' ){
               VG_(sprintf)( objname, "%x_unknownobj", value1 );
            }

            Char *pEquals, *pTmp, *pSpace;
            Char tmp[16];

            // 0x19006 ST t80 = t85 I16
            //               ^--pEquals
            //                  ^--pTmp
            //                     ^--pSpace
            pEquals = VG_(strstr)( aTmp, " = " );

            if( pEquals[3] == 't' ){
               pTmp = pEquals + 4;
               pSpace = VG_(strchr)( pTmp, ' ' );
               VG_(strncpy)( tmp, pTmp, pSpace-pTmp );
               tmp[pSpace-pTmp] = '\0';
            
               // Get index
               Int tmpnum = get_and_check_tvar( tmp );

               VG_(printf)( "%s <- t%s.%d", objname, tmp, tvar_i[tmpnum] );

               // Pointer tainting
               Char *pTmp2 = VG_(strstr)( aTmp, " t" );
               if( pTmp2 != NULL && pTmp2 < pEquals ){
                  Char tmp2[16];
                  pTmp2 += 2;
               // 0x15008 ST t35 = t34 I32
               //             ^--pTmp2
                  VG_(strncpy)( tmp2, pTmp2, pEquals-pTmp2 );
                  tmp2[pEquals-pTmp2] = '\0';
                  Int tmpnum2 = get_and_check_tvar( tmp2 );
                  VG_(printf)( "; t%s.%d <&- t%s.%d", tmp2, tvar_i[tmpnum2], tmp, tvar_i[tmpnum] );
               }

            }else{
            // 0x19006 ST t80 = 0xff
            //               ^--pEquals
               VG_(printf)( "%s", objname );
            }

         }else /*if( taint1 && taint2 )*/{
            Char *pTmp1, *pTmp2, *pEquals, *pHex, *pSpace;
            Char tmp1[16], tmp2[16];

            // 0x15006 t7 = Shl32 t35 0x5
            //         ^--pTmp1   ^--pTmp2
            //           ^--pEquals
            //                        ^--pHex
            // 0x15006 t7 = Shl32 0x5 t35 
            //         ^--pTmp1       ^--pTmp2
            //           ^--pEquals
            //                    ^--pHex

            pTmp1 = VG_(strstr)( aTmp, " t" ); pTmp1 += 2;
            pEquals = VG_(strstr)( aTmp, " = " );
            pTmp2 = VG_(strstr)( pEquals, " t" ); pTmp2 += 2;
            pHex = VG_(strstr)( pEquals, " 0x" ); pHex++;

            VG_(strncpy)( tmp1, pTmp1, pEquals-pTmp1 );
            tmp1[pEquals-pTmp1] = '\0';

            if( pTmp2 < pHex ){
               pSpace = VG_(strchr)( pTmp2, ' ' );
               VG_(strncpy)( tmp2, pTmp2, pSpace-pTmp2 );
               tmp2[pSpace-pTmp2] = '\0';
            }else{
               VG_(strncpy)( tmp2, pTmp2, VG_(strlen)(pTmp2) );
               tmp2[VG_(strlen)(pTmp2)] = '\0';
            }

            // Get index
            Int tmpnum1 = get_and_check_tvar( tmp1 );
            Int tmpnum2 = get_and_check_tvar( tmp2 );
            tvar_i[tmpnum1]++;

            VG_(printf)( "t%s.%d <- t%s.%d", tmp1, tvar_i[tmpnum1], tmp2, tvar_i[tmpnum2] );
         }

         VG_(printf)("\n");

      }
   }
}

VG_REGPARM(3)
void TNT_(helperc_1_tainted_enc64) (
   ULong enc0, 
   ULong enc1, 
   ULong value1, 
   ULong value2, 
   ULong taint1, 
   ULong taint2 ) {

   ULong  pc; 
   Char  fnname[300];
   Int   n_fnname = 300;
   Char  aTmp[128];
   UInt  enc[4] = { (UInt)(enc0 >> 32), (UInt)(enc0 & 0xffffffff),
                    (UInt)(enc1 >> 32), (UInt)(enc1 & 0xffffffff) };

   if( TNT_(clo_critical_ins_only) &&
       ( enc[0] & 0xf8000000 ) != 0x68000000 &&
       ( enc[0] & 0xf8000000 ) != 0x80000000 )
      return;

   if( TNT_(clo_critical_ins_only)           &&
       ( enc[0] & 0xf8000000 ) == 0x68000000 &&
       !taint1 )
      return;

   if( TNT_(clo_critical_ins_only)           &&
       ( enc[0] & 0xf8000000 ) == 0x80000000 &&
       !taint2 )
      return;

   if(!TNT_(do_print) && (taint1 || taint2))
      TNT_(do_print) = 1;

   if(TNT_(do_print)){
      if((TNT_(clo_tainted_ins_only) && (taint1 || taint2)) ||
          !TNT_(clo_tainted_ins_only)){
         pc = VG_(get_IP)( VG_(get_running_tid)() );
         VG_(describe_IP) ( pc, fnname, n_fnname );

         decode_string( enc, aTmp );
         post_decode_string( aTmp );
         VG_(printf)("%s | %s | 0x%lx 0x%lx | 0x%lx 0x%lx | ", 
                           fnname, aTmp,
                           (long unsigned int) value1,
                           (long unsigned int) value2,
                           (long unsigned int) taint1,
                           (long unsigned int) taint2 );

         // Information flow
         if( VG_(strstr)( aTmp, " LD " ) != NULL /*&& taint1*/ ){
            Char objname[256];
            PtrdiffT pdt;
            VG_(memset)( objname, 0, 255 );
            VG_(get_datasym_and_offset)( value2, objname, 255, &pdt );

            if( objname[0] == '\0' ){
               VG_(sprintf)( objname, "%lx_unknownobj", (long unsigned int) value2 );
            }

            Char *pTmp, *pEquals;
            Char tmp[16];

            // 0x15008 t35 = LD I32 0x805badc
            //          ^--pTmp
            //            ^--pEquals
            pTmp = VG_(strstr)( aTmp, " t" ); pTmp += 2;
            pEquals = VG_(strstr)( aTmp, " = " );
            
            VG_(strncpy)( tmp, pTmp, pEquals-pTmp );
            tmp[pEquals-pTmp] = '\0';

            // Get index
            Int tmpnum = get_and_check_tvar( tmp );
            tvar_i[tmpnum]++;

            VG_(printf)( "t%s.%d <- %s", tmp, tvar_i[tmpnum], objname );

            // Pointer tainting
            Char *pTmp2 = VG_(strstr)( pTmp + 1, " t" );
            if( pTmp2 != NULL ){
               Char tmp2[16];
               pTmp2 += 2;
            // 0x15008 t35 = LD I32 t34
            //                      ^--pTmp2
               VG_(strncpy)( tmp2, pTmp2, VG_(strlen)(pTmp2) );
               tmp2[VG_(strlen)(pTmp2)] = '\0';
               Int tmpnum2 = get_and_check_tvar( tmp2 );
               VG_(printf)( "; t%s.%d <*- t%s.%d", tmp, tvar_i[tmpnum], tmp2, tvar_i[tmpnum2] );
            }

         }else if( VG_(strstr)( aTmp, " ST " ) != NULL /*&& taint2*/ ){
            Char objname[256];
            PtrdiffT pdt;
            VG_(memset)( objname, 0, 255 );
            VG_(get_datasym_and_offset)( value1, objname, 255, &pdt );

            if( objname[0] == '\0' ){
               VG_(sprintf)( objname, "%lx_unknownobj", (long unsigned int)  value1 );
            }

            Char *pEquals, *pTmp, *pSpace;
            Char tmp[16];

            // 0x19006 ST t80 = t85 I16
            //               ^--pEquals
            //                   ^--pTmp
            //                     ^--pSpace
            pEquals = VG_(strstr)( aTmp, " = " );

            if( pEquals[3] == 't' ){
               pTmp = pEquals + 4;
               pSpace = VG_(strchr)( pTmp, ' ' );
               VG_(strncpy)( tmp, pTmp, pSpace-pTmp );
               tmp[pSpace-pTmp] = '\0';
            
               // Get index
               Int tmpnum = get_and_check_tvar( tmp );

               VG_(printf)( "%s <- t%s.%d", objname, tmp, tvar_i[tmpnum] );

               // Pointer tainting
               Char *pTmp2 = VG_(strstr)( aTmp, " t" );
               if( pTmp2 != NULL && pTmp2 < pEquals ){
                  Char tmp2[16];
                  pTmp2 += 2;
               // 0x15008 ST t35 = t34 I32
               //             ^--pTmp2
                  VG_(strncpy)( tmp2, pTmp2, pEquals-pTmp2 );
                  tmp2[pEquals-pTmp2] = '\0';
                  Int tmpnum2 = get_and_check_tvar( tmp2 );
                  VG_(printf)( "; t%s.%d <&- t%s.%d", tmp2, tvar_i[tmpnum2], tmp, tvar_i[tmpnum] );
               }
            }else{
            // 0x19006 ST t80 = 0xff
            //               ^--pEquals
               VG_(printf)( "%s", objname );
            }

         }else /*if( taint1 && taint2 )*/{
            Char *pTmp1, *pTmp2, *pEquals, *pHex, *pSpace;
            Char tmp1[16], tmp2[16];

            // 0x15006 t7 = Shl32 t35 0x5
            //          ^--pTmp1   ^--pTmp2
            //           ^--pEquals
            //                        ^--pHex
            // 0x15006 t7 = Shl32 0x5 t35 
            //          ^--pTmp1       ^--pTmp2
            //           ^--pEquals
            //                    ^--pHex

            pTmp1 = VG_(strstr)( aTmp, " t" ); pTmp1 += 2;
            pEquals = VG_(strstr)( aTmp, " = " );
            pTmp2 = VG_(strstr)( pEquals, " t" ); pTmp2 += 2;
            pHex = VG_(strstr)( pEquals, " 0x" ); pHex++;

            VG_(strncpy)( tmp1, pTmp1, pEquals-pTmp1 );
            tmp1[pEquals-pTmp1] = '\0';

            if( pTmp2 < pHex ){
               pSpace = VG_(strchr)( pTmp2, ' ' );
               VG_(strncpy)( tmp2, pTmp2, pSpace-pTmp2 );
               tmp2[pSpace-pTmp2] = '\0';
            }else{
               VG_(strncpy)( tmp2, pTmp2, VG_(strlen)(pTmp2) );
               tmp2[VG_(strlen)(pTmp2)] = '\0';
            }

            // Get index
            Int tmpnum1 = get_and_check_tvar( tmp1 );
            Int tmpnum2 = get_and_check_tvar( tmp2 );
            tvar_i[tmpnum1]++;

            VG_(printf)( "t%s.%d <- t%s.%d", tmp1, tvar_i[tmpnum1], tmp2, tvar_i[tmpnum2] );
         }

         VG_(printf)("\n");
      }
   }
}


VG_REGPARM(3)
void TNT_(helperc_0_tainted) ( 
   HChar *str, 
   UInt value, 
   UInt taint ) {

   UInt  pc; 
   Char  fnname[300];
   Int   n_fnname = 300;

   if( TNT_(clo_critical_ins_only) )
      return;

   if(!TNT_(do_print) && taint)
      TNT_(do_print) = 1;

   if(TNT_(do_print)){
      if((TNT_(clo_tainted_ins_only) && taint) ||
          !TNT_(clo_tainted_ins_only)){
         pc = VG_(get_IP)( VG_(get_running_tid)() );
         VG_(describe_IP) ( pc, fnname, n_fnname );
         VG_(printf)("%s | %s | 0x%x | 0x%x | ", fnname, str, value, taint );

         // Information flow
         if( VG_(strstr)( str, "0x15006" ) != NULL /*&& taint*/ ){
            Char *pTmp1, *pTmp2, *pTmp3, *pEquals;
            Char tmp1[16], tmp2[16], tmp3[16];

            // 0x15006 t81 = Add32 t20 t20
            //          ^--pTmp1    ^--pTmp2
            //            ^--pEquals    ^--pTmp3
            pTmp1 = VG_(strstr)( str, " t" );
            pEquals = VG_(strstr)( str, " = " );
            pTmp2 = VG_(strstr)( pEquals, " t" );
            pTmp3 = VG_(strstr)( pTmp2+1, " t" );
            pTmp1 += 2; pTmp2 += 2; pTmp3 += 2;

            VG_(strncpy)( tmp1, pTmp1, pEquals-pTmp1 );
            tmp1[pEquals-pTmp1] = '\0';
            VG_(strncpy)( tmp2, pTmp2, pTmp3-2-pTmp2 );
            tmp2[pTmp3-2-pTmp2] = '\0';
            VG_(strncpy)( tmp3, pTmp3, VG_(strlen)(pTmp3) );
            tmp3[VG_(strlen)(pTmp3)] = '\0';

            // Get index
            Int tmpnum1 = get_and_check_tvar( tmp1 );
            Int tmpnum2 = get_and_check_tvar( tmp2 );
            Int tmpnum3 = get_and_check_tvar( tmp3 );
            tvar_i[tmpnum1]++;

            VG_(printf)( "t%s.%d <- t%s.%d; t%s.%d <- t%s.%d", tmp1, tvar_i[tmpnum1], tmp2, tvar_i[tmpnum2], tmp1, tvar_i[tmpnum1], tmp3, tvar_i[tmpnum3] );
         }else if( VG_(strstr)( str, " = " ) != NULL ){
            Char *pTmp, *pEquals;
            Char tmp[16];
            pTmp = VG_(strstr)( str, " t" ); pTmp += 2;
            pEquals = VG_(strstr)( str, " = " );
            VG_(strncpy)( tmp, pTmp, pEquals-pTmp );
            tmp[pEquals-pTmp] = '\0';

            // Get index
            Int tmpnum = get_and_check_tvar( tmp );
            tvar_i[tmpnum]++;
            VG_(printf)( "t%s.%d", tmp, tvar_i[tmpnum] );
         }
         VG_(printf)("\n");
      }
   }
}

VG_REGPARM(3)
void TNT_(helperc_1_tainted) ( 
   HChar *str, 
   UInt value, 
   UInt arg1, 
   UInt taint1, 
   UInt taint2 ) {

   UInt  pc; 
   Char  fnname[300];
   Int   n_fnname = 300;

   if( TNT_(clo_critical_ins_only) )
      return;

   if(!TNT_(do_print) && (taint1 || taint2))
      TNT_(do_print) = 1;

   if(TNT_(do_print)){
      if((TNT_(clo_tainted_ins_only) && (taint1 || taint2)) ||
          !TNT_(clo_tainted_ins_only)){
         pc = VG_(get_IP)( VG_(get_running_tid)() );
         VG_(describe_IP) ( pc, fnname, n_fnname );
         VG_(printf)("%s | %s | 0x%x 0x%x | 0x%x 0x%x\n", 
            fnname, str, value, arg1, taint1, taint2 );
//         VG_(message_flush) ( );
      }
   }
}

VG_REGPARM(3)
void TNT_(helperc_2_tainted) ( 
   HChar *str, 
   UInt value, 
   UInt arg1, 
   UInt arg2,
   UInt taint1, 
   UInt taint2, 
   UInt taint3 ) {

   UInt  pc;
   Char  fnname[300];
   Int   n_fnname = 300;

   if( TNT_(clo_critical_ins_only) )
      return;

   if( !TNT_(do_print) && (taint1 || taint2 || taint3) )
      TNT_(do_print) = 1;

   if(TNT_(do_print)){
      if((TNT_(clo_tainted_ins_only) && (taint1 || taint2 || taint3) ) ||
          !TNT_(clo_tainted_ins_only)){
         pc = VG_(get_IP)( VG_(get_running_tid)() );
         VG_(describe_IP) ( pc, fnname, n_fnname );
         VG_(printf)("%s | %s | 0x%x 0x%x 0x%x | 0x%x 0x%x 0x%x | ", 
            fnname, str, value, arg1, arg2, 
            taint1, taint2, taint3 );

         // Information flow
         if( VG_(strstr)( str, "0x15006" ) != NULL /*&& taint1*/ ){
            Char *pTmp1, *pTmp2, *pTmp3, *pEquals;
            Char tmp1[16], tmp2[16], tmp3[16];

            // 0x15006 t81 = Add32 t20 t20
            //          ^--pTmp1    ^--pTmp2
            //            ^--pEquals    ^--pTmp3
            pTmp1 = VG_(strstr)( str, " t" );
            pEquals = VG_(strstr)( str, " = " );
            pTmp2 = VG_(strstr)( pEquals, " t" );
            pTmp3 = VG_(strstr)( pTmp2+1, " t" );
            pTmp1 += 2; pTmp2 += 2; pTmp3 += 2;

            VG_(strncpy)( tmp1, pTmp1, pEquals-pTmp1 );
            tmp1[pEquals-pTmp1] = '\0';
            VG_(strncpy)( tmp2, pTmp2, pTmp3-2-pTmp2 );
            tmp2[pTmp3-2-pTmp2] = '\0';
            VG_(strncpy)( tmp3, pTmp3, VG_(strlen)(pTmp3) );
            tmp3[VG_(strlen)(pTmp3)] = '\0';

            // Get index
            Int tmpnum1 = get_and_check_tvar( tmp1 );
            Int tmpnum2 = get_and_check_tvar( tmp2 );
            Int tmpnum3 = get_and_check_tvar( tmp3 );
            tvar_i[tmpnum1]++;

            //if( taint2 && taint3 )
               VG_(printf)( "t%s.%d <- t%s.%d; t%s.%d <- t%s.%d", tmp1, tvar_i[tmpnum1], tmp2, tvar_i[tmpnum2], tmp1, tvar_i[tmpnum1], tmp3, tvar_i[tmpnum3] );
               //VG_(printf)("t%s.%d <- t%s.%d; t%s.%d <- t%s.%d", tmp1, tmp2, tmp1, tmp3 );
            /*else if( taint2 )
               VG_(printf)("%s <- %s", tmp1, tmp2 );
            else if( taint3 )
               VG_(printf)("%s <- %s", tmp1, tmp3 );*/
         }

         VG_(printf)("\n");
      }
   }
}

VG_REGPARM(3)
void TNT_(helperc_3_tainted) ( 
   HChar *str, 
   UInt value, 
   UInt arg1, 
   UInt arg2, 
   UInt arg3, 
   UInt taint ) {

   UInt  pc;
   Char  fnname[300];
   Int   n_fnname = 300;

   if( TNT_(clo_critical_ins_only) )
      return;

   if(!TNT_(do_print) && taint)
      TNT_(do_print) = 1;

   if(TNT_(do_print)){
      if((TNT_(clo_tainted_ins_only) && taint) ||
          !TNT_(clo_tainted_ins_only)){
         pc = VG_(get_IP)( VG_(get_running_tid)() );
         VG_(describe_IP) ( pc, fnname, n_fnname );
         VG_(printf)("%s | %s | 0x%x 0x%x 0x%x 0x%x | 0x%x\n", 
            fnname, str, value, arg1, arg2, arg3, taint );
//         VG_(message_flush) ( );
      }
   }
}

VG_REGPARM(3)
void TNT_(helperc_4_tainted) ( 
   HChar *str, 
   UInt value, 
   UInt arg1,
   UInt arg2, 
   UInt arg3, 
   UInt arg4, 
   UInt taint ) {

   UInt  pc;
   Char  fnname[300];
   Int   n_fnname = 300;

   if( TNT_(clo_critical_ins_only) )
      return;

   if(!TNT_(do_print) && taint)
      TNT_(do_print) = 1;

   if(TNT_(do_print)){
      if((TNT_(clo_tainted_ins_only) && taint) ||
          !TNT_(clo_tainted_ins_only)){
         pc = VG_(get_IP)( VG_(get_running_tid)() );
         VG_(describe_IP) ( pc, fnname, n_fnname );
         VG_(printf)("%s | %s | 0x%x 0x%x 0x%x 0x%x 0x%x | 0x%x\n", 
            fnname, str, value, arg1, arg2, arg3, arg4, taint );
//         VG_(message_flush) ( );
      }
   }
}

/*------------------------------------------------------------*/
/*--- Initialisation                                       ---*/
/*------------------------------------------------------------*/

static void init_shadow_memory ( void )
{
   Int     i;
   SecMap* sm;

   tl_assert(V_BIT_TAINTED   == 1);
   tl_assert(V_BIT_UNTAINTED     == 0);
   tl_assert(V_BITS8_TAINTED == 0xFF);
   tl_assert(V_BITS8_UNTAINTED   == 0);

   /* Build the 3 distinguished secondaries */
   sm = &sm_distinguished[SM_DIST_NOACCESS];
   for (i = 0; i < SM_CHUNKS; i++) sm->vabits8[i] = VA_BITS8_NOACCESS;

   sm = &sm_distinguished[SM_DIST_TAINTED];
   for (i = 0; i < SM_CHUNKS; i++) sm->vabits8[i] = VA_BITS8_TAINTED;

   sm = &sm_distinguished[SM_DIST_UNTAINTED];
   for (i = 0; i < SM_CHUNKS; i++) sm->vabits8[i] = VA_BITS8_UNTAINTED;

   /* Set up the primary map. */
   /* These entries gradually get overwritten as the used address
      space expands. */
   // Taintgrind: Initialise all memory as untainted
   for (i = 0; i < N_PRIMARY_MAP; i++)
      primary_map[i] = &sm_distinguished[SM_DIST_UNTAINTED];
//      primary_map[i] = &sm_distinguished[SM_DIST_NOACCESS];

   /* Auxiliary primary maps */
   init_auxmap_L1_L2();

   /* auxmap_size = auxmap_used = 0;
      no ... these are statically initialised */

   /* Secondary V bit table */
   secVBitTable = createSecVBitTable();

#if 0
   // Taintgrind: Solely for testing
   TNT_(make_mem_tainted)(0xbe000000, 0x1000000);
#endif
}



/*------------------------------------------------------------*/
/*--- Syscall event handlers                               ---*/
/*------------------------------------------------------------*/

static
void tnt_pre_syscall(ThreadId tid, UInt syscallno,
                           UWord* args, UInt nArgs)
{
}

static
void tnt_post_syscall(ThreadId tid, UInt syscallno,
                            UWord* args, UInt nArgs, SysRes res)
{
  switch ((int)syscallno) {
#ifdef VGP_x86_linux
    case 3: //__NR_read:
      TNT_(syscall_read)(tid, args, nArgs, res);
      break;
    case 5: //__NR_open:
      TNT_(syscall_open)(tid, args, nArgs, res);
      break;
    case 6: //__NR_close:
      TNT_(syscall_close)(tid, args, nArgs, res);
      break;
    case 140: //__NR_llseek:
      TNT_(syscall_llseek)(tid, args, nArgs, res);
      break;
    case 180: //__NR_pread64:
      TNT_(syscall_pread)(tid, args, nArgs, res);
      break;
#elif VGP_amd64_linux
    case 0: //__NR_read:
      TNT_(syscall_read)(tid, args, nArgs, res);
      break;
    case 2: //__NR_open:
      TNT_(syscall_open)(tid, args, nArgs, res);
      break;
    case 3: //__NR_close:
      TNT_(syscall_close)(tid, args, nArgs, res);
      break;
    case 17: //__NR_pread64:
      TNT_(syscall_pread)(tid, args, nArgs, res);
      break;
#elif defined VGP_amd64_freebsd || defined VGP_x86_freebsd
    case 3: //__NR_read:
      TNT_(syscall_read)(tid, args, nArgs, res);
      break;
    case 5: //__NR_open:
      TNT_(syscall_open)(tid, args, nArgs, res);
      break;
    case 6: //__NR_close:
      TNT_(syscall_close)(tid, args, nArgs, res);
      break;
    case 475: //__NR_pread64:
      TNT_(syscall_pread)(tid, args, nArgs, res);
      break;
    case 478: //__NR_lseek:
      TNT_(syscall_llseek)(tid, args, nArgs, res);
      break;
#else
#error Unknown platform
#endif
  }
}

/*
   Taintgrind args
*/

//static Char   TNT_(default_file_filter)[]      = "";
Char*         TNT_(clo_file_filter)            = "";
Int           TNT_(clo_taint_start)            = 0;
Int           TNT_(clo_taint_len)              = 0x800000;
Bool          TNT_(clo_taint_all)              = False;
Int           TNT_(clo_after_bb)               = 0;
Int           TNT_(clo_before_bb)              = -1;
Bool          TNT_(clo_tainted_ins_only)       = True;
Bool          TNT_(clo_critical_ins_only)      = True;
Int           TNT_(do_print)                   = 0;

static Bool tnt_process_cmd_line_options(Char* arg) {
   if VG_STR_CLO(arg, "--file-filter", TNT_(clo_file_filter)) {
      TNT_(do_print) = 0;
   }
   else if VG_BHEX_CLO(arg, "--taint-start", TNT_(clo_taint_start), 0x0000, 0x8000000) {}
   else if VG_BHEX_CLO(arg, "--taint-len", TNT_(clo_taint_len), 0x0000, 0x800000) {}
   else if VG_BOOL_CLO(arg, "--taint-all", TNT_(clo_taint_all)) {}
   else if VG_BINT_CLO(arg, "--after-bb", TNT_(clo_after_bb), 0, 1000000) {}
   else if VG_BINT_CLO(arg, "--before-bb", TNT_(clo_before_bb), 0, 1000000) {}
   else if VG_BOOL_CLO(arg, "--tainted-ins-only", TNT_(clo_tainted_ins_only)) {}
   else if VG_BOOL_CLO(arg, "--critical-ins-only", TNT_(clo_critical_ins_only)) {}
   else
      return VG_(replacement_malloc_process_cmd_line_option)(arg);

   return True;
}

static void tnt_print_usage(void) {
   VG_(printf)(
"    --file-filter=<full_path>   full path of file to taint [\"\"]\n"
"    --taint-start=[0,800000]    starting byte to taint (in hex) [0]\n"
"    --taint-len=[0,800000]      number of bytes to taint from taint-start (in hex)[800000]\n"
"    --taint-all= no|yes         taint all bytes of all files read. warning: slow! [no]\n"
"    --after-bb=[0,1000000]      start instrumentation after [0]\n"
"    --before-bb=[0,1000000]     stop instrumentation after [-1]\n"
"    --tainted-ins-only= no|yes  print tainted instructions only [yes]\n"
"    --critical-ins-only= no|yes print critical instructions only [yes]\n"
   );
}

static void tnt_print_debug_usage(void)
{
   VG_(printf)(
"    (none)\n"
   );
}
                                   

/*
   Valgrind core functions
*/                                                     

Bool TNT_(instrument_start) = False;
#define MAX_PATH 256
static void tnt_post_clo_init(void)
{
   if(*TNT_(clo_file_filter) == '\0'){

      if( !TNT_(clo_tainted_ins_only) || !TNT_(clo_critical_ins_only) )
         TNT_(do_print) = 1;

   }else if(*TNT_(clo_file_filter) != '/') { // Not absolute path
      if (*TNT_(clo_file_filter) == '~') {
         HChar* home    = VG_(getenv)("HOME");

         if (home) {
            HChar tmp[MAX_PATH+1];
            VG_(snprintf)( tmp, MAX_PATH, "%s%s", home, TNT_(clo_file_filter)+1 );
            VG_(snprintf)( TNT_(clo_file_filter), MAX_PATH, "%s", tmp );
            //VG_(printf)("%s\n", TNT_(clo_file_filter) );
         }else{
            VG_(printf)("*** Please use absolute path for --file-filter\n");
            VG_(exit)(1);
         }
      }else if (*TNT_(clo_file_filter) == '*') {
         // Wildcard
      }else{
         VG_(printf)("*** Please use absolute path for --file-filter\n");
         VG_(exit)(1);
      }
   }

   if( TNT_(clo_critical_ins_only) )
      TNT_(clo_tainted_ins_only) = True;

   // Initialise temporary variables/reg SSA index array
   Int i;
   for( i=0; i< TVAR_I_MAX; i++ )
      tvar_i[i] = 0;
   for( i=0; i< REG_I_MAX; i++ )
      reg_i[i] = 0;
}

static void tnt_fini(Int exitcode)
{
}

static void tnt_pre_clo_init(void)
{
   VG_(details_name)            ("Taintgrind");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("the taint analysis tool");
   VG_(details_copyright_author)(
      "Copyright (C) 2010, and GNU GPL'd, by Wei Ming Khoo.");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);

   VG_(basic_tool_funcs)        (tnt_post_clo_init,
                                 TNT_(instrument),
                                 tnt_fini);

   /* Track syscalls for tainting purposes */
   // TODO: will this conflict?
   VG_(needs_syscall_wrapper)     ( tnt_pre_syscall,
                                    tnt_post_syscall );

   init_shadow_memory();

   VG_(needs_command_line_options)(tnt_process_cmd_line_options,
                                   tnt_print_usage,
                                   tnt_print_debug_usage);

   VG_(needs_malloc_replacement)  (TNT_(malloc),
                                   TNT_(__builtin_new),
                                   TNT_(__builtin_vec_new),
                                   TNT_(memalign),
                                   TNT_(calloc),
                                   TNT_(free),
                                   TNT_(__builtin_delete),
                                   TNT_(__builtin_vec_delete),
                                   TNT_(realloc),
                                   TNT_(malloc_usable_size),
                                   TNT_MALLOC_REDZONE_SZB );

   // Taintgrind: Needed for tnt_malloc_wrappers.c
   TNT_(malloc_list)  = VG_(HT_construct)( "TNT_(malloc_list)" );
//   TNT_(mempool_list) = VG_(HT_construct)( "TNT_(mempool_list)" );

//   VG_(track_new_mem_mmap)        ( tnt_new_mem_mmap );
   VG_(track_copy_mem_remap)      ( TNT_(copy_address_range_state) );
   VG_(track_die_mem_stack_signal)( TNT_(make_mem_defined) );
   VG_(track_die_mem_brk)         ( TNT_(make_mem_defined) );
   VG_(track_die_mem_munmap)      ( TNT_(make_mem_defined) );
}

VG_DETERMINE_INTERFACE_VERSION(tnt_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
