#ifndef __TNT_STRUCTS_H__
#define __TNT_STRUCTS_H__

//#include <stdlib.h>

#define MAX_LEN 256
#define STACK_SIZE 102400

Int myStringArray_getIndex( struct myStringArray *a, const HChar* string );
Int myStringArray_push( struct myStringArray *a, const HChar* string );

//Stack of strings---------------------------------------
struct myStringArray{
   char m[STACK_SIZE][MAX_LEN];
   int size;
//   int get_index(char *string){
//      for(int i = 0; i < size; i++ ){
//         if( strstr(m[i], string) != NULL && strstr(string, m[i]) != NULL )
//            return i;
//      }
//      //msg( "get_index: string %s not found\n", string );
//      return -1;
//   };
//   void push( char *item ){
//      if( size >= STACK_SIZE ){
//         VG_(printf)("***Error - myStringArray.push: max stack limit reached %d\n", STACK_SIZE);
//         return;
//      }
//   
//      qsnprintf( m[size], MAX_LEN-1, "%s", item );
//      size++;   
//   }
//   // Same as push, but only unique strings. No copies allowed
//   // returns: true if unique, false if already found
//   bool pushUnique( char *item ){
//
//      for(int i = 0; i < size; i++ ){
//         if( strstr( m[i], item ) != NULL &&
//            strstr( item, m[i] ) != NULL ){
//            return false;
//         }
//      }
//
//      push( item );
//      return true;
//   }
//   char *pop( void ){
//      size--;
//      return m[size];
//   }
//   void chop( char *string ){
//      char *p = string;
//
//      while( *p != '\0' ){
//         p++;
//      }
//   
//      if( p != string ){
//         *(p-1) = '\0';
//      }
//   }
};

Int myStringArray_getIndex(struct myStringArray *a, const HChar* string){
   int i;

   for( i = 0; i < a->size; i++ ){
      if( VG_(strstr)(a->m[i], string) != NULL && VG_(strstr)(string, a->m[i]) != NULL )
         return i;
   }
   //msg( "get_index: string %s not found\n", string );
   return -1;
};

Int myStringArray_push( struct myStringArray *a, const HChar* string ){
   Int idx;
   if( a->size >= STACK_SIZE ){
      VG_(printf)("***Error - myStringArray.push: max stack limit reached %d\n", STACK_SIZE);
      //exit(-1);
      return -1;
   }
   // check if it already exists
   if ((idx = myStringArray_getIndex(a, string)) == -1) {
	   VG_(snprintf)( a->m[a->size], MAX_LEN-1, "%s", string );
	   idx = a->size;
	   a->size++;
   }
   return idx;
}
//End Stack of strings---------------------------------------------------

////Stack of addresses-----------------------------------------------------
//struct eaArray{
//   ea_t m[STACK_SIZE];
//   int size;
//   int get_index(ea_t addr){
//      for(int i = 0; i < size; i++ ){
//         if( addr == m[i] )
//            return i;
//      }
//      return -1;
//   };
//
//   void push( ea_t item ){
//      if( size >= STACK_SIZE ){
//         msg("***Error - eaArray.push: max stack limit reached %d\n", STACK_SIZE);
//         return;
//      }
//
//      m[size] = item;
//      size++;   
//   }
//
//   // Same as push, but only unique items. No copies allowed
//   // returns: true if unique, false if already found
//   bool pushUnique( ea_t item ){
//
//      for(int i = 0; i < size; i++ ){
//         if( m[i] == item ){
//            return false;
//         }
//      }
//
//      push( item );
//      return true;
//   }
//
//   ea_t pop( void ){
//      size--;
//      return m[size];
//   }
//};

//End Stack of Addresses----------------------------------
#endif
