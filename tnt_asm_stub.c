#include "pub_tool_tooliface.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_hashtable.h"

#include "tnt_include.h"
#include "tnt_asm.h"

Bool TNT_(asm_init)(void)
{
   return True;
}

void TNT_(asm_release)(void)
{
}

Bool TNT_(asm_guest_pprint)(Addr a, SizeT len, char *out, SizeT olen)
{
   (void)len;
   VG_(snprintf)(out, olen, "instruction@%#llx", (ULong)a);
   return True;
}
