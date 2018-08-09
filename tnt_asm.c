/*
 * 
 * Not sure if it's possible to get the guest architecture at run time.
 * The instrument() function in tnt_translate.c has a parameter 
 * VexArchInfo* archinfo_host, but this is the host, not the guest.
 * This is called from VEX/priv/main_main.c
 * 
 * So instead, I use a macro because that's the way valgrind seems to do
 * it internally at compilation time, see coregrind/m_machine.c
 * 
 * So I copy their macros here and set the correct architecture, 
 * then use capstone to disassemble [0]. An example can be found at [1].
 * 
 * For installation, see [2]. It may vary depending on your platform.
 * Headers should be installed under <YOUR_INCLUDE>/capstone/
 * 
 * [0] http://www.capstone-engine.org
 * [1] http://www.capstone-engine.org/lang_c.html
 * [2] http://www.capstone-engine.org/documentation.html
 * 
 * */


#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"		// VG_(*printf)
#include "pub_tool_hashtable.h"   // For tnt_include.h, VgHashtable

#include "tnt_include.h"
#include "tnt_asm.h"

// capstone stuff
#include <inttypes.h>
#include <capstone/capstone.h>

/*
	as defined in capstone.h
	========================
	
	cs_arch:
	-------
	CS_ARCH_ARM = 0,	// ARM architecture (including Thumb, Thumb-2)
	CS_ARCH_ARM64,		// ARM-64, also called AArch64
	CS_ARCH_MIPS,		// Mips architecture
	CS_ARCH_X86,		// X86 architecture (including x86 & x86-64)
	CS_ARCH_PPC,		// PowerPC architecture
	CS_ARCH_SPARC,		// Sparc architecture
	CS_ARCH_SYSZ,		// SystemZ architecture
	CS_ARCH_XCORE,		// XCore architecture
	CS_ARCH_MAX,
	CS_ARCH_ALL = 0xFFFF, // All architectures - for cs_support()

	cs_mode:
	-------
	CS_MODE_LITTLE_ENDIAN = 0,	// little-endian mode (default mode)
	CS_MODE_ARM = 0,	// 32-bit ARM
	CS_MODE_16 = 1 << 1,	// 16-bit mode (X86)
	CS_MODE_32 = 1 << 2,	// 32-bit mode (X86)
	CS_MODE_64 = 1 << 3,	// 64-bit mode (X86, PPC)
	CS_MODE_THUMB = 1 << 4,	// ARM's Thumb mode, including Thumb-2
	CS_MODE_MCLASS = 1 << 5,	// ARM's Cortex-M series
	CS_MODE_V8 = 1 << 6,	// ARMv8 A32 encodings for ARM
	CS_MODE_MICRO = 1 << 4, // MicroMips mode (MIPS)
	CS_MODE_MIPS3 = 1 << 5, // Mips III ISA
	CS_MODE_MIPS32R6 = 1 << 6, // Mips32r6 ISA
	CS_MODE_MIPSGP64 = 1 << 7, // General Purpose Registers are 64-bit wide (MIPS)
	CS_MODE_V9 = 1 << 4, // SparcV9 mode (Sparc)
	CS_MODE_BIG_ENDIAN = 1 << 31,	// big-endian mode
	CS_MODE_MIPS32 = CS_MODE_32,	// Mips32 ISA (Mips)
	CS_MODE_MIPS64 = CS_MODE_64,	// 
*/

// global variables
#define INVALID (-1)
static csh handle 	= 	INVALID;
static cs_insn *insn 	= 	(void*)INVALID;
static cs_arch arch	=	INVALID;
static cs_mode mode 	=	INVALID;

#if defined(VGA_arm)
static csh handle2 	= 	INVALID;
static cs_mode mode2 	=	INVALID;
#endif

static Bool is_init(void) {
	return (handle != INVALID && arch != INVALID && mode != INVALID);
}

static void reset(void) {
	handle 	= 	INVALID;
	insn 	= 	(void*)INVALID;
	arch	=	INVALID;
	mode 	=	INVALID;
}

/*
 * 
 * # CAPSTONE_VALGRIND
ifdef CAPSTONE_VALGRIND
LDFLAGS += -nodefaultlibs -nostartfiles
#hellow rold
endif
 * 
 * 
 * */
Bool TNT_(asm_init)(void) {
	// here we set the global var
	
	/*
	 * My understanding from reading coregrind/m_machine.c is that:
	 * - x86 is only 32 bits
	 * - amd64 is amd and x86-64
	 * - the rest is self-explanatory
	 * 
	 * see http://www.capstone-engine.org/lang_c.html for the mapping to capstone
	 */
	
	cs_err err = CS_ERR_OK;
	tl_assert ( ! is_init() );
	reset();
	
#if defined(VGA_x86)

	arch = CS_ARCH_X86;
	mode = CS_MODE_32;
	
#elif defined(VGA_amd64)

	arch = CS_ARCH_X86;
	mode = CS_MODE_64;
	
#elif defined(VGA_ppc32)

	arch = CS_ARCH_PPC;
	mode = CS_MODE_32;
	
#elif defined(VGA_ppc64be) || defined(VGA_ppc64le)

	arch = CS_ARCH_PPC;
	mode = CS_MODE_64;
	
#elif defined(VGA_arm)

	arch = CS_ARCH_ARM;
	mode = CS_MODE_ARM;	// default
	mode2 = CS_MODE_THUMB;	// if ARM mode fails
	
#elif defined(VGA_arm64)

	arch = CS_ARCH_ARM64;
	mode = CS_MODE_ARM; 	// need to check these
	
#elif defined(VGA_s390x)

	arch = CS_ARCH_SYSZ;
	mode = CS_MODE_64;	// check this
	
#elif defined(VGA_mips32)

	arch = CS_ARCH_MIPS;
	mode = CS_MODE_MIPS32;
	
#elif defined(VGA_mips64)

	arch = CS_ARCH_MIPS;
	mode = CS_MODE_MIPS64;
	
#else
	Platform not supported!
#endif

	if ( (err=cs_open(arch, mode, &handle)) != CS_ERR_OK) { 
		VG_(printf)("Failed cs_open");
		goto end; 
	}
#if defined(VGA_arm)
	if ( (err=cs_open(arch, mode2, &handle2)) != CS_ERR_OK) { 
		VG_(printf)("Failed cs_open");
		goto end; 
	}
#endif
	//// use AT&T syntax -- not sure this will fail on non-intel platforms...
	//if ( (err=cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT)) != CS_ERR_OK) {
	//	VG_(printf)("Failed cs_option. Make your capstone was NOT compiled with CAPSTONE_X86_ATT_DISABLE");
	//	goto end;
	//}
	
	end:
	return (err==CS_ERR_OK);
}

void TNT_(asm_release)(void) {
	
	tl_assert ( is_init() );
	cs_close(&handle);
	reset();
	
}

Bool TNT_(asm_guest_pprint)(Addr a, SizeT len, char *out, SizeT olen) {
	
	tl_assert ( is_init() );
	
	size_t count;
	Bool ret = False;
	
	// see http://www.capstone-engine.org/lang_c.html
	count = cs_disasm(handle, (uint8_t*)a, len, a, 0, &insn);
	if (count > 0) {
           // Only copy the first instruction
           VG_(snprintf)(out, olen, "%s %s", insn[0].mnemonic, insn[0].op_str);
	   cs_free(insn, count);
	   ret = True;
	}
#if defined(VGA_arm)
	else { // if primary mode fails, try secondary mode
	   count = cs_disasm(handle2, (uint8_t*)a, len, a, 0, &insn);
	   if (count > 0) {
              // Only copy the first instruction
              VG_(snprintf)(out, olen, "%s %s", insn[0].mnemonic, insn[0].op_str);
	      cs_free(insn, count);
	      ret = True;
	   }
        }
#endif
 
	return ret;
}
