include $(top_srcdir)/Makefile.tool.am

#----------------------------------------------------------------------------
# Headers
#----------------------------------------------------------------------------

pkginclude_HEADERS = \
	taintgrind.h

noinst_HEADERS = \
	tnt_include.h \
	tnt_strings.h \
        copy.h

#----------------------------------------------------------------------------
# taintgrind-<platform>
#----------------------------------------------------------------------------

noinst_PROGRAMS  = taintgrind-@VGCONF_ARCH_PRI@-@VGCONF_OS@
if VGCONF_HAVE_PLATFORM_SEC
noinst_PROGRAMS += taintgrind-@VGCONF_ARCH_SEC@-@VGCONF_OS@
endif

TAINTGRIND_SOURCES_COMMON = \
	tnt_syswrap.c \
	tnt_main.c \
	tnt_translate.c \
        copy.c \
        tnt_smt2.c \
        tnt_asm.c

taintgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_SOURCES      = $(TAINTGRIND_SOURCES_COMMON)
taintgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
taintgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CFLAGS       = \
	$(AM_CFLAGS_@VGCONF_PLATFORM_PRI_CAPS@) -O2
taintgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_DEPENDENCIES = \
	$(TOOL_DEPENDENCIES_@VGCONF_PLATFORM_PRI_CAPS@)
taintgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDADD        = \
	$(TOOL_LDADD_@VGCONF_PLATFORM_PRI_CAPS@)
taintgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDFLAGS      = \
	$(TOOL_LDFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
taintgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LINK = \
        ../coregrind/link_tool_exe_@VGCONF_OS@ \
        @VALT_LOAD_ADDRESS_PRI@ \
        $(LINK) \
        $(taintgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CFLAGS) \
        $(taintgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDFLAGS)

if VGCONF_HAVE_PLATFORM_SEC
taintgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_SOURCES      = $(TAINTGRIND_SOURCES_COMMON)
taintgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
taintgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CFLAGS       = \
	$(AM_CFLAGS_@VGCONF_PLATFORM_SEC_CAPS@) -O2
taintgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_DEPENDENCIES = \
	$(TOOL_DEPENDENCIES_@VGCONF_PLATFORM_SEC_CAPS@)
taintgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDADD        = \
	$(TOOL_LDADD_@VGCONF_PLATFORM_SEC_CAPS@)
taintgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDFLAGS      = \
	$(TOOL_LDFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
taintgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LINK = \
        ../coregrind/link_tool_exe_@VGCONF_OS@ \
        @VALT_LOAD_ADDRESS_SEC@ \
        $(LINK) \
        $(taintgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CFLAGS) \
        $(taintgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDFLAGS)
endif

tnt_main.o: CFLAGS += -fomit-frame-pointer

