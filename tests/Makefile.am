#include $(top_srcdir)/Makefile.tool-tests.am
include ../../Makefile.tool-tests.am

SUBDIRS = .

check_PROGRAMS = heartbleed \
                 memcpy \
                 sign8  \
                 sign16 \
                 sign32 \
                 sign64 \
                 signstdin \
                 signstdin2 \
                 taint_stdin \
                 misprint

heartbleed_SOURCES = heartbleed.c
heartbleed_CFLAGS = -I../ -I../../include
memcpy_SOURCES = memcpy.c
memcpy_CFLAGS = -I../ -I../../include
sign8_SOURCES = sign8.c
sign8_CFLAGS = -I../ -I../../include
sign16_SOURCES = sign16.c
sign16_CFLAGS = -I../ -I../../include
sign32_SOURCES = sign32.c
sign32_CFLAGS = -I../ -I../../include
sign64_SOURCES = sign64.c
sign64_CFLAGS = -I../ -I../../include
signstdin_SOURCES = signstdin.c
signstdin_CFLAGS = -I../ -I../../include
signstdin2_SOURCES = signstdin2.c
signstdin2_CFLAGS = -I../ -I../../include
taint_stdin_SOURCES = taint_stdin.c
taint_stdin_CFLAGS = -I../ -I../../include
misprint_SOURCES = misprint.c
misprint_CFLAGS = -I../ -I../../include -g -O0 -fno-inline -fno-omit-frame-pointer -fno-stack-protector -m32
