#include $(top_srcdir)/Makefile.tool-tests.am
include ../../Makefile.tool-tests.am

SUBDIRS = .

check_PROGRAMS = checktaint \
                 heartbleed \
                 memchr \
                 memcpy \
                 misprint \
                 sign8  \
                 sign16 \
                 sign32 \
                 sign64 \
                 signstdin \
                 signstdin2 \
                 symbolic_maze \
                 taint_stdin

checktaint_SOURCES = checktaint.c
checktaint_CFLAGS = -I../ -I../../include -g -O0
heartbleed_SOURCES = heartbleed.c
heartbleed_CFLAGS = -I../ -I../../include -g -O0
memchr_SOURCES = memchr.c
memchr_CFLAGS = -I../ -I../../include -g -O0
memcpy_SOURCES = memcpy.c
memcpy_CFLAGS = -I../ -I../../include -g -O0
misprint_SOURCES = misprint.c
misprint_CFLAGS = -I../ -I../../include -g -O0 -fno-inline -fno-omit-frame-pointer -fno-stack-protector -no-pie
sign8_SOURCES = sign8.c
sign8_CFLAGS = -I../ -I../../include -g -O0
sign16_SOURCES = sign16.c
sign16_CFLAGS = -I../ -I../../include -g -O0
sign32_SOURCES = sign32.c
sign32_CFLAGS = -I../ -I../../include -g -O0
sign64_SOURCES = sign64.c
sign64_CFLAGS = -I../ -I../../include -g -O0
signstdin_SOURCES = signstdin.c
signstdin_CFLAGS = -I../ -I../../include -g -O0
signstdin2_SOURCES = signstdin2.c
signstdin2_CFLAGS = -I../ -I../../include -g -O0
symbolic_maze_SOURCES = symbolic_maze.c
symbolic_maze_CFLAGS = -I../ -I../../include -O0
taint_stdin_SOURCES = taint_stdin.c
taint_stdin_CFLAGS = -I../ -I../../include -g -O0
