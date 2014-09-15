Taintgrind: a Valgrind taint analysis tool
==========================================


2014-09-15 Support for Valgrind 3.10.0, x86\_linux and amd64\_linux

2013-12-20 Experimental support for 32-bit ARM, tested on Android 4.4 emulator with API 19

2013-11-18 Currently supporting: Valgrind 3.9.0, x86\_linux and amd64\_linux



Installation
------------

1. Download [Valgrind](http://valgrind.org) and build


		[me@machine ~/] tar jxvf valgrind-X.X.X.tar.bz2
		[me@machine ~/] cd valgrind-X.X.X
		[me@machine ~/valgrind-X.X.X] ./autogen.sh
		[me@machine ~/valgrind-X.X.X] ./configure --prefix=`pwd`/inst
		[me@machine ~/valgrind-X.X.X] make && make install

2. Git clone and build Taintgrind


		[me@machine ~/valgrind-X.X.X] git clone http://github.com/wmkhoo/taintgrind.git
		[me@machine ~/valgrind-X.X.X] cd taintgrind 
		[me@machine ~/valgrind-X.X.X/taintgrind] ../autogen.sh
		[me@machine ~/valgrind-X.X.X/taintgrind] ./configure --prefix=`pwd`/../inst
		[me@machine ~/valgrind-X.X.X/taintgrind] make && make install

Usage
-----

	[me@machine ~/valgrind-X.X.X] ./inst/bin/valgrind --tool=taintgrind --help
	...
	user options for Taintgrind:
	    --file-filter=<full_path>   full path of file to taint [""]
	    --taint-start=[0,800000]    starting byte to taint (in hex) [0]
	    --taint-len=[0,800000]      number of bytes to taint from taint-start (in hex)[800000]
	    --taint-all= no|yes         taint all bytes of all files read. warning: slow! [no]
	    --tainted-ins-only= no|yes  print tainted instructions only [yes]
	    --critical-ins-only= no|yes print critical instructions only [no]


Sample output
-------------

The output of Taintgrind is a list of Valgrind IR (VEX) statements in the form

	Address Location | VEX-ID VEX-IRStmt | Runtime value(s) | Taint value(s) | Information flow


E.g.


	> valgrind --tool=taintgrind --file-filter=/path/to/test.txt --taint-start=0 --taint-len=1 --critical-ins-only=no gzip -c path/to/test.txt
	==31644== Taintgrind, the taint analysis tool
	==31644== Copyright (C) 2010, and GNU GPL'd, by Wei Ming Khoo.
	==31644== Using Valgrind-3.7.0 and LibVEX; rerun with -h for copyright info
	==31644== Command: gzip -c /test.txt
	==31644== 
	BBs read: 1000 On
	syscall open 1 /path/to/test.txt 8900 3
	syscall read 1 3 0x0 0x5 0x8097ae0 0x61
	taint_byte 0x08097ae0 0x61
	0x8049A1B: lm_init (deflate.c:345) | 0x15008 t24 = LD I8 0x8097ae0 | 0x61 0x8097ae0 | 0xff 0x0 | t24 <- window
	0x8049A1B: lm_init (deflate.c:345) | 0x15007 t23 = 8Sto16 t24 | 0x61 0x61 | 0xff 0xff | t23 <- t24
	0x8049A22: lm_init (deflate.c:345) | 0x15006 t5 = Shl32 t23 0x5 | 0xc20 0x61 | 0x1fe0 0xff | t5 <- t23
	0x8049A22: lm_init (deflate.c:345) | 0x15006 t8 = Xor32 t5 t25 | 0xc42 0xc20 0x62 | 0x1fe0 0x1fe0 0x0 | t8 <- t5
	0x8049A22: lm_init (deflate.c:345) | 0x19003 put 0 = t8 | 0xc42 | 0x1fe0 | r0 <- t8
	0x8049A2E: lm_init (deflate.c:345) | 0x19006 ST 0x805badc = t8 I32 | 0x805badc 0xc42 | 0x0 0x1fe0 | ins_h <- t8
	0x8049D45: deflate (deflate.c:684) | 0x15008 t35 = LD I32 0x805badc | 0x823 0x805badc | 0x7c00 0x0 | t35 <- ins_h
	0x8049D51: deflate (deflate.c:684) | 0x15006 t7 = Shl32 t35 0x5 | 0x10460 0x823 | 0xf8000 0x7c00 | t7 <- t35
	0x8049D51: deflate (deflate.c:684) | 0x15006 t10 = Xor32 t39 t7 | 0x10404 0x64 0x10460 | 0xf8000 0x0 0xf8000 | t10 <- t7
	0x8049D51: deflate (deflate.c:684) | 0x15006 t13 = And32 t10 0x7fff | 0x404 0x10404 | 0x0 0xf8000 | 
	0x8049E90: deflate (deflate.c:744) | 0x15008 t29 = LD I8 t26 | 0x61 0x8097ae0 | 0xff 0x0 | t29 <- window
	0x8049E90: deflate (deflate.c:744) | 0x15007 t61 = 8Sto16 t29 | 0x61 0x61 | 0xff 0xff | t61 <- t29
	0x8049E90: deflate (deflate.c:744) | 0x15003 t28 = t61 | 0x61 | 0xff | t28 <- t61
	0x8049E9E: deflate (deflate.c:744) | 0x19006 ST t30 = t28 I32 | 0xbef37c34 0x61 | 0x0 0xff | bef37c34_unknownobj <- t28
	0x804FD52: ct_tally (trees.c:966) | 0x15008 t50 = LD I32 t48 | 0x61 0xbef37c34 | 0xff 0x0 | t50 <- bef37c34_unknownobj
	0x804FD52: ct_tally (trees.c:966) | 0x19003 put 0 = t50 | 0x61 | 0xff | r0 <- t50
	0x804FD55: ct_tally (trees.c:967) | 0x15001 t53 = get 0 i8 | 0x61 | 0xff | t53 <- r0
	0x804FD55: ct_tally (trees.c:967) | 0x19006 ST t51 = t53 I8 | 0x807f240 0x61 | 0x0 0xff | inbuf <- t53
	0x804F1E8: compress_block (trees.c:1031) | 0x15008 t25 = LD I8 t22 | 0x61 0x807f240 | 0xff 0x0 | t25 <- inbuf
	0x804F1E8: compress_block (trees.c:1031) | 0x15007 t35 = 8Sto16 t25 | 0x61 0x61 | 0xff 0xff | t35 <- t25
	0x804F1E8: compress_block (trees.c:1031) | 0x15003 t24 = t35 | 0x61 | 0xff | t24 <- t35
	0x804F1E8: compress_block (trees.c:1031) | 0x19003 put 28 = t24 | 0x61 | 0xff | r28 <- t24
	0x804F1A8: compress_block (trees.c:1033) | 0x15001 t27 = get 28 i32 | 0x61 | 0xff | t27 <- r28
	0x804F1A8: compress_block (trees.c:1033) | 0x15006 t26 = Shl32 t27 0x2 | 0x184 0x61 | 0x3fc 0xff | t26 <- t27
	0x804F1A8: compress_block (trees.c:1033) | 0x15006 t25 = Add32 t24 t26 | 0x805daa4 0x805d920 0x184 | 0xfffffffc 0x0 0x3fc | t25 <- t26
	0x804F1AE: compress_block (trees.c:1033) | 0x15006 t29 = Add32 t25 0x2 | 0x805daa6 0x805daa4 | 0xfffffffc 0xfffffffc | t29 <- t25

Details of VEX-IDs and VEX-IRStmts can be found in VEX/pub/libvex\_ir.h .

Notes
-----
Taintgrind is based on [Valgrind](http://valgrind.org)'s MemCheck and [Flayer](http://code.google.com/p/flayer/).

Taintgrind borrows the bit-precise shadow memory from MemCheck and only propagates explicit data flow. This means that Taintgrind will not propagate taint in control structures such as if-else, for-loops and while-loops. Taintgrind will also not propagate taint in dereferenced tainted pointers.

Run without any parameters, Taintgrind will not taint anything and the program output should be printed. Run with the "--file-filter=[file]" option, Taintgrind will output an execution trace starting at the point [file] is read, with all bytes of [file] tainted. The taint can be restricted at the byte level using the "--taint-start" and "--taint-len" options. Running with the "--tainted-ins-only=yes" option restricts the output to instructions with tainted data only.

The output of Taintgrind can be *huge*. You might consider piping the output to gzip.

	[valgrind command] 2>&1 | gzip > output.gz

