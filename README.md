Taintgrind: a Valgrind taint analysis tool
==========================================

2025-05-27 Support for Valgrind 3.25.1, x86\_linux, amd64\_linux, arm\_linux [v3.25.1](https://github.com/wmkhoo/taintgrind/releases/tag/v3.25.1)

2023-10-24 Support for Valgrind 3.21.0, x86\_linux, amd64\_linux, arm\_linux [v3.21.0](https://github.com/wmkhoo/taintgrind/releases/tag/v3.21.0)

2021-11-19 Support for Valgrind 3.18.1, x86\_linux, amd64\_linux, arm\_linux [v3.18.1](https://github.com/wmkhoo/taintgrind/releases/tag/v3.18.1)


Installation (using Docker)
---------------------------

Make sure you have Docker installed. Then do:

	~$ git clone http://github.com/wmkhoo/taintgrind
	~$ cd taintgrind 
	~/taintgrind$ docker build -t taintgrind .

After the container is built, you can run taintgrind by doing

	~/taintgrind$ sudo docker run -it --rm -v $(pwd):/pwd taintgrind <ARGUMENTS>
	~/taintgrind$ sudo docker run -it --rm -v $(pwd):/pwd taintgrind tests/sign32


Installation (from source)
--------------------------

1. Install Dependencies (Ubuntu)


		~$ apt install -y git wget gcc build-essential automake python gcc-multilib
		
2. Download [Valgrind](http://valgrind.org)


		~$ tar jxvf valgrind-X.X.X.tar.bz2
		~$ cd valgrind-X.X.X
		~/valgrind-X.X.X$ 

3. Git clone taintgrind


		~/valgrind-X.X.X$ git clone http://github.com/wmkhoo/taintgrind.git
		~/valgrind-X.X.X$ cd taintgrind 

4. Run build_taintgrind.sh (to build valgrind, taintgrind and [Capstone](http://github.com/aquynh/capstone))


A simple example
----------------

A simple example is tests/sign32.c

	1  #include "taintgrind.h"
	2  int get_sign(int x) {
	3      if (x == 0) return 0;
	4      if (x < 0)  return -1;
	5      return 1;
	6  }
	7  int main(int argc, char **argv)
	8  {
	9      int a = 1000;
	10     // Defines int a as tainted
	11     TNT_TAINT(&a, sizeof(a));
	12     int s = get_sign(a);
	13     return s;
	14 }

The TNT_TAINT client request (defined in taintgrind.h) taints a.
See [Client Requests](https://github.com/wmkhoo/taintgrind/wiki/Client-requests) for more information on the client requests available.

Compile with

	../taintgrind$ make check

Run with

	../taintgrind$ ../build/bin/valgrind --tool=taintgrind tests/sign32

or simply

	../taintgrind$ ../build/bin/taintgrind tests/sign32

![Example output](../assets/sign32_cli.png?raw=true)


The output of taintgrind is of the form

	Address/Location | Assembly instruction | Instruction type | Runtime value(s) | Information flow

The first instruction indicates an integer is loaded from a into temporary variable t22\_6518. 
Its run-time value is 0x3e8 or 1,000 (hightlighted in red). 
With debugging information, taintgrind can list the source location, e.g. sign32.c:12 (highlighted in magenta), and the variable name (a).
Only one run-time/taint value per instruction is shown. That variable is usually the one being assigned. In the case of an if-goto, it is the conditional variable; in the case of an indirect jump, it is the jump target; for loads and stores, it is the data.
The assembly instructions, e.g. jne 0x1088f0, are highlighted in green.
The other instructions are intermediate VEX instructions, which have been either omitted or simplified.
As expected, the conditions (instructions 0x1088E7 and 0x1088F4, are both false, and are thus 0.
	
See [Detecting a classic buffer overflow](https://github.com/wmkhoo/taintgrind/wiki/Detecting-a-classic-buffer-overflow)


Graph Visualisation
-------------------

Create a Graphviz dot file with e.g.

	$ taintgrind tests/sign32 2>&1 | python log2dot.py > sign32.dot

Visualise the graph with

	$ sudo apt install graphviz
	$ dot -Tpng sign32.dot -o sign32.png
	
Or, for larger graphs

	$ dot -Tsvg sign32.dot -o sign32.svg
	
![Example taint graph](../assets/sign32_small.png?raw=true)



Tainting file input
-------------------

	~/valgrind-X.X.X/taintgrind$ ../build/bin/taintgrind --help
	...
	user options for Taintgrind:
	    --file-filter=<full_path>   full path of file to taint [""]
	    --taint-start=[0,800000]    starting file byte to taint (in hex) [0]
	    --taint-len=[0,800000]      number of file bytes to taint from taint-start (in hex)[800000]
	    --taint-stdin= no|yes       taint stdin [no]
	    --taint-network= no|yes     taint network data [no]
	    --taint-all= no|yes         taint all files, stdin, network. warning: slow! [no]
	    --tainted-ins-only= no|yes  print tainted instructions only [yes]
	    --critical-ins-only= no|yes print critical instructions only [no]
	    --compact= no|yes           print the logs in compact form (less difficult to read, faster to process by scripts) [no]\n"
	    --smt2= no|yes              output SMT-LIBv2 format [no]\n"
	    --head= no|yes              limited taint propagation [no]\n"

If the file-filter field is '\*', it is equivalent to --taint-all=yes.
Tainted instructions are really instructions where one or more of its input/output variables are tainted.
At the moment, critical instructions include loads, stores, conditional jumps and indirect jumps/calls. If --critical-ins-only is turned on, all other instructions are not printed.
The --tainted-ins-only and --critical-ins-only options control the output of taintgrind. If both of these options are 'no', then taintgrind prints every instruction executed. 
Run without any parameters, taintgrind will not taint anything and the program output should be printed.

To taint all contents of a file, run:

	$ taintgrind --file-filter=/path/to/test.txt gzip -c path/to/test.txt

To limit taint to certain bytes, run:

	$ taintgrind --file-filter=/path/to/test.txt --taint-start=0 --taint-len=1 gzip path/to/test.txt

For generating SMT Libv2, see [Generating SMT Libv2 output](https://github.com/wmkhoo/taintgrind/wiki/Generating-SMT-Libv2-output)

For limiting taint propagation, see [Limiting taint propagation](https://github.com/wmkhoo/taintgrind/wiki/Limiting-taint-propagation-with-head=yes)


Notes
-----

Taintgrind is based on [Valgrind](http://valgrind.org)'s MemCheck and [Flayer](http://code.google.com/p/flayer/).

Taintgrind borrows the bit-precise shadow memory from MemCheck and only propagates explicit data flow. This means that Taintgrind will not propagate taint in control structures such as if-else, for-loops and while-loops. Taintgrind will also not propagate taint in dereferenced tainted pointers.
For more information, see [Control-flow and Pointer tainting](https://github.com/wmkhoo/taintgrind/wiki/Control-flow-and-Pointer-tainting).

Taintgrind has been used in [SOAAP](https://github.com/CTSRD-SOAAP/) and [Secretgrind](https://github.com/lmrs2/secretgrind).


License
-------

Taintgrind is licensed under GNU GPLv2.


Thanks
------
Many of the improvements wouldn't be possible without help, feedback, bug reports, or patches from:

```
Khilan Gudka
Laurent Simon
Giuseppe Di Guglielmo
Marc Heuse
tkchia
Marek Zmysłowski
```
