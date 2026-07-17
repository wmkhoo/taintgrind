from __future__ import print_function
import os, sys
import fileinput
import re

def sanitise_var(varname):
    # dot will complain if we have strange chars
    varname = varname.replace('[','_').replace(']','_')
    varname = varname.replace('.','_').replace('.','_')

    # E.g. <address>_unknownobj -> a<address>
    if "_unknownobj" in varname:
        varname = 'a' + varname.split("_unknownobj")[0]

    # E.g. <varname>:<address> -> a<address>
    if ":" in varname:
        varname = 'a' + varname.split(":")[1]

    # dot will complain if var name starts with a number
    if re.match('^[0-9]',varname):
        varname = 'g' + varname

    # dot will complain if var name contains a space
    if ' ' in varname:
        varname = varname.split(' ')[0]
    return varname


# Get the location/function of a line
# E.g. Input is '0x8048507: main (sign32.c:10)',
#      Output is 'main'
def get_loc(line):
    if '(' in line.split()[1]:
        return line.split()[1].split('(')[0]
    return line.split()[1] 


# g:     array to collect nodes by function
# label: node label
# loc:   function
def add_node(g, label, loc):
    if loc not in g:
        g[loc] = ""
    elif label not in g[loc]:
        g[loc] += "    %s\n" % (label)

    return g


# Extract the function name from, e.g.
# 0x4CC398D: free (malloc.c:3103)
# Expected output from above: free (malloc.c)
def getfuncname(addr):
    funcname = addr
    # Get rid of address
    if ": " in addr:
        funcname = addr.split(": ")[1]

    # Remove all digits and colons
    funcname = re.sub(r'[0-9:]', '', funcname)
    return funcname


TAINT_SINKS = ["__memcpy_sse_unaligned_erms (memmove-vec-unaligned-erms.S)",
               "memcpy@GLIBC_.. (memmove-vec-unaligned-erms.S)",
               "_int_malloc (malloc.c)",
              ]


# array to store all lines
data = []

# associative array to retrieve by variable name if any
var = {}
f = []

for line in fileinput.input():
    f.append(line)

# Pass 1: Remove non-taintgrind output
for i in range(len(f)):
    line = f[i]

    if not line.startswith("0x"):
        continue

    # Need to remove valgrind warnings, which add a LF
    # We need to add the next line as well
    if "-- warning:" in line:
        elts = line.split("|")
        nextline = f[i+1]
        c = 2

        while "-- warning:" in nextline:
            nextline = f[i+c]
            c += 1
        
        elts[-1] = " " + nextline
        line = "|".join(elts)

    data.append(line)


# Pass 2: Construct the graph; define nodes and edges
edges = []
nodes = {}

for line in data:
    addr = ""
    insn = ""
    insnty = ""
    val = ""
    flow = ""

    a = line.rstrip().split(" | ")

    if len(a) == 5:
        (addr,insn,insnty,val,flow) = line.rstrip().split(" | ")
    elif len(a) == 4:
        (addr,insnty,val,flow) = line.rstrip().split(" | ")
    elif len(a) == 2:
        (addr,flow) = line.rstrip().split(" | ")
    else:
        print("%d" % (len(a)))
        sys.exit(0)

    funcname = getfuncname(addr)

    # If there is taint flow
    if len(flow) >= 4:
        # Get location/function of line
        loc = get_loc(line)

        if " <- " in flow:
            (sink,sources) = flow.split(" <- ")

            for source in sources.split():
                # Add an edge for each source
                if "(" not in source:
                    # Direct source
                    edges.append("%s -> %s" % (sanitise_var(source),sanitise_var(sink)))
                    if source not in nodes:
                        nodes[source] = ("%s [label=\"%s\"]" % (sanitise_var(source), source), loc)
                else:
                    # Indirect source, colour it red
                    source2 = source[1:-1]
                    edges.append("%s -> %s[color=\"red\"]" % (sanitise_var(source2),sanitise_var(sink)))
                    if source2 not in nodes:
                        nodes[source2] = ("%s [label=\"%s\"]" % (sanitise_var(source2), source2), loc)

            vname = sanitise_var(sink)

            if (funcname in TAINT_SINKS) and ("Store" in insnty):
                # If we find Stores in predefined TAINT_SINKS, e.g. malloc or memcpy, colour it red
                nodes[sink] = ("%s [label=\"%s:%s (%s)\",fillcolor=red,style=filled]" % (vname,sink,val,insnty), loc)
            elif (len(sources.split()) > 1) and ("Store" in insnty):
                # If both address and data to this Store are tainted, colour it red
                nodes[sink] = ("%s [label=\"%s:%s (%s)\",fillcolor=red,style=filled]" % (vname,sink,val,insnty), loc)
            elif val and insnty:
                #os.system(">&2 echo \"%s\" %s" % (funcname, insnty))
                nodes[sink] = ("%s [label=\"%s:%s (%s)\"]" % (vname,sink,val,insnty), loc)
            else:
                nodes[sink] = ("%s [label=\"\" shape=point]" % (vname), loc)

        elif "Jmp" in insnty:
            vname = sanitise_var(flow)
            # If jump target is tainted, colour it red
            nodes[flow] = ("%s [label=\"%s:%s (%s)\",fillcolor=red,style=filled]" % (vname,flow,val,insnty), loc)
        elif "IfGoto" in insnty and funcname in TAINT_SINKS:
            vname = sanitise_var(flow)
            # If if-goto is in a taint sink, colour it red
            nodes[flow] = ("%s [label=\"%s:%s (%s)\",fillcolor=red,style=filled]" % (vname,flow,val,insnty), loc)
        elif val and insnty:
            vname = sanitise_var(flow)
            nodes[flow] = ("%s [label=\"%s:%s (%s)\"]" % (vname,flow,val,insnty), loc)
        else:
            vname = sanitise_var(flow)
            nodes[flow] = ("%s [label=\"\" shape=point]" % (vname), loc)


# Pass 3: Collect the nodes into subgraphs,
#         Grouped together by function
subgraph = {}

for line in data:
    addr = ""
    insn = ""
    insnty = ""
    val = ""
    flow = ""

    a = line.rstrip().split(" | ")

    if len(a) == 5:
        (_,_,_,_,flow) = line.rstrip().split(" | ")
    elif len(a) == 4:
        (_,_,_,flow) = line.rstrip().split(" | ")
    elif len(a) == 2:
        (_,flow) = line.rstrip().split(" | ")
    else:
        print("%d" % (len(a)))
        sys.exit(0)

    # If there is taint flow
    if len(flow) >= 4:
        # Get location/function of line
        loc = get_loc(line)

        if " <- " in flow:
            (sink,sources) = flow.split(" <- ")

            for source in sources.split():
                # Add an edge for each source
                if "(" not in source:
                    # Direct source
                    subgraph = add_node(subgraph, nodes[source][0], nodes[source][1])
                else:
                    # Indirect source, colour it red
                    source2 = source[1:-1]
                    subgraph = add_node(subgraph, nodes[source2][0], nodes[source2][1])

            subgraph = add_node(subgraph, nodes[sink][0], nodes[sink][1])
        else:
            subgraph = add_node(subgraph, nodes[flow][0], nodes[flow][1])


# Now we construct the graph
print("digraph {")

# Print subgraphs
for s in subgraph:
    sname = s.replace("???","unknown")
    sname = re.sub(r'[^a-zA-Z0-9_]', '_', sname)
    print("    subgraph cluster_%s{" % (sname))
    print("        label=\"%s\"" % (s))
    print(subgraph[s])
    print("    }")

# Print the edges
for e in edges:
    print("    " + e)

print("}")
