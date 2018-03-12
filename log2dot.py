import os, sys
import fileinput
import re

def sanitise_var(varname):
    # dot will complain if we have strange chars
    varname = varname.replace('[','_').replace(']','_')

    # dot will complain if var name starts with a number
    if re.match('^[0-9]',varname):
        return 'g' + varname
    return varname


# Get the location/function of a line
# E.g. Input is '0x8048507: main (sign32.c:10)',
#      Output is 'main'
def get_loc(line):
    if '(' in line.split()[1]:
        return line.split()[1].split('(')[0]
    return line.split()[1] 


def add_node(g, label, loc):
    if loc not in g:
        g[loc] = ""

    g[loc] += "    %s\n" % (label)

    return g


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
#         Collect the nodes into subgraphs,
#         Grouped together by function
subgraph = {}
edges = []
nodes = []

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
        print "%d" % (len(a))
        sys.exit(0)

    # If there is taint flow
    if len(flow) >= 4:
        # Get location/function of line
        loc = get_loc(line)

        if "<-" in flow:
            (sink,sources) = flow.split(" <- ")

            for source in sources.split():
                # Add an edge for each source
                if "(" not in source:
                    # Direct source
                    edges.append("%s -> %s" % (sanitise_var(source),sanitise_var(sink)))
                    if source not in nodes:
                        nodes.append(source)
                        subgraph = add_node(subgraph, "%s [label=\"%s\"]" % (sanitise_var(source), source), loc)
                else:
                    # Indirect source, colour it red
                    source2 = source[1:-1]
                    edges.append("%s -> %s[color=\"red\"]" % (sanitise_var(source2),sanitise_var(sink)))
                    if source2 not in nodes:
                        nodes.append(source2)
                        subgraph = add_node(subgraph, "%s [label=\"%s\"]" % (sanitise_var(source2), source2), loc)

            vname = sanitise_var(sink)

            if (len(sources.split()) > 1) and ("Load" in insnty or "Store" in insnty):
                # If both address and data to this Load/Store are tainted,
                # Colour it red
                subgraph = add_node(subgraph, "%s [label=\"%s:%s (%s)\",fillcolor=red,style=filled]" % (vname,sink,val,insnty), loc)
            elif val and insnty:
                subgraph = add_node(subgraph, "%s [label=\"%s:%s (%s)\"]" % (vname,sink,val,insnty), loc)
            else:
                subgraph = add_node(subgraph, "%s [label=\"\"]" % (vname), loc)

            if sink not in nodes:
                nodes.append(sink)
        elif "Jmp" in insnty:
            vname = sanitise_var(flow)
            # If jump target is tainted, colour it red
            subgraph = add_node(subgraph, "%s [label=\"%s:%s (%s)\",fillcolor=red,style=filled]" % (vname,flow,val,insnty), loc)

            if flow not in nodes:
                nodes.append(flow)
        elif val and insnty:
            vname = sanitise_var(flow)
            subgraph = add_node(subgraph, "%s [label=\"%s:%s (%s)\"]" % (vname,flow,val,insnty), loc)

            if flow not in nodes:
                nodes.append(flow)
        else:
            vname = sanitise_var(flow)
            subgraph = add_node(subgraph, "%s [label=\"\"]" % (vname), loc)

            if flow not in nodes:
                nodes.append(flow)


# Now we construct the graph
print "digraph {"

# Print subgraphs
for s in subgraph:
    print "    subgraph cluster_%s{" % (s.replace(":","_").replace("???","unknown"))
    print "        label=\"%s\"" % (s)
    print subgraph[s]
    print "    }"

# Print the edges
for e in edges:
    print "    " + e

print "}"
