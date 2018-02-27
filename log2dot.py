import os, sys
import fileinput
import re

def get_load_or_store_addr(line):
    (addr,insn,val,tnt,flow) = line.split("|")

    if "LOAD" in line:
        # Retrieve the temp var for the address
        tmp = insn.split()[-1]

    elif "STORE" in line:
        # Retrieve tmp
        tmp = insn.split("STORE ")[1].split()[0]
    else:
        print "***get_load_or_store_addr: not load or store %s" % (line)
        sys.exit(0)

    if tmp in var:
        (addr2,insn2,val2,tnt2,flow2) = var[tmp].split("|")
        return val2.split()[0]
    else:
        #print "***%s not defined: %s" % (tmp, line)
        #print "***Suggest calling TNT_START_PRINT()"
        return tmp

def resolve_unknown_var(varname, line):
    if "_unknownobj" in varname:
        addr = get_load_or_store_addr(line)

        if addr in var:
            return var[addr]

    varname = varname.replace('[','_').replace(']','_')

    if re.match('^[0-9]',varname):
        return 'g' + varname
    return varname

def get_op(line):
    if "LOAD"  in line:    return "LOAD"
    if "STORE" in line:    return "STORE"
    if "IF"    in line:    return "IF"
    if "JMP"   in line:    return "JMP"
    if line.split(" | ")[1][0] == 'r':  return "PUT"
    if line.split(" = ")[1].split()[0][0] == 'r': return "GET"
    if line.split(" = ")[1].split()[0][0] == 't': return "RDTMP"
    return line.split(" = ")[1].split()[0]


# Get the location of a line
# 0x8048507: main (sign32.c:10)
def get_loc(line):
    if '(' in line.split()[1]:
        return line.split()[1].split('(')[0]
    return line.split()[1] 


# array to store all lines
data = []

# associative array to retrieve by variable name if any
var = {}
f = []

for line in fileinput.input():
    f.append(line)

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
    (addr,insn,val,tnt,flow) = line.split("|")
    
    if insn[1] == 't' or \
       insn[1] == 'r':
        var[insn.split()[0]] = line

    # If we found the symbol for an address, store it
    if "LOAD" in insn and "_unknownobj" not in line and len(flow) >= 4:
        addr = get_load_or_store_addr(line)
        if addr not in var:
            if ";" in flow:
                flows = flow.split("; ")
            else:
                flows = [flow]

            for flow in flows:
                if "<- " in flow:
                    var[addr] = flow.rstrip().split("<- ")[1]
                elif "<*- " in flow:
                    var[addr] = flow.rstrip().split("<*- ")[1]


# Now we construct the graph
edges = []
nodes = {}

for line in data:
    (addr,insn,val,tnt,flow) = line.split("|")

    # If there is taint flow
    if len(line.split(" | ")[-1]) >= 4:
        flow_orig = line.split(" | ")[-1].rstrip()

        if "<-" in flow_orig or "<*-" in flow_orig:
            if ";" in flow_orig:
                flows = flow_orig.split("; ")
            else:
                flows = [flow_orig]

            for flow in flows:
                sink = ""
                source = ""

                if " <- " in flow:
                    (sink,source) = flow.split(" <- ")
                elif " <*- " in flow:
                    (sink,source) = flow.split(" <*- ")

                if "LOAD" in line:
                    source = resolve_unknown_var(source, line)
                elif "STORE" in line:
                    sink = resolve_unknown_var(sink, line)

                src = []
                if ", " in source:
                    src = source.split(", ")
                else:
                    src.append(source)
 
                for source in src:
                    edges.append("%s -> %s" % (source,sink))

                    if source not in nodes:
                        nodes[source] = source

                if sink not in nodes:
                    nodes[sink] = sink

                if ";" in flow_orig:
                    # If there is more than 1 taint source to this node, colour it red
                    nodes[sink] = "%s [label=\"%s:%s (%s)\",color=red]" % (sink,sink,val,get_op(line))
                else:
                    nodes[sink] = "%s [label=\"%s:%s (%s)\"]" % (sink,sink,val,get_op(line))
        elif "JMP" in get_op(line):
            # If jump target is tainted, colour it red
            nodes[sink] = "%s [label=\"%s:%s (%s)\",fillcolor=red,style=filled]" % (sink,sink,val,get_op(line))
        else:
            nodes[sink] = "%s [label=\"%s:%s (%s)\"]" % (sink,sink,val,get_op(line))

# Collect the nodes into subgraphs
subgraph = {}

for line in data:
    (addr,insn,val,tnt,flow) = line.split("|")

    # If there is taint flow
    if len(line.split(" | ")[-1]) >= 4:
        flow = line.split(" | ")[-1].rstrip()

        if "<-" in flow or "<*-" in flow:
            if ";" in flow:
                flows = flow.split("; ")
            else:
                flows = [flow]

            for flow in flows:
                sink = ""
                source = ""

                if " <- " in flow:
                    (sink,source) = flow.split(" <- ")
                elif " <*- " in flow:
                    (sink,source) = flow.split(" <*- ")

                if "LOAD" in line:
                    source = resolve_unknown_var(source, line)
                elif "STORE" in line:
                    sink = resolve_unknown_var(sink, line)

                loc = get_loc(line)
    
                if loc not in subgraph:
                    subgraph[loc] = ""
                subgraph[loc] += "    %s\n" % (nodes[sink])
        else:

            loc = get_loc(line)
    
            if loc not in subgraph:
                subgraph[loc] = ""
            subgraph[loc] += "    %s\n" % (nodes[sink])


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
