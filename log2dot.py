import os, sys

def get_load_or_store_addr(line):
    (addr,insn,val,tnt,flow) = line.split("|")

    if "LOAD" in line:
        # Retrieve the temp var for the address
        tmp = insn.split()[-1]

    elif "STORE" in line:
        # Retrieve tmp
        tmp = insn.split("STORE ")[1].split()[0]
    else:
        print "***get_load_or_store_addr: %s" % (line)

    if tmp in var:
        (addr2,insn2,val2,tnt2,flow2) = var[tmp].split("|")
        return val2.split()[0]
    else:
        print "***%s not defined: %s" % (tmp, line)
        sys.exit(0)

def resolve_unknown_var(varname, line):
    if "_unknownobj" in varname:
        addr = get_load_or_store_addr(line)

        if addr in var:
            return var[addr]
        else:
            print "***%s not in var: %s" % (addr,line)

    return varname

if len(sys.argv) != 2:
    print "Usage: %s <log file>" % (sys.argv[0])
    sys.exit(0)

f = open(sys.argv[1], "r")

line = f.readline()

# array to store all lines
data = []

# associative array to retrieve by variable name if any
var = {}

while line:
    if line.startswith("=="):
        line = f.readline()
        continue

    # Need to remove valgrind warnings, which add a LF
    # We need to add the next line as well
    if "-- warning:" in line:
        elts = line.split("|")
        nextline = f.readline()

        while "-- warning:" in nextline:
            nextline = f.readline()
        
        elts[-1] = " " + nextline
        line = "|".join(elts)
        #print "After: " + line

    data.append(line)
    #if len(line.split("|")) == 4:
    #    (addr,insn,val,tnt) = line.split("|")
    #else:
    (addr,insn,val,tnt,flow) = line.split("|")
    
    if insn[1] == 't' or \
       insn[1] == 'r':
        var[insn.split()[0]] = line

    # If we found the symbol for an address, store it
    if "LOAD" in insn and "_unknownobj" not in line and len(flow) >= 4:
        addr = get_load_or_store_addr(line)
        if addr not in var:
            var[addr] = flow.rstrip().split("<- ")[1]

    line = f.readline()

# Now we construct the graph
print "digraph {"

for line in data:
    (addr,insn,val,tnt,flow) = line.split("|")

    # If there is taint flow
    if len(line.split(" | ")[-1]) >= 4:
        flow = line.split(" | ")[-1].rstrip()

        if "<-" in flow:
            (sink,source) = flow.split(" <- ")

            if "LOAD" in line:
                source = resolve_unknown_var(source, line)
            elif "STORE" in line:
                sink = resolve_unknown_var(sink, line)
                
            print "%s -> %s" % (source,sink)

print "}"
