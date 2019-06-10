#!/bin/bash
# Patch valgrind-3.13
patch -d ../ -p0 < d3basics.patch

# Patch link_exe_tool_darwin
patch -d ../ -p0 < link_tool_exe_darwin.patch

# Find out how far we can parallelize the build
jobs="`lscpu -p | awk 'BEGIN { n = 0 } /^[^#]/ { n += 1 } END { print n }'`"
if [ "" = "$jobs" -o "1" -gt "$jobs" ]; then
    jobs=1
fi

# Build valgrind
cd ../ && \
    ./autogen.sh && \
    ./configure --prefix=`pwd`/build && \
    make -j"$jobs" && \
    make install

# build capstone
cd taintgrind && \
    wget https://github.com/aquynh/capstone/archive/3.0.4.tar.gz -O capstone.tar.gz && \
    tar xf capstone.tar.gz && \
    sh configure_capstone.sh `pwd`/../build && \
    cd capstone-3.0.4 && \
    sh make_capstone.sh

# build taintgrind
cd ../ && \
    ../autogen.sh && \
    ./configure --prefix=`pwd`/../build && \
    make -j"$jobs" && \
    make install && \
    make check
