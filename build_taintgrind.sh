#!/bin/bash
# Patch valgrind-3.13
patch -d ../ -p0 < d3basics.patch

# Build valgrind
cd ../ && \
    ./autogen.sh && \
    ./configure --prefix=`pwd`/build && \
    make && \
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
    make && \
    make install && \
    make check
