#!/bin/bash
# Patch valgrind
patch -d ../ -p0 < d3basics.patch

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

# Download and extract capstone
cd taintgrind
CAPSTONE_VERSION=$(grep 'CAPSTONE_VERSION = ' Makefile.tool.am | sed 's/CAPSTONE_VERSION = //g')
echo CAPSTONE_VERSION
echo $CAPSTONE_VERSION
wget https://github.com/aquynh/capstone/archive/$CAPSTONE_VERSION.tar.gz -O capstone.tar.gz && \
    tar xf capstone.tar.gz

# Patch capstone
patch -p1 < ./capstone-$CAPSTONE_VERSION.patch
retval=$?
if [ $retval -ne 0 ]; then
       echo "Return code was not zero but $retval"
       exit
fi

mv capstone-$CAPSTONE_VERSION capstone

# build taintgrind
../autogen.sh && \
    ./configure --prefix=`pwd`/../build && \
    make -j"$jobs" && \
    make install && \
    make check
