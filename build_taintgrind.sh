#!/bin/bash
# Patch valgrind-3.13
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

# grep the Makefile to get VGCONF_ARCH_PRI and VGCONF_ARCH_SEC
VGCONF_ARCH_PRI=$(grep VGCONF_ARCH_PRI Makefile | sed 's/VGCONF_ARCH_PRI = //g')
VGCONF_ARCH_SEC=$(grep VGCONF_ARCH_SEC Makefile | sed 's/VGCONF_ARCH_SEC = //g')

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

echo VGCONF_ARCH_PRI
echo $VGCONF_ARCH_PRI
if [ -n "$VGCONF_ARCH_PRI" ]; then
    sh configure_capstone.sh `pwd`/../build $VGCONF_ARCH_PRI && \
    cd capstone-$CAPSTONE_VERSION && \
    sh make_capstone.sh && \
    cd ..
else
    echo VGCONF_ARCH_PRI not defined in Makefile
    exit
fi

echo VGCONF_ARCH_SEC
echo $VGCONF_ARCH_SEC
if [ -n "$VGCONF_ARCH_SEC" ]; then
    sh configure_capstone.sh `pwd`/../build $VGCONF_ARCH_SEC && \
    cd capstone-$CAPSTONE_VERSION && \
    sh make_capstone.sh && \
    cd ..
fi

# build taintgrind
../autogen.sh && \
    ./configure --prefix=`pwd`/../build && \
    make -j"$jobs" && \
    make install && \
    make check
