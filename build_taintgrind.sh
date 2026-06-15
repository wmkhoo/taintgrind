#!/bin/bash
# Find out how far we can parallelize the build
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)"
if [ -z "$jobs" ] || [ "$jobs" -lt 1 ]; then
    jobs=1
fi

download() {
    url="$1"
    output="$2"

    if command -v wget >/dev/null 2>&1; then
        wget "$url" -O "$output"
    elif command -v curl >/dev/null 2>&1; then
        curl -L "$url" -o "$output"
    else
        echo "Error: install wget or curl to download $url"
        exit 1
    fi
}

# Build valgrind
cd ../ && \
    ./autogen.sh && \
    ./configure --prefix="$(pwd)/build" && \
    make -j"$jobs" && \
    make install

# Download and extract capstone
cd taintgrind
CAPSTONE_VERSION="$(grep 'CAPSTONE_VERSION = ' Makefile.tool.am | sed 's/CAPSTONE_VERSION = //g')"
echo CAPSTONE_VERSION
echo "$CAPSTONE_VERSION"
download "https://github.com/aquynh/capstone/archive/$CAPSTONE_VERSION.tar.gz" capstone.tar.gz && \
    tar xf capstone.tar.gz

# Patch capstone
patch -p1 < "./capstone-$CAPSTONE_VERSION.patch"
retval=$?
if [ $retval -ne 0 ]; then
       echo "Return code was not zero but $retval"
       exit
fi

mv "capstone-$CAPSTONE_VERSION" capstone

# build taintgrind
../autogen.sh && \
    ./configure --prefix="$(pwd)/../build" && \
    make -j"$jobs" && \
    make install && \
    make check
