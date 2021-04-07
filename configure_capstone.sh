#!/bin/sh
if [ $# -ne 2 ]
then
  echo "Error in $0 - Invalid Argument Count"
  echo "Usage: $0 <valgrind-inst-dir> <arch>"
  exit
fi

# example: sh configure_capstone.sh `pwd`/../inst

VG_INST_DIR=$1
ARCH=$2

CAPSTONE_VERSION="3.0.4"

#- 1 Apply patches
#==================
# guide to patches http://www.cyberciti.biz/faq/appy-patch-file-using-patch-command/
# patches were created with 
# diff -rupN ./capstone/ ./capstone.patches/ > capstone.patch
# then I removed the Makefile one and the VG_define coz it fails or complains

#patch -p1 < ./capstone-$CAPSTONE_VERSION.patch
#retval=$?
#if [ $retval -ne 0 ]; then
#	echo "Return code was not zero but $retval"
#	exit
#fi

#-2 create make_capstone.sh with the rigth args
python make_capstone_options.py --vginstdir $VG_INST_DIR --capstonedir capstone-$CAPSTONE_VERSION --arch $ARCH --outmakefile make_capstone.sh
retval=$?
if [ $retval -ne 0 ]; then
	echo "Return code was not zero but $retval"
	exit
fi

