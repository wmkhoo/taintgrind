#!/bin/sh

run ()
{
    echo "running: $*"
    eval $*

    if test $? != 0 ; then
	echo "error: while running '$*'"
	exit 1
    fi
}

run aclocal
run autoheader
run automake -c -a
run autoconf
