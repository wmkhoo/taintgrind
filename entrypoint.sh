#!/bin/bash

#/code/valgrind/build/bin/valgrind --tool=taintgrind $@
../build/bin/valgrind --tool=taintgrind $@
