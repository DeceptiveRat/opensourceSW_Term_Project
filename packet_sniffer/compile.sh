#!/bin/bash 

if [ $# -ne 2 ]; then
	echo "usage: $0 <file name> <extra flag>"
	exit
fi

rm hacking_my.o
gcc hacking_my.c -o hacking_my.o -c -g
make clean FILENAME=$1
make debug FILENAME=$1 EXTRAFLAGS=$2
