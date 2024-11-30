#!/bin/bash 

default=`cat default.txt`

if [ $# -eq 1 ] && [ "$1" = "default" ]; then
	if [[ $default == make* ]] || [[ $default == gcc* ]]; then
		find . -name "*.h" | while read -r header_file; do
			c_file="${header_file%.h}.c"
			if [[ -f "$c_file" ]]; then
				o_file="${c_file%.c}.o"
				gcc -c "$c_file" -o "$o_file"
				echo "compiled $c_file into $o_file"
			else
				echo "warning: No matching .c file for $header_file"
			fi
		done
		eval "$default"
	else
		echo "DANGEROUS CONTENT IN DEFAULT FILE!"
	fi
	exit
elif [ "$1" = "set" ] && [ "$2" = "default" ]; then
	echo "$3" > default.txt
	exit
elif [ $# -ne 2 ]; then
	echo "usage: $0 <file name> <extra flag>"
	exit
fi

find . -name "*.h" | while read -r header_file; do
	c_file="${header_file%.h}.c"
	if [[ -f "$c_file" ]]; then
		o_file="${c_file%.c}.o"
		gcc -c "$c_file" -o "$o_file"
		echo "compiled $c_file into $o_file"
	else
		echo "warning: No matching .c file for $header_file"
	fi
done

make clean FILENAME="$1"
make debug FILENAME="$1" EXTRAFLAGS="$2"
