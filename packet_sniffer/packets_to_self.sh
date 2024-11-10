#!/bin/bash 

TARGET_IP="127.0.0.1"
TARGET_PORT=9999
MESSAGE="a"

for i in {1..100}
do
	echo -n "$MESSAGE" | nc -u -w 1 "$TARGET_IP" "$TARGET_PORT"
done
