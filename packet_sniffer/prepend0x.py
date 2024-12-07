#!/bin/python3 

with open('bytestream.txt', 'r', encoding='utf-8') as file:
	content = file.read()

if(len(content) % 2 != 1):
	print("Byte stream does not have even length!")
	print(len(content))
	exit()

newcontent = ""

for i in range(0, len(content) - 1, 2):
	newcontent += "0x"
	newcontent += content[i:i+2]
	newcontent += ", "

with open('hex.txt', 'w', encoding='utf-8') as outputfile:
	outputfile.write(newcontent)
