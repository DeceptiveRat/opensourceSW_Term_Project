#pragma once
#include <stdio.h>

#define ERROR_MESSAGE_SIZE 200

// linked list of allocated pointers for easy deallocation
struct allocated_pointers
{
	void* pointer;
	struct allocated_pointers* next_pointer;
};

/*
 * Accepts a socket FD and a ptr to a null terminated string to send.
 * It will make sure all byets are sent.
 * Returns 0 on error and 1 on success.
 */
int sendString(int sockfd, unsigned char *buffer);

/*
 * Accepts a socket FD and a ptr to a destination.
 * Receives from the socket until EOL byte sequence is detected.
 * Returns the size of the line read or 0 if not found.
 */
int recvLine(int sockfd, unsigned char *destBuffer);

/*
 * Dump dataBuffer to:
 * dump -> stdout
 * dump_to_file -> file 
 * hex_dump_only -> file
 */
void dump(const unsigned char* dataBuffer, const unsigned int length);
void dump_to_file(const unsigned char* dataBuffer, const unsigned int length, FILE* outputFilePtr);
void hex_dump_only(const unsigned char* databuffer, const unsigned int length, FILE* outputFilePtr);

void fatal(char* message, char* location, FILE* outputFilePtr);

// pointer functions
void free_all_pointers(struct allocated_pointers* head);
void add_new_pointer(struct allocated_pointers* head, struct allocated_pointers* tail, void* new_pointer);
