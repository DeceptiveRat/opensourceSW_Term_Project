/* 
 * This file is part of BPS.
 *
 * BPS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * BPS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with BPS.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "otherFunctions.h"

int sendString(int sockfd, unsigned char *buffer)
{
	int sentBytes, bytesToSend;
	bytesToSend = strlen((char*)buffer);

	while(bytesToSend > 0)
	{
		sentBytes = send(sockfd, buffer, bytesToSend, 0);

		// return 0 on error
		if(sentBytes == -1)
			return 0;

		bytesToSend -= sentBytes;
		buffer += sentBytes;
	}

	return 1;
}

int recvLine(int sockfd, unsigned char *destBuffer)
{
#define EOL "\r\n"
#define EOL_SIZE 2

	unsigned char *ptr;
	int eolMatched = 0;

	ptr = destBuffer;

	while(recv(sockfd, ptr, 1, 0) == 1)
	{
		if(*ptr == EOL[eolMatched])
		{
			eolMatched++;

			if(eolMatched == EOL_SIZE)
			{
				*(ptr - EOL_SIZE + 1) = '\0';
				return strlen((char*)destBuffer);
			}
		}

		else
			eolMatched = 0;

		ptr++;
	}

	// no end of line character found
	return 0;
}

void dump(const unsigned char* dataBuffer, const unsigned int length)
{
	unsigned int printLocation = 0;
	char byte;

	while(printLocation <= length)
	{
		for(int i = 0; i < 16; i++)
		{
			if(printLocation + i <= length)
				printf("%02x ", dataBuffer[printLocation + i]);

			else
				printf("   ");
		}

		printf(" | ");

		for(int i = 0; i < 16; i++)
		{
			if(printLocation + i <= length)
			{
				byte = dataBuffer[printLocation + i];

				if(byte > 31 && byte < 127)
					printf("%c ", byte);

				else
					printf(",");
			}

			else
			{
				printf("\n");
				break;
			}
		}

		printf("\n");
		printLocation += 16;
	}
}

void dump_to_file(const unsigned char* dataBuffer, const unsigned int length, FILE* outputFilePtr)
{
	unsigned int printLocation = 0;
	char byte;

	while(printLocation <= length)
	{
		for(int i = 0; i < 16; i++)
		{
			if(printLocation + i <= length)
				fprintf(outputFilePtr, "%02x ", dataBuffer[printLocation + i]);

			else
				fprintf(outputFilePtr, "   ");
		}

		fprintf(outputFilePtr, " | ");

		for(int i = 0; i < 16; i++)
		{
			if(printLocation + i <= length)
			{
				byte = dataBuffer[printLocation + i];

				if(byte > 31 && byte < 127)
					fprintf(outputFilePtr, "%c ", byte);

				else
					fprintf(outputFilePtr, ",");
			}

			else
			{
				fprintf(outputFilePtr, "\n");
				break;
			}
		}

		fprintf(outputFilePtr, "\n");
		printLocation += 16;
	}
}

void hex_dump_only(const unsigned char* databuffer, const unsigned int length, FILE* outputFilePtr)
{
	unsigned int printLocation = 0;

	while(printLocation <= length)
	{
		fprintf(outputFilePtr, "%02x ", databuffer[printLocation]);
		printLocation++;
	}

	fprintf(outputFilePtr, "\n");
}

void fatal(char *message, char *location, FILE* outputFilePtr)
{
	char error_message[ERROR_MESSAGE_SIZE];
	int lengthLeft = ERROR_MESSAGE_SIZE;

	strcpy(error_message, "[!!] Fatal Error ");
	lengthLeft -= 17;
	strncat(error_message, message, lengthLeft);
	lengthLeft -= strlen(message);
	strncat(error_message, "In function: ", lengthLeft);
	lengthLeft -= 13;
	strncat(error_message, location, lengthLeft);
	lengthLeft -= strlen(location);

	if(outputFilePtr != NULL)
		fprintf(outputFilePtr, "%s", error_message);

	strncat(error_message, "\nError", lengthLeft);
	perror(error_message);
	exit(-1);
}

void free_all_pointers(struct allocated_pointers* head)
{
	struct allocated_pointers* next = NULL;
	struct allocated_pointers* prev = NULL;
	next = head->next_pointer;
	prev = head;

	while(next != NULL)
	{
		free(prev);
		free(next->pointer);
		prev = next;
		next = next->next_pointer;
	}

	free(prev);
}

void add_new_pointer(struct allocated_pointers* head, struct allocated_pointers* tail, void* new_pointer)
{
	struct allocated_pointers* new_node = (struct allocated_pointers*)malloc(sizeof(struct allocated_pointers));

	if(new_node == NULL)
	{
		free_all_pointers(head);
		fatal("allocating memory for a new node", "add_new_pointer", NULL);
	}

	new_node->pointer = new_pointer;
	new_node->next_pointer = NULL;
	if(tail == NULL)
	{
		tail = head;
		while(tail->next_pointer != NULL)
			tail = tail->next_pointer;
	}
	tail->next_pointer = new_node;
}
