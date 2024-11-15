#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include "hacking_my.h"

const char ws_dns_query[] = "705dcc5120382cf05d5befed08004500004d1530000040112e82c0a80017d2dca352ba8c0035003937393f0201000001000000000001086163636f756e747307796f757475626503636f6d000041000100002905c0000000000000";
const char ws_dns_response[] = "2cf05d5befed705dcc51203808004500009bffeb4000f9114a77d2dca352c0a800170035ba8c008774f73f0281800001000100010001086163636f756e747307796f757475626503636f6d0000410001c00c000500010000011e00100477777733016c06676f6f676c65c01dc037000600010000003c0026036e7331c03909646e732d61646d696ec039298315c80000038400000384000007080000003c0000291000000000000000";

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
        for(int i = 0; i < 15; i++)
        {
            if(printLocation + i <= length)
                printf("%02x ", dataBuffer[printLocation + i]);

            else
                printf("   ");
        }

        printf(" | ");

        for(int i = 0; i < 15; i++)
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
        printLocation += 15;
    }
}

void dump_to_file(const unsigned char* dataBuffer, const unsigned int length, FILE* outputFilePtr)
{
    unsigned int printLocation = 0;
    char byte;

    while(printLocation <= length)
    {
        for(int i = 0; i < 15; i++)
        {
            if(printLocation + i <= length)
                fprintf(outputFilePtr, "%02x ", dataBuffer[printLocation + i]);

            else
                fprintf(outputFilePtr, "   ");
        }

        fprintf(outputFilePtr, " | ");

        for(int i = 0; i < 15; i++)
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
        printLocation += 15;
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

void fatal(char *message)
{
    char error_message[ERROR_MESSAGE_SIZE];

    strcpy(error_message, "[!!] Fatal Error ");
    strncat(error_message, message, ERROR_MESSAGE_SIZE - 17);
    perror(error_message);
    exit(-1);
}

void print_caught_packet(unsigned char *user_args, const struct pcap_pkthdr *cap_header, const unsigned char *packet)
{
    FILE* outputFilePtr = (FILE*)user_args;
    int tcp_header_length, total_header_size, pkt_data_len;
    unsigned char *pkt_data;

    fprintf(outputFilePtr, "==== Got a %d byte packet ====\n", cap_header->len);

    char protocol = 0;
    protocol = ((struct ip_hdr*)(packet + ETHER_HDR_LEN))->ip_type;

    if(protocol == IP_TYPE_UDP)
    {
        if(udp_checksum_matches(packet, outputFilePtr) != 1)
        {
            fprintf(outputFilePtr, "checksum doesn't match\n");
            fprintf(outputFilePtr, "UDP packet dropped.\n");
            return;
        }
    }

    else if(protocol == IP_TYPE_TCP)
    {
        if(tcp_checksum_matches(packet, outputFilePtr) != 1)
        {
            fprintf(outputFilePtr, "checksum doesn't match\n");
            fprintf(outputFilePtr, "TCP packet dropped.\n");
            return;
        }
    }

    // --------------------------------------- initialize allocated pointer list ------------------------------------
    struct allocated_pointers* head = NULL;
    struct allocated_pointers* tail = NULL;
    head = (struct allocated_pointers*)malloc(sizeof(struct allocated_pointers));

    if(head == NULL)
    {
        printf("Error allocating memory: head\n");
		return;
    }

    head->pointer = NULL;
    head->next_pointer = NULL;
    tail = head;
    // ---------------------------------------------------------------------------------------------------------------

    struct ether_hdr* ethernet_header = NULL;
    ethernet_header = (struct ether_hdr*)malloc(ETHER_HDR_LEN);

    if(ethernet_header == NULL)
    {
        printf("Error allocating memory: ethernet_header\n");
        free_all_pointers(head, outputFilePtr);
		exit(-1);
    }

    add_new_pointer(head, tail, (void*)ethernet_header, outputFilePtr);
    *ethernet_header = decode_ethernet(packet, outputFilePtr);
    total_header_size = ETHER_HDR_LEN;

    struct ip_hdr* ip_header = NULL;
    ip_header = (struct ip_hdr*)malloc(IP_HDR_LEN);

    if(ip_header == NULL)
    {
        printf("Error allocating memory: ip_header\n");
        free_all_pointers(head, outputFilePtr);
		exit(-1);
    }

    add_new_pointer(head, tail, (void*)ip_header, outputFilePtr);
    *ip_header = decode_ip(packet + total_header_size, outputFilePtr);
    total_header_size += IP_HDR_LEN;

    if(ip_header->ip_type == IP_TYPE_TCP)
    {
        struct tcp_hdr* tcp_header = NULL;
        tcp_header = (struct tcp_hdr*)malloc(TCP_HDR_LEN);

        if(tcp_header == NULL)
        {
            printf("Error allocating memory: tcp_header\n");
			free_all_pointers(head, outputFilePtr);
			exit(-1);
        }

        add_new_pointer(head, tail, (void*)tcp_header, outputFilePtr);
        *tcp_header = decode_tcp(packet + total_header_size, outputFilePtr, &tcp_header_length);
        total_header_size += tcp_header_length;
    }

    else if(ip_header->ip_type == IP_TYPE_UDP)
    {
        struct udp_hdr* udp_header = NULL;
        udp_header = (struct udp_hdr*)malloc(UDP_HDR_LEN);

        if(udp_header == NULL)
        {
            printf("Error allocating memory: udp_header\n");
			free_all_pointers(head, outputFilePtr);
			exit(-1);
        }

        add_new_pointer(head, tail, (void*)udp_header, outputFilePtr);
        *udp_header = decode_udp(packet + total_header_size, outputFilePtr);
        total_header_size += UDP_HDR_LEN;
    }

    else
    {
        fprintf(outputFilePtr, "unknown type\n");
    }

    pkt_data = (unsigned char *)packet + total_header_size;
    pkt_data_len = cap_header->len - total_header_size;

    if(pkt_data_len > 0)
    {
        fprintf(outputFilePtr, "\t\t\t%u bytes of packet data\n", pkt_data_len);
        dump_to_file(pkt_data, pkt_data_len, outputFilePtr);
    }

    else
        fprintf(outputFilePtr, "\t\t\tNo Packet Data\n");

    free_all_pointers(head, NULL);
    head = NULL;
    tail = NULL;
}

void analyze_caught_packet(unsigned char *user_args, const struct pcap_pkthdr *cap_header, const unsigned char *packet)
{
    FILE* outputFilePtr = (FILE*)user_args;
    int tcp_header_length, total_header_size, pkt_data_len;
    unsigned char *pkt_data;

    fprintf(outputFilePtr, "==== Got a %d byte packet ====\n", cap_header->len);

    // --------------------------------------- initialize allocated pointer list ------------------------------------
    struct allocated_pointers* head = NULL;
    struct allocated_pointers* tail = NULL;
    head = (struct allocated_pointers*)malloc(sizeof(struct allocated_pointers));

    if(head == NULL)
    {
        printf("Error allocating memory: head\n");
		return;
    }

    head->pointer = NULL;
    head->next_pointer = NULL;
    tail = head;
    // ---------------------------------------------------------------------------------------------------------------

    struct ether_hdr* ethernet_header = NULL;
    ethernet_header = (struct ether_hdr*)malloc(ETHER_HDR_LEN);

    if(ethernet_header == NULL)
    {
        printf("Error allocating memory: ethernet_header\n");
		free_all_pointers(head, outputFilePtr);
		exit(-1);
    }

    add_new_pointer(head, tail, (void*)ethernet_header, outputFilePtr);
	// verify if it is ethernet later
    get_ethernet_header(packet, ethernet_header);
    total_header_size = ETHER_HDR_LEN;

    struct ip_hdr* ip_header = NULL;
    ip_header = (struct ip_hdr*)malloc(IP_HDR_LEN);

    if(ip_header == NULL)
    {
        printf("Error allocating memory: ip_header\n");
		free_all_pointers(head, outputFilePtr);
		exit(-1);
    }

	add_new_pointer(head, tail, (void*)ip_header, outputFilePtr);
	// verify if it is IP later
    get_ip_header(packet + total_header_size, ip_header);
    total_header_size += IP_HDR_LEN;

    if(ip_header->ip_type == IP_TYPE_TCP)
    {
        if(tcp_checksum_matches(packet, outputFilePtr) != 1)
        {
            fprintf(outputFilePtr, "checksum doesn't match\n");
            fprintf(outputFilePtr, "TCP packet dropped.\n");
			free_all_pointers(head, outputFilePtr);
			exit(-1);
        }

        struct tcp_hdr* tcp_header = NULL;
        tcp_header = (struct tcp_hdr*)malloc(TCP_HDR_LEN);

        if(tcp_header == NULL)
        {
            printf("Error allocating memory: tcp_header\n");
			free_all_pointers(head, outputFilePtr);
			exit(-1);
        }

        add_new_pointer(head, tail, (void*)tcp_header, outputFilePtr);
		// verify if it is TCP later
		get_tcp_header(packet + total_header_size, tcp_header, &tcp_header_length);
        total_header_size += tcp_header_length;
    }

    else if(ip_header->ip_type == IP_TYPE_UDP)
    {
        if(udp_checksum_matches(packet, outputFilePtr) != 1)
        {
            fprintf(outputFilePtr, "checksum doesn't match\n");
            fprintf(outputFilePtr, "UDP packet dropped.\n");
			free_all_pointers(head, outputFilePtr);
			exit(-1);
        }

        struct udp_hdr* udp_header = NULL;
        udp_header = (struct udp_hdr*)malloc(UDP_HDR_LEN);

        if(udp_header == NULL)
        {
            printf("Error allocating memory: udp_header\n");
			free_all_pointers(head, outputFilePtr);
			exit(-1);
        }

        add_new_pointer(head, tail, (void*)udp_header, outputFilePtr);
		// verify if it is UDP later
		get_udp_header(packet + total_header_size, udp_header);
        total_header_size += UDP_HDR_LEN;
    }

    else
    {
        fprintf(outputFilePtr, "unknown type\n");
    }

    pkt_data = (unsigned char *)packet + total_header_size;
    pkt_data_len = cap_header->len - total_header_size;

    // check if it is a DNS packet

    free_all_pointers(head, NULL);
    head = NULL;
    tail = NULL;
}

struct ether_hdr decode_ethernet(const unsigned char *header_start, FILE* outputFilePtr)
{
    int i;
    const struct ether_hdr *ethernet_header;

    ethernet_header = (const struct ether_hdr *)header_start;
    fprintf(outputFilePtr, "[[  Layer 2 :: Ethernet Header  ]]\n");
    fprintf(outputFilePtr, "[ Source: %02x", ethernet_header->ether_src_addr[0]);

    for(i = 1; i < ETHER_ADDR_LEN; i++)
        fprintf(outputFilePtr, ":%02x", ethernet_header->ether_src_addr[i]);

    fprintf(outputFilePtr, "\tDest: %02x", ethernet_header->ether_dest_addr[0]);

    for(i = 1; i < ETHER_ADDR_LEN; i++)
        fprintf(outputFilePtr, ":%02x", ethernet_header->ether_dest_addr[i]);

    fprintf(outputFilePtr, "\tType: %hu ]\n", ethernet_header->ether_type);

    return *ethernet_header;
}

struct ip_hdr decode_ip(const unsigned char *header_start, FILE* outputFilePtr)
{
    const struct ip_hdr *ip_header;
    char addressString[16];

    ip_header = (const struct ip_hdr*)header_start;
    fprintf(outputFilePtr, "\t((  Layer 3 ::: IP Header  ))\n");

    inet_ntop(AF_INET, (struct in_addr*) & (ip_header->ip_src_addr), addressString, 16);
    fprintf(outputFilePtr, "\t( Source: %s\t", addressString);

    inet_ntop(AF_INET, (struct in_addr*) & (ip_header->ip_dest_addr), addressString, 16);
    fprintf(outputFilePtr, "Dest: %s )\n", addressString);
    fprintf(outputFilePtr, "\t( Type: %u\t", (unsigned int) ip_header->ip_type);
    fprintf(outputFilePtr, "ID: %hu\tLength: %hu )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));

    return *ip_header;
}

struct tcp_hdr decode_tcp(const unsigned char *header_start, FILE* outputFilePtr, int *tcp_header_size)
{
    unsigned int header_size;
    const struct tcp_hdr *tcp_header;

    tcp_header = (const struct tcp_hdr *)header_start;
    header_size = 4 * tcp_header->tcp_offset;

    fprintf(outputFilePtr, "\t\t{{  Layer 4 :::: TCP Header  }}\n");
    fprintf(outputFilePtr, "\t\t{ Src Port: %hu\t", ntohs(tcp_header->tcp_src_port));
    fprintf(outputFilePtr, "Dest Port: %hu }\n", ntohs(tcp_header->tcp_dest_port));
    fprintf(outputFilePtr, "\t\t{ Seq #: %u\t", ntohl(tcp_header->tcp_seq));
    fprintf(outputFilePtr, "Ack #: %u }\n", ntohl(tcp_header->tcp_ack));
    fprintf(outputFilePtr, "\t\t{ Header Size: %u\tFlags: ", header_size);

    if(tcp_header->tcp_flags & TCP_FIN)
        fprintf(outputFilePtr, "FIN ");

    if(tcp_header->tcp_flags & TCP_SYN)
        fprintf(outputFilePtr, "SYN ");

    if(tcp_header->tcp_flags & TCP_RST)
        fprintf(outputFilePtr, "RST ");

    if(tcp_header->tcp_flags & TCP_PUSH)
        fprintf(outputFilePtr, "PUSH ");

    if(tcp_header->tcp_flags & TCP_ACK)
        fprintf(outputFilePtr, "ACK ");

    if(tcp_header->tcp_flags & TCP_URG)
        fprintf(outputFilePtr, "URG ");

    fprintf(outputFilePtr, " }\n");

    *tcp_header_size = header_size;
    return *tcp_header;
}

struct udp_hdr decode_udp(const unsigned char* header_start, FILE* outputFilePtr)
{
    const struct udp_hdr *udp_header;

    udp_header = (const struct udp_hdr*)header_start;

    fprintf(outputFilePtr, "\t\t{{  Layer 4 :::: UDP Header  }}\n");
    fprintf(outputFilePtr, "\t\t{ Src Port: %hu\t", ntohs(udp_header->udp_src_port));
    fprintf(outputFilePtr, "Dest Port: %hu }\n", ntohs(udp_header->udp_dest_port));
    fprintf(outputFilePtr, "\t\t{ Length: %d\t", ntohs(udp_header->udp_length));
    fprintf(outputFilePtr, "Checksum: %d }\n", ntohs(udp_header->udp_checksum));

    return *udp_header;
}

char udp_checksum_matches(const unsigned char* packet_header, FILE* outputFilePtr)
{
    struct ip_hdr* ip_header = (struct ip_hdr*)(packet_header + ETHER_HDR_LEN);
    struct udp_hdr* udp_header = (struct udp_hdr*)(packet_header + ETHER_HDR_LEN + sizeof(struct ip_hdr));
    const unsigned char* data = packet_header + ETHER_HDR_LEN + sizeof(struct ip_hdr) + sizeof(struct udp_hdr);

    unsigned int sum = 0;
    sum += (ntohl(ip_header->ip_src_addr) >> 16) & 0xFFFF; // source addr
    sum += ntohl(ip_header->ip_src_addr) & 0xFFFF;
    sum += (ntohl(ip_header->ip_dest_addr) >> 16) & 0xFFFF; // dest addr
    sum += ntohl(ip_header->ip_dest_addr) & 0xFFFF;
    sum += 0x11; // protocol
    sum += ntohs(udp_header->udp_src_port);
    sum += ntohs(udp_header->udp_dest_port);
    sum += ntohs(udp_header->udp_length);
    sum += ntohs(udp_header->udp_length);

    int data_length_bytes = ntohs(udp_header->udp_length) - sizeof(struct udp_hdr);

    for(int i = 0; i < data_length_bytes; i += 2)
    {
        unsigned short word = 0;
        word = data[i] << 8;

        if(i + 1 < data_length_bytes)
            word |= data[i + 1];

        sum += word;
    }

    while(sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (((~sum) & 0xFFFF) == ntohs(udp_header->udp_checksum)) ? 1 : 0;
}

char tcp_checksum_matches(const unsigned char* packet_header, FILE* outputFilePtr)
{
    struct ip_hdr* ip_header = (struct ip_hdr*)(packet_header + ETHER_HDR_LEN);
    struct tcp_hdr* tcp_header = (struct tcp_hdr*)(packet_header + ETHER_HDR_LEN + sizeof(struct ip_hdr));
    const unsigned char* data = packet_header + ETHER_HDR_LEN + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr);

    unsigned int sum = 0;
    sum += (ntohl(ip_header->ip_src_addr) >> 16) & 0xFFFF; // source addr
    sum += ntohl(ip_header->ip_src_addr) & 0xFFFF;
    sum += (ntohl(ip_header->ip_dest_addr) >> 16) & 0xFFFF; // dest addr
    sum += ntohl(ip_header->ip_dest_addr) & 0xFFFF;
    sum += 6; // protocol
    sum += ntohs(ip_header->ip_len) - sizeof(struct ip_hdr);

    sum += ntohs(tcp_header->tcp_src_port);
    sum += ntohs(tcp_header->tcp_dest_port);
    sum += (ntohl(tcp_header->tcp_seq) >> 16) & 0xFFFF;
    sum += ntohl(tcp_header->tcp_seq) & 0xFFFF;
    sum += (ntohl(tcp_header->tcp_ack) >> 16) & 0xFFFF; // dest port
    sum += ntohl(tcp_header->tcp_ack) & 0xFFFF;
    sum += ((short)(tcp_header->tcp_offset) << 12) | tcp_header->tcp_flags;
    sum += ntohs(tcp_header->tcp_window);
    sum += ntohs(tcp_header->tcp_urgent);

    // data + options
    int data_length_bytes = ntohs(ip_header->ip_len) - sizeof(struct ip_hdr) - sizeof(struct tcp_hdr);

    for(int i = 0; i < data_length_bytes; i += 2)
    {
        unsigned short word = 0;
        word = data[i] << 8;

        if(i + 1 < data_length_bytes)
            word |= data[i + 1];

        sum += word;
    }

    while(sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (((~sum) & 0xFFFF) == ntohs(tcp_header->tcp_checksum)) ? 1 : 0;
}

void free_all_pointers(struct allocated_pointers* head, FILE* outputFilePtr)
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
	if(outputFilePtr != NULL)
		fclose(outputFilePtr);
}
void add_new_pointer(struct allocated_pointers* head, struct allocated_pointers* tail, void* new_pointer, FILE* outputFilePtr)
{
    struct allocated_pointers* new_node = (struct allocated_pointers*)malloc(sizeof(struct allocated_pointers));

    if(new_node == NULL)
    {
        printf("Error allocating memory: new_node\n");
        free_all_pointers(head, outputFilePtr);
        exit(-1);
    }

    new_node->pointer = new_pointer;
    new_node->next_pointer = NULL;
    tail->next_pointer = new_node;
    tail = new_node;
};


char get_ethernet_header(const unsigned char *header_start, struct ether_hdr* ethernet_header)
{
    // ***IMPORTANT: change code to verify ethernet later***
    const struct ether_hdr *ethernet_header_pointer;
    ethernet_header_pointer = (const struct ether_hdr *)header_start;

    *ethernet_header = *ethernet_header_pointer;
    return 1;
}

char get_ip_header(const unsigned char *header_start, struct ip_hdr* ip_header)
{
    // ***IMPORTANT: change code to verify IP later***
    const struct ip_hdr *ip_header_pointer;
    ip_header_pointer = (const struct ip_hdr*)header_start;

    *ip_header = *ip_header_pointer;
    return 1;
}

char get_tcp_header(const unsigned char *header_start, struct tcp_hdr* tcp_header, int *tcp_header_size)
{
    unsigned int header_size;
    const struct tcp_hdr *tcp_header_pointer;
    tcp_header_pointer = (const struct tcp_hdr *)header_start;
    header_size = 4 * tcp_header->tcp_offset;

    *tcp_header = *tcp_header_pointer;
    *tcp_header_size = header_size;
    return 1;
}

char get_udp_header(const unsigned char *header_start, struct udp_hdr* udp_header)
{
    const struct udp_hdr *udp_header_pointer;
    udp_header_pointer = (const struct udp_hdr*)header_start;

    *udp_header = *udp_header_pointer;
    return 1;
}

char get_dns_query(const unsigned char *header_start, struct dns_query* dns_query_pointer, struct allocated_pointers* head, struct allocated_pointers* tail, FILE* outputFilePtr)
{
	struct dns_query dns_query_struct;
	struct dns_hdr dns_header_struct;
	struct dns_query_section dns_query_section_struct;
	struct dns_response_section dns_query_additional_struct;

	dns_header_struct = *(struct dns_hdr*)header_start;
	if((dns_header_struct.dns_flags & DNS_QR) != 0)
		return -1;
	if((dns_header_struct.dns_flags & DNS_ZERO) != 0)
		return -1;
	if(dns_header_struct.dns_answer_count != 0)
		return -1;
	if(dns_header_struct.dns_authority_count != 0)
		return -1;
	
	const unsigned char* packet_pointer = header_start + DNS_HDR_LEN;
	unsigned char byte;
	int offset = 0;
	int domain_name_length = 0;

	byte = *packet_pointer;
	while(byte != 0x00)
	{
		offset++;
		byte = packet_pointer[offset];
		domain_name_length++;
	}
	
	dns_query_section_struct.dns_domain_name = NULL;
	dns_query_section_struct.dns_domain_name = (unsigned char*)malloc(sizeof(domain_name_length));
	if(dns_query_section_struct.dns_domain_name == NULL)
	{
		printf("Error while allocating memory for: dns_domain_name\n");
		free_all_pointers(head, outputFilePtr);
	}
	add_new_pointer(head, tail, dns_query_section_struct.dns_domain_name, outputFilePtr);

	// save the domain name as string
	int bytes_left_in_label = 0;
	for(int i = 0;i<domain_name_length;i++)
	{
		if(bytes_left_in_label == 0)
			bytes_left_in_label = packet_pointer[i];
		else
		{
		}
	}
}

char get_dns_response(const unsigned char *header_start, struct dns_response* dns_response_pointer, struct allocated_pointers* head, struct allocated_pointers* tail, FILE* outputFilePtr)
{
}
