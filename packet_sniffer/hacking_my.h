#pragma once

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>

#define ERROR_MESSAGE_SIZE 100

// ------------------------------------------------------ #structures -------------------------------------------------------------- //

// linked list of allocated pointers for easy deallocation
struct allocated_pointers
{
	void* pointer;
	struct allocated_pointers* next_pointer;
};

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14
struct ether_hdr
{
    unsigned char ether_dest_addr[ETHER_ADDR_LEN];
    unsigned char ether_src_addr[ETHER_ADDR_LEN];
    unsigned short ether_type;
};

#define IP_HDR_LEN 20
struct ip_hdr
{
    unsigned char ip_version_and_header_length;
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_frag_offset;
    unsigned char ip_ttl;
    unsigned char ip_type;
    unsigned short ip_checksum;
    unsigned int ip_src_addr;
    unsigned int ip_dest_addr;
};
#define IP_TYPE_TCP 6
#define IP_TYPE_UDP 17

#define TCP_HDR_LEN 20
struct tcp_hdr
{
    unsigned short tcp_src_port;
    unsigned short tcp_dest_port;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    // assuming little endian
    unsigned char tcp_reserved_4: 4;
    unsigned char tcp_offset: 4;
    unsigned char tcp_flags;	// the first 2 bits are reserved
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
    unsigned short tcp_window;
    unsigned short tcp_checksum;
    unsigned short tcp_urgent;
};

struct tcp_hdr_options
{
	// work in progress
};

#define UDP_HDR_LEN 8
struct udp_hdr
{
    unsigned short udp_src_port;
    unsigned short udp_dest_port;
    unsigned short udp_length;
    unsigned short udp_checksum;
};

#define DNS_HDR_LEN 12
struct dns_hdr
{
	unsigned short dns_id;
	unsigned short dns_flags;
#define DNS_QR 0x8000
#define DNS_OPCODE 0x7800
#define DNS_AA 0x400
#define DNS_TC 0x200
#define DNS_RD 0x100
#define DNS_RA 0x80
#define DNS_ZERO 0x70
#define DNS_RCODE 0xF 

	unsigned short dns_question_count;
	unsigned short dns_answer_count;
	unsigned short dns_authority_count;
	unsigned short dns_additional_count;
};

// cast end of domain name
struct dns_query_section
{
	unsigned short dns_type;
#define DNS_RECORD_A 1
#define DNS_RECORD_NS 2
#define DNS_RECORD_CNAME 5
#define DNS_RECORD_MX 15
#define DNS_RECORD_PTR 12
#define DNS_RECORD_HINFO 13

	unsigned short dns_class;
#define DNS_CLASS_IN 1
	unsigned char* dns_domain_name;
};

// cast end of domain name
struct dns_response_section
{
	unsigned short dns_type;
#define DNS_RECORD_A 1
#define DNS_RECORD_NS 2
#define DNS_RECORD_CNAME 5
#define DNS_RECORD_MX 15
#define DNS_RECORD_PTR 12
#define DNS_RECORD_HINFO 13

	unsigned short dns_class;
#define DNS_CLASS_IN 1

	unsigned int dns_TTL;
	unsigned short dns_data_length;
	unsigned char* dns_domain_name;
	unsigned char* dns_resource_data;
};

struct dns_query
{
	struct dns_hdr dns_query_header;
	struct dns_query_section dns_query_queries;
	struct dns_response_section dns_query_additional;
};

struct dns_response 
{
	struct dns_hdr dns_response_header;
	struct dns_query_section dns_response_queries;
	struct dns_response_section dns_response_answer;
	struct dns_response_section dns_response_authoritative;
	struct dns_response_section dns_response_additional;
};

// ------------------------------------------------------- #functions -------------------------------------------------------------- //
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

void fatal(char* message);

// pcap handler functions
void print_caught_packet(unsigned char *user_args, const struct pcap_pkthdr *cap_header, const unsigned char *packet);
void analyze_caught_packet(unsigned char *user_args, const struct pcap_pkthdr *cap_header, const unsigned char *packet);

// decode various layers
struct ether_hdr decode_ethernet(const unsigned char *header_startheader_start, FILE* outputFilePtr);
struct ip_hdr decode_ip(const unsigned char *header_start, FILE* outputFilePtr);
struct tcp_hdr decode_tcp(const unsigned char *header_start, FILE* outputFilePtr, int *tcp_header_size);
struct udp_hdr decode_udp(const unsigned char *header_start, FILE* outputFilePtr);

/*
 * get headers
 * returns -1 if wrong structure
 * returns 1 and sets pointer passed to that structure
 * if pointer is NULL, just return 1
 * returns -2 if there was an error, e.g. while allocating memory
 */
char get_ethernet_header(const unsigned char *header_start, struct ether_hdr* ethernet_header);
char get_ip_header(const unsigned char *header_start, struct ip_hdr* ip_header);
char get_tcp_header(const unsigned char *header_start, struct tcp_hdr* tcp_header, int *tcp_header_size);
char get_udp_header(const unsigned char *header_start, struct udp_hdr* udp_header);
// pass start of data as header_start
char get_dns_query(const unsigned char *header_start, struct dns_query* dns_query_pointer, struct allocated_pointers* head, struct allocated_pointers* tail, FILE* outputFilePtr);
char get_dns_response(const unsigned char *header_start, struct dns_response* dns_response_pointer, struct allocated_pointers* head, struct allocated_pointers* tail, FILE* outputFilePtr);

// checksum match functions
char udp_checksum_matches(const unsigned char *header_start, FILE* outputFilePtr);
char tcp_checksum_matches(const unsigned char *header_start, FILE* outputFilePtr);

// pointer functions
void free_all_pointers(struct allocated_pointers* head, FILE* outputFilePtr);
void add_new_pointer(struct allocated_pointers* head, struct allocated_pointers* tail, void* new_pointer, FILE* outputFilePtr);

// ------------------------------------------------------- #variables -------------------------------------------------------------- //

