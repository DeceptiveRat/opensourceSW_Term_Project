#pragma once

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdbool.h>

#define DNS_COMPRESSION_PTR 0xC0

// ------------------------------------------------------ #structures -------------------------------------------------------------- //

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
	unsigned char* dns_domain_name;

	unsigned short dns_type;
#define DNS_RECORD_A 1
#define DNS_RECORD_NS 2
#define DNS_RECORD_CNAME 5
#define DNS_RECORD_MX 15
#define DNS_RECORD_PTR 12
#define DNS_RECORD_HINFO 13

	unsigned short dns_class;
#define DNS_CLASS_IN 1
};

// cast end of domain name
struct dns_response_section
{
	unsigned char* dns_domain_name;

	unsigned short dns_type;

	// UDP payload size of OPT records
	unsigned short dns_class;

	// Extended RCODE and flags for OPT record
	unsigned int dns_TTL;
	unsigned short dns_data_length;
	unsigned char* dns_resource_data;
};

struct dns_query
{
	struct dns_hdr dns_query_header;
	struct dns_query_section *dns_query_queries;
	struct dns_response_section *dns_query_additional;
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

// pcap handler functions
void analyze_caught_packet(unsigned char *user_args, const struct pcap_pkthdr *cap_header, const unsigned char *packet);

// decode various layers
struct ether_hdr decode_ethernet(const unsigned char *ethernet_header_start, FILE* outputFilePtr);
struct ip_hdr decode_ip(const unsigned char *ip_header_start, FILE* outputFilePtr);
struct tcp_hdr decode_tcp(const unsigned char *tcp_header_start, FILE* outputFilePtr, int *tcp_header_size);
struct udp_hdr decode_udp(const unsigned char *udp_header_start, FILE* outputFilePtr);

// get headers
bool get_ethernet_header(const unsigned char *ethernet_header_start, struct ether_hdr* ethernet_header);
bool get_ip_header(const unsigned char *ip_header_start, struct ip_hdr* ip_header);
bool get_tcp_header(const unsigned char *tcp_header_start, struct tcp_hdr* tcp_header, int *tcp_header_size);
bool get_udp_header(const unsigned char *udp_header_start, struct udp_hdr* udp_header);
bool get_dns_query(const unsigned char *udp_payload_start, struct dns_query* dns_query_pointer);
bool get_dns_response(const unsigned char *udp_payload_start, struct dns_response* dns_response_pointer);

/*
 * return domain name as string
 * change query offset so it points to the correct place
 * returns NULL if domain name format is wrong
 */
unsigned char* get_domain_name(const unsigned char* query_start_pointer, int *query_offset);

// checksum match functions
char udp_checksum_matches(const unsigned char *header_start);
char tcp_checksum_matches(const unsigned char *header_start);

// print functions

// ------------------------------------------------------- #variables -------------------------------------------------------------- //

