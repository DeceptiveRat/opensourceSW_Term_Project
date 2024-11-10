#pragma once

#include <stdio.h>
#include <sys/socket.h>

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

void dump(const unsigned char* dataBuffer, const unsigned int length);
void dump_to_file(const unsigned char* dataBuffer, const unsigned int length, FILE* outputFilePtr);
void hex_dump_only(const unsigned char* databuffer, const unsigned int length, FILE* outputFilePtr);

void fatal(char* message);

/*
 * Ethernet frame header structure
 */

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

struct ether_hdr
{
    unsigned char ether_dest_addr[ETHER_ADDR_LEN];
    unsigned char ether_src_addr[ETHER_ADDR_LEN];
    unsigned short ether_type;
};

/*
 * IP header structure
 * Originally in netinet/ip.h
 */

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

/*
 * TCP header structure
 * Originally in netinet/tcp.h
 */

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

struct udp_hdr
{
    unsigned short udp_src_port;
    unsigned short udp_dest_port;
    unsigned short udp_length;
    unsigned short udp_checksum;
};

void caught_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

void decode_ethernet(const u_char *, FILE* outputFilePtr);
void decode_ip(const u_char *, FILE* outputFilePtr);
u_int decode_tcp(const u_char *, FILE* outputFilePtr);
void decode_udp(const u_char*, FILE* outputFilePtr);

char udp_checksum_matches(const u_char*, FILE* outputFilePtr);
char tcp_checksum_matches(const u_char*, FILE* outputFilePtr);
