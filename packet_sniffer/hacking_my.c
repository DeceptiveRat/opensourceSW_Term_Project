#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include "hacking_my.h"

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
    char error_message[100];

    strcpy(error_message, "[!!] Fatal Error ");
    strncat(error_message, message, 83);
    perror(error_message);
    exit(-1);
}

void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet)
{
    FILE* outputFilePtr = (FILE*)user_args;
    int tcp_header_length, total_header_size, pkt_data_len;
    u_char *pkt_data;

    fprintf(outputFilePtr, "==== Got a %d byte packet ====\n", cap_header->len);

    char protocol = 0;
    protocol = ((struct ip_hdr*)(packet + ETHER_HDR_LEN))->ip_type;

    if(protocol == 17)
    {
        	if(udp_checksum_matches(packet, outputFilePtr) != 1)
        	{
        		fprintf(outputFilePtr, "checksum doesn't match\n");
        		fprintf(outputFilePtr, "UDP packet dropped.\n");
        		return;
        	}
    }

    else if(protocol == 6)
    {
        if(tcp_checksum_matches(packet, outputFilePtr) != 1)
        {
            fprintf(outputFilePtr, "checksum doesn't match\n");
            fprintf(outputFilePtr, "TCP packet dropped.\n");
            return;
        }
    }

    decode_ethernet(packet, outputFilePtr);
    decode_ip(packet + ETHER_HDR_LEN, outputFilePtr);

    if(protocol == 6)
    {
        tcp_header_length = decode_tcp(packet + ETHER_HDR_LEN + sizeof(struct ip_hdr), outputFilePtr);
        total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr) + tcp_header_length;
    }

    else if(protocol == 17)
    {
        decode_udp(packet + ETHER_HDR_LEN + sizeof(struct ip_hdr), outputFilePtr);
        total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr) + sizeof(struct udp_hdr);
    }

    else
    {
        fprintf(outputFilePtr, "unknown type\n");
    }

    pkt_data = (u_char *)packet + total_header_size;
    pkt_data_len = cap_header->len - total_header_size;

    if(pkt_data_len > 0)
    {
        fprintf(outputFilePtr, "\t\t\t%u bytes of packet data\n", pkt_data_len);
        dump_to_file(pkt_data, pkt_data_len, outputFilePtr);
    }

    else
        fprintf(outputFilePtr, "\t\t\tNo Packet Data\n");
}

void decode_ethernet(const u_char *header_start, FILE* outputFilePtr)
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
}

void decode_ip(const u_char *header_start, FILE* outputFilePtr)
{
    const struct ip_hdr *ip_header;
    char addressString[16];

    ip_header = (const struct ip_hdr*)header_start;
    fprintf(outputFilePtr, "\t((  Layer 3 ::: IP Header  ))\n");

    inet_ntop(AF_INET, (struct in_addr*) & (ip_header->ip_src_addr), addressString, 16);
    fprintf(outputFilePtr, "\t( Source: %s\t", addressString);

    inet_ntop(AF_INET, (struct in_addr*) & (ip_header->ip_dest_addr), addressString, 16);
    fprintf(outputFilePtr, "Dest: %s )\n", addressString);
    fprintf(outputFilePtr, "\t( Type: %u\t", (u_int) ip_header->ip_type);
    fprintf(outputFilePtr, "ID: %hu\tLength: %hu )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));
}

u_int decode_tcp(const u_char *header_start, FILE* outputFilePtr)
{
    u_int header_size;
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

    return header_size;
}

void decode_udp(const u_char* header_start, FILE* outputFilePtr)
{
    const struct udp_hdr *udp_header;

    udp_header = (const struct udp_hdr*)header_start;

    fprintf(outputFilePtr, "\t\t{{  Layer 4 :::: UDP Header  }}\n");
    fprintf(outputFilePtr, "\t\t{ Src Port: %hu\t", ntohs(udp_header->udp_src_port));
    fprintf(outputFilePtr, "Dest Port: %hu }\n", ntohs(udp_header->udp_dest_port));
    fprintf(outputFilePtr, "\t\t{ Length: %d\t", ntohs(udp_header->udp_length));
    fprintf(outputFilePtr, "Checksum: %d }\n", ntohs(udp_header->udp_checksum));
}

char udp_checksum_matches(const u_char* packet_header, FILE* outputFilePtr)
{
    struct ip_hdr* ip_header = (struct ip_hdr*)(packet_header + ETHER_HDR_LEN);
    struct udp_hdr* udp_header = (struct udp_hdr*)(packet_header + ETHER_HDR_LEN + sizeof(struct ip_hdr));
    const u_char* data = packet_header + ETHER_HDR_LEN + sizeof(struct ip_hdr) + sizeof(struct udp_hdr);

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

char tcp_checksum_matches(const u_char* packet_header, FILE* outputFilePtr)
{
    struct ip_hdr* ip_header = (struct ip_hdr*)(packet_header + ETHER_HDR_LEN);
    struct tcp_hdr* tcp_header = (struct tcp_hdr*)(packet_header + ETHER_HDR_LEN + sizeof(struct ip_hdr));
    const u_char* data = packet_header + ETHER_HDR_LEN + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr);

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
