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
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>

#include "packetFunctions.h"
#include "otherFunctions.h"

void analyze_caught_packet(unsigned char *user_args, const struct pcap_pkthdr *cap_header, const unsigned char *packet)
{
	FILE* outputFilePtr = (FILE*)user_args;
	int tcp_header_length, total_header_size, pkt_data_len;
	unsigned char *pkt_data;
	bool isUDP;

	fprintf(outputFilePtr, "==== Got a %d byte packet ====\n", cap_header->len);

	struct ether_hdr* ethernet_header = NULL;
	ethernet_header = (struct ether_hdr*)malloc(ETHER_HDR_LEN);

	if(ethernet_header == NULL)
		fatal("allocating memory: ethernet_header", "analyze_caught_packet", outputFilePtr);

	// verify if it is ethernet later
	get_ethernet_header(packet, ethernet_header);
	total_header_size = ETHER_HDR_LEN;

	struct ip_hdr* ip_header = NULL;
	ip_header = (struct ip_hdr*)malloc(IP_HDR_LEN);

	if(ip_header == NULL)
		fatal("allocating memory: ip_header", "analyze_caught_packet", outputFilePtr);

	// verify if it is IP later
	get_ip_header(packet + total_header_size, ip_header);
	total_header_size += IP_HDR_LEN;

	struct tcp_hdr* tcp_header = NULL;
	struct udp_hdr* udp_header = NULL;

	if(ip_header->ip_type == IP_TYPE_TCP)
	{
		isUDP = false;
		if(tcp_checksum_matches(packet) != 1)
		{
			fprintf(outputFilePtr, "checksum doesn't match\n");
			fprintf(outputFilePtr, "TCP packet dropped.\n");
			return;
		}

		tcp_header = (struct tcp_hdr*)malloc(TCP_HDR_LEN);

		if(tcp_header == NULL)
			fatal("allocating memory: tcp_header", "analyze_caught_packet", outputFilePtr);

		// verify if it is TCP later
		get_tcp_header(packet + total_header_size, tcp_header, &tcp_header_length);
		total_header_size += tcp_header_length;
		isUDP = false;
		printf("TCP packet dropped\n");
		fprintf(outputFilePtr, "TCP packet dropped\n");
		return;
	}

	else if(ip_header->ip_type == IP_TYPE_UDP)
	{
		isUDP = true;
		if(udp_checksum_matches(packet) != 1)
		{
			fprintf(outputFilePtr, "checksum doesn't match\n");
			fprintf(outputFilePtr, "UDP packet dropped.\n");
			return;
		}

		udp_header = (struct udp_hdr*)malloc(UDP_HDR_LEN);

		if(udp_header == NULL)
			fatal("allocating memory: udp_header", "analyze_caught_packet", outputFilePtr);

		// verify if it is UDP later
		get_udp_header(packet + total_header_size, udp_header);
		total_header_size += UDP_HDR_LEN;
	}

	else
		fprintf(outputFilePtr, "unknown type\n");

	pkt_data = (unsigned char *)(packet + total_header_size);
	pkt_data_len = cap_header->len - total_header_size;
	struct dns_query* query_ptr = NULL;
	if(isUDP)
		get_dns_query(pkt_data, &query_ptr);
	else
		return;

	fprintf(outputFilePtr, "packet data length: %d\n", pkt_data_len);
	fprintf(outputFilePtr, "dns id: %d\n", query_ptr->dns_query_header.dns_id);
	fprintf(outputFilePtr, "flags: %d\n", query_ptr->dns_query_header.dns_flags);
	fprintf(outputFilePtr, "question count: %d\n", query_ptr->dns_query_header.dns_question_count);
	fprintf(outputFilePtr, "answer count: %d\n", query_ptr->dns_query_header.dns_answer_count);
	fprintf(outputFilePtr, "authority count: %d\n", query_ptr->dns_query_header.dns_authority_count);
	fprintf(outputFilePtr, "additional count: %d\n", query_ptr->dns_query_header.dns_additional_count);
	fprintf(outputFilePtr, "query 1 domain name: %s\n", query_ptr->dns_query_queries->dns_domain_name);
	fprintf(outputFilePtr, "query 1 type: %d\n", query_ptr->dns_query_queries->dns_type);
	fprintf(outputFilePtr, "query 1 class: %d\n", query_ptr->dns_query_queries->dns_class);
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

char udp_checksum_matches(const unsigned char* packet_header)
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

char tcp_checksum_matches(const unsigned char* packet_header)
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

bool get_ethernet_header(const unsigned char *header_start, struct ether_hdr* ethernet_header)
{
	// ***IMPORTANT: change code to verify ethernet later***
	const struct ether_hdr *ethernet_header_pointer;
	ethernet_header_pointer = (const struct ether_hdr *)header_start;

	*ethernet_header = *ethernet_header_pointer;
	return true;
}

bool get_ip_header(const unsigned char *header_start, struct ip_hdr* ip_header)
{
	// ***IMPORTANT: change code to verify IP later***
	const struct ip_hdr *ip_header_pointer;
	ip_header_pointer = (const struct ip_hdr*)header_start;

	*ip_header = *ip_header_pointer;
	return true;
}

bool get_tcp_header(const unsigned char *header_start, struct tcp_hdr* tcp_header, int *tcp_header_size)
{
	unsigned int header_size;
	const struct tcp_hdr *tcp_header_pointer;
	tcp_header_pointer = (const struct tcp_hdr *)header_start;
	header_size = 4 * tcp_header->tcp_offset;

	*tcp_header = *tcp_header_pointer;
	*tcp_header_size = header_size;
	return true;
}

bool get_udp_header(const unsigned char *header_start, struct udp_hdr* udp_header)
{
	const struct udp_hdr *udp_header_pointer;
	udp_header_pointer = (const struct udp_hdr*)header_start;

	*udp_header = *udp_header_pointer;
	return true;
}

bool get_dns_query(const unsigned char *header_start, struct dns_query** dns_query_pointer)
{
	struct allocated_pointers* head = NULL;
	head = (struct allocated_pointers*)malloc(sizeof(struct allocated_pointers));
	if(head == NULL)
		fatal("allocating memory for clean up head", "get_dns_query", NULL);
	
	*dns_query_pointer = (struct dns_query*)malloc(sizeof(struct dns_query));
	if(dns_query_pointer == NULL)
		return false;
	else
		add_new_pointer(head, NULL, dns_query_pointer);
	(*dns_query_pointer)->dns_query_queries = NULL;
	(*dns_query_pointer)->dns_query_additional = NULL;

	// add header 
	struct dns_hdr query_header;

	query_header = *(struct dns_hdr*)header_start;

	// convert network byte order to host byte order
	query_header.dns_id = ntohs(query_header.dns_id);
	query_header.dns_question_count = ntohs(query_header.dns_question_count);
	query_header.dns_answer_count = ntohs(query_header.dns_answer_count);
	query_header.dns_authority_count = ntohs(query_header.dns_authority_count);
	query_header.dns_additional_count = ntohs(query_header.dns_additional_count);

	if((query_header.dns_flags & DNS_QR) != 0)
		return false;
	if((query_header.dns_flags & DNS_ZERO) != 0)
		return false;
	if(query_header.dns_answer_count != 0)
		return false;
	if(query_header.dns_authority_count != 0)
		return false;

	(*dns_query_pointer)->dns_query_header = query_header;
	
	const unsigned char* query_start = header_start + DNS_HDR_LEN;
	unsigned char byte;
	unsigned short word;
	int query_offset = 0;
	int query_count = query_header.dns_question_count;

	// initialize query variables
	struct dns_query_section* queries = NULL;
	queries = (struct dns_query_section*)malloc(sizeof(struct dns_query_section)*query_count);
	if(queries==NULL)
		fatal("allocating memory for dns queries", "get_dns_query", NULL);
	else
		add_new_pointer(head, NULL, queries);
	char **domain_names = NULL;
	domain_names = (char**)malloc(sizeof(char*)*query_count);
	if(domain_names == NULL)
		fatal("allocating memory for domain names", "get_dns_query", NULL);
	else
	{
		add_new_pointer(head, NULL, domain_names);
		for(int i = 0;i<query_count;i++)
			domain_names[i] = NULL;
	}

	// fill query information
	for(int j = 0;j<query_count;j++)
	{
		domain_names[j] = get_domain_name(query_start, &query_offset);
		if(domain_names[j] == NULL)
		{
			free_all_pointers(head);
			return false;
		}
		else
			add_new_pointer(head, NULL, domain_names[j]);

		// get other information
		query_offset++;
		word = *(unsigned short*)(query_start + query_offset);
		queries[j].dns_type = word;
		query_offset+=2;
		word = *(unsigned short*)(query_start+query_offset);
		queries[j].dns_class = word;
		queries[j].dns_domain_name = domain_names[j];
		query_offset+=2;
	}
	(*dns_query_pointer)->dns_query_queries = queries;

	// prevent accidental use
	queries = NULL;
	for(int k = 0;k<query_count;k++)
		domain_names[k] = NULL;
	domain_names = NULL;

	int additional_count = query_header.dns_additional_count;

	if(additional_count == 0)
		return true;

	// initialize response variables
	struct dns_response_section* additional_records = NULL;
	additional_records = (struct dns_response_section*)malloc(sizeof(struct dns_response_section)*additional_count);
	if(additional_records == NULL)
		fatal("allocating memory for additional records", "get_dns_query", NULL);
	else
		add_new_pointer(head, NULL, additional_records);
	char** domain_names_additional = NULL;
	domain_names_additional = (char**)malloc(sizeof(char*)*additional_count);
	if(domain_names_additional == NULL)
		fatal("allocating memory for additional record domain names", "get_dns_query", NULL);
	else
	{
		add_new_pointer(head, NULL, domain_names_additional);
		for(int i = 0;i<additional_count;i++)
			domain_names_additional[i] = NULL;
	}

	// add additional section
	for(int additional_record_index;additional_record_index<additional_count;additional_record_index++)
	{
		byte = *(query_start + query_offset);

		// OPT record
		if(byte == 0x00)
		{
			additional_records[additional_record_index].dns_type = *(unsigned short*)(query_start + query_offset);
			query_offset+=2;
			if(additional_records[additional_record_index].dns_type != 41)
			{
				free_all_pointers(head);
				return false;
			}
			
			additional_records[additional_record_index].dns_class = *(unsigned short*)(query_start + query_offset);
			query_offset+=2;
			additional_records[additional_record_index].dns_TTL = *(unsigned int*)(query_start + query_offset);
			query_offset+=4;
			int dataLength = *(unsigned short*)(query_start + query_offset);
			query_offset+=2;
			additional_records[additional_record_index].dns_data_length = dataLength;
			if(dataLength != 0)
			{
				unsigned char* resource_data = (unsigned char*)malloc(sizeof(unsigned char)*dataLength);
				if(resource_data == NULL)
					fatal("allocating memory for resource data", "get_dns_query", NULL);
				else
					add_new_pointer(head, NULL, resource_data);

				memcpy(resource_data, query_start + query_offset, dataLength);
				query_offset+=dataLength;
				additional_records[additional_record_index].dns_resource_data = resource_data;
			}
			else
				additional_records[additional_record_index].dns_resource_data = NULL;
		}
		// normal record
		else
		{
			domain_names_additional[additional_record_index] = get_domain_name(query_start, &query_offset);
			if(domain_names_additional[additional_record_index] == NULL)
			{
				free_all_pointers(head);
				return false;
			}
			else
				add_new_pointer(head, NULL, domain_names_additional[additional_record_index]);

			additional_records[additional_record_index].dns_domain_name = domain_names_additional[additional_record_index];
			additional_records[additional_record_index].dns_type = *(unsigned short*)(query_start + query_offset);
			query_offset+=2;
			additional_records[additional_record_index].dns_class = *(unsigned short*)(query_start + query_offset);
			query_offset+=2;
			additional_records[additional_record_index].dns_TTL = *(unsigned int*)(query_start + query_offset);
			query_offset+=4;
			int dataLength = *(unsigned short*)(query_start + query_offset);
			query_offset+=2;
			additional_records[additional_record_index].dns_data_length = dataLength;
			if(dataLength != 0)
			{
				unsigned char* resource_data = (unsigned char*)malloc(sizeof(unsigned char)*dataLength);
				if(resource_data == NULL)
					fatal("allocating memory for resource data", "get_dns_query", NULL);
				else
					add_new_pointer(head, NULL, resource_data);

				memcpy(resource_data, query_start + query_offset, dataLength);
				query_offset+=dataLength;
				additional_records[additional_record_index].dns_resource_data = resource_data;
			}
			else
				additional_records[additional_record_index].dns_resource_data = NULL;
		}
	}

	(*dns_query_pointer)->dns_query_additional = additional_records;
	return true;
}

bool get_dns_response(const unsigned char *header_start, struct dns_response* dns_response_pointer)
{
	return false;
}

char* get_domain_name(const unsigned char* query_start_pointer, int *query_offset)
{
	char name[256];
	int domain_name_length =0;
	unsigned char byte;
	byte = *(query_start_pointer + *query_offset);
	(*query_offset)++;
	while(byte != 0x00)
	{
		// check for compression pointer
		if((byte & DNS_COMPRESSION_PTR) == DNS_COMPRESSION_PTR)
		{
			unsigned short offset = *(query_start_pointer + *query_offset -1);
			(*query_offset)++;
			// use offset to get the rest of the name
			offset -= DNS_COMPRESSION_PTR;
			int temp_offset = offset;
			char* temp = get_domain_name(query_start_pointer, &temp_offset);
			if(domain_name_length + temp_offset - offset > 256)
				return NULL;
			strncpy(&name[domain_name_length], temp, temp_offset - offset);
			domain_name_length += temp_offset - offset;
			free(temp);

			char* name_pointer = (char*)malloc(sizeof(char)*domain_name_length);
			if(name_pointer == NULL)
				fatal("allocating memory for domain_names", "get_domain_name", NULL);

			strncpy((char*)name_pointer, name, domain_name_length);
			return name_pointer;
		}
		for(int label_bytes_left = 0;label_bytes_left<byte;label_bytes_left++)
		{
			if(domain_name_length > 255)
				return NULL;
			name[domain_name_length] = *(query_start_pointer + *query_offset);
			(*query_offset)++;
			domain_name_length++;
		}
		if(domain_name_length > 255)
			return NULL;

		name[domain_name_length] = '.';
		domain_name_length++;
		byte = *(query_start_pointer + *query_offset);
		(*query_offset)++;
	}
	name[domain_name_length - 1] = '\0';

	char* name_pointer = (char*)malloc(sizeof(char)*domain_name_length);
	if(name_pointer == NULL)
		fatal("allocating memory for domain_names", "get_domain_name", NULL);

	strncpy(name_pointer, name, domain_name_length);
	return name_pointer;
}
