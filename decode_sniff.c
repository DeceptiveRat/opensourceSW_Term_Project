#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>

#include "hacking_my.h"

#define CAPTURECOUNT 8

void pcap_fatal(const char *, const char *);
void decode_ethernet(const u_char *, FILE* outputFilePtr);
void decode_ip(const u_char *, FILE* outputFilePtr);
u_int decode_tcp(const u_char *, FILE* outputFilePtr);

void caught_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

int main()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *interface_list;
	pcap_t *pcap_handle;

	if(pcap_findalldevs(&interface_list, errbuf) == PCAP_ERROR)
		pcap_fatal("At findalldevs", errbuf);
	
	pcap_if_t *interface = interface_list;
	for(int i =0;i>-1;++i)
	{
		if(interface == NULL)
			break;
		printf("Interface #[%d] Name: %s (%s)\n", i, interface->name, interface->description);
		interface = interface->next;
	}

	printf("Choose an interface to use:\n");
	int interfaceNumber;
	scanf("%d", &interfaceNumber);

	interface = interface_list;
	for(int i = 0;i<interfaceNumber;i++)
	{
		if(interface == NULL)
		{
			printf("Choose a correct interface\n");
			exit(0);
		}

		interface = interface->next;
	}

	printf("Sniffing on device %s (%s)\n", interface->name, interface->description);

	// open file
	FILE *outputFilePtr = 0;
	outputFilePtr = fopen("packets_caught.txt", "w");
	if(outputFilePtr == 0)
	{
		printf("Error while opening file!\n");
		exit(-1);
	}

	pcap_handle = pcap_open_live(interface->name, 16384, 1, 100, errbuf);
	if(pcap_handle == NULL)
		pcap_fatal("At handle", errbuf);
	
	pcap_loop(pcap_handle, CAPTURECOUNT, caught_packet, (u_char *)outputFilePtr);

	pcap_freealldevs(interface_list);
	fclose(outputFilePtr);
	return 0;
}

void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet)
{
	FILE* outputFilePtr = (FILE*)user_args;
	int tcp_header_length, total_header_size, pkt_data_len;
	u_char *pkt_data;

	fprintf(outputFilePtr, "==== Got a %d byte packet ====\n", cap_header->len);

	decode_ethernet(packet, outputFilePtr);
	decode_ip(packet+ETHER_HDR_LEN, outputFilePtr);
	tcp_header_length = decode_tcp(packet+ETHER_HDR_LEN+sizeof(struct ip_hdr), outputFilePtr);

	total_header_size = ETHER_HDR_LEN+sizeof(struct ip_hdr)+tcp_header_length;

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

void pcap_fatal(const char *failed_in, const char *errbuf)
{
	printf("Fatal Error in %s: %s\n", failed_in, errbuf);
	exit(1);
}

void decode_ethernet(const u_char *header_start, FILE* outputFilePtr)
{
	int i;
	const struct ether_hdr *ethernet_header;

	ethernet_header = (const struct ether_hdr *)header_start;
	fprintf(outputFilePtr, "[[  Layer 2 :: Ethernet Header  ]]\n");
	fprintf(outputFilePtr, "[ Source: %02x", ethernet_header->ether_src_addr[0]);
	for(i = 1;i<ETHER_ADDR_LEN;i++)
		fprintf(outputFilePtr, ":%02x", ethernet_header->ether_src_addr[i]);
	
	fprintf(outputFilePtr, "\tDest: %02x", ethernet_header->ether_dest_addr[0]);
	for(i = 1;i<ETHER_ADDR_LEN;i++)
		fprintf(outputFilePtr, ":%02x", ethernet_header->ether_dest_addr[i]);
	
	fprintf(outputFilePtr, "\tType: %hu ]\n", ethernet_header->ether_type);
}

void decode_ip(const u_char *header_start, FILE* outputFilePtr)
{
	const struct ip_hdr *ip_header;
	char addressString[16];

	ip_header = (const struct ip_hdr*)header_start;
	fprintf(outputFilePtr, "\t((  Layer 3 ::: IP Header  ))\n");

	inet_ntop(AF_INET, (struct in_addr*)&(ip_header->ip_src_addr), addressString, 16);
	fprintf(outputFilePtr, "\t( Source: %s\t", addressString);

	inet_ntop(AF_INET, (struct in_addr*)&(ip_header->ip_src_addr), addressString, 16);
	fprintf(outputFilePtr, "Dest: %s )\n", addressString);
	fprintf(outputFilePtr, "\t( Type: %u\t", (u_int) ip_header->ip_type);
	fprintf(outputFilePtr, "ID: %hu\tLength: %hu )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));
}

u_int decode_tcp(const u_char *header_start, FILE* outputFilePtr)
{
	u_int header_size;
	const struct tcp_hdr *tcp_header;

	tcp_header = (const struct tcp_hdr *)header_start;
	header_size = 4*tcp_header->tcp_offset;

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
