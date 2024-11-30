#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>

#include "packetFunctions.h"
#include "otherFunctions.h"

#define CAPTURECOUNT 10

void pcap_fatal(const char *, const char *);

int main()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *interface_list;
	pcap_t *pcap_handle;

	if(pcap_findalldevs(&interface_list, errbuf) == PCAP_ERROR)
		pcap_fatal("At findalldevs", errbuf);
	
	// choose first interface
	pcap_if_t interface;
	interface = *interface_list;
	pcap_freealldevs(interface_list);
	
	printf("Sniffing on device %s (%s)\n", interface.name, interface.description);

	// open file
	FILE *outputFilePtr = 0;
	outputFilePtr = fopen("analyze_packets.txt", "w");
	if(outputFilePtr == 0)
	{
		printf("Error while opening file!\n");
		pcap_freealldevs(interface_list);
		exit(-1);
	}

	pcap_handle = pcap_open_live(interface.name, 16384, 1, 100, errbuf);
	if(pcap_handle == NULL)
	{
		pcap_freealldevs(interface_list);
		fclose(outputFilePtr);
		pcap_fatal("At handle", errbuf);
	}
	
	pcap_loop(pcap_handle, CAPTURECOUNT, analyze_caught_packet, (u_char *)outputFilePtr);

	printf("Successfully caught all packets\n");
	fclose(outputFilePtr);
	return 0;
}

void pcap_fatal(const char *failed_in, const char *errbuf)
{
	printf("Fatal Error in %s: %s\n", failed_in, errbuf);
	exit(1);
}
