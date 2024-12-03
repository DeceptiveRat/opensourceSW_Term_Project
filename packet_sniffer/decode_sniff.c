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


#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>

#include "otherFunctions.h"
#include "packetFunctions.h"

#define CAPTURECOUNT 10

void pcap_fatal(const char *, const char *);

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
			pcap_freealldevs(interface_list);
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
		pcap_freealldevs(interface_list);
		exit(-1);
	}

	pcap_handle = pcap_open_live(interface->name, 16384, 1, 100, errbuf);
	if(pcap_handle == NULL)
	{
		pcap_freealldevs(interface_list);
		fclose(outputFilePtr);
		pcap_fatal("At handle", errbuf);
	}
	
	pcap_loop(pcap_handle, CAPTURECOUNT, print_caught_packet, (u_char *)outputFilePtr);

	printf("Successfully caught all packets\n");
	pcap_freealldevs(interface_list);
	fclose(outputFilePtr);
	return 0;
}

void pcap_fatal(const char *failed_in, const char *errbuf)
{
	printf("Fatal Error in %s: %s\n", failed_in, errbuf);
	exit(1);
}
