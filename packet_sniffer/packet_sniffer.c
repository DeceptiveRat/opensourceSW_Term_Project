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

#include "packetFunctions.h"
#include "otherFunctions.h"

#define CAPTURECOUNT 20

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
	
	printf("Sniffing on device %s (%s)\n", interface.name, interface.description);

	pcap_handle = pcap_open_live(interface.name, 16384, 1, 100, errbuf);
	if(pcap_handle == NULL)
	{
		pcap_freealldevs(interface_list);
		pcap_fatal("At handle", errbuf);
	}
	
	pcap_loop(pcap_handle, CAPTURECOUNT, analyze_caught_packet, NULL);

	pcap_freealldevs(interface_list);
	printf("Successfully caught all packets\n");
	return 0;
}

void pcap_fatal(const char *failed_in, const char *errbuf)
{
	printf("Fatal Error in %s: %s\n", failed_in, errbuf);
	exit(1);
}
