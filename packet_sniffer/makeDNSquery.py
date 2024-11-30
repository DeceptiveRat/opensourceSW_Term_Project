#!/bin/python3

from scapy.all import *

# Build a DNS query with two questions
dns_query = DNS(
    id=0x1234,
    qr=0,
    qd=DNSQR(qname="example.com", qtype="A") / DNSQR(qname="example.org", qtype="AAAA"),
    ar=DNSRROPT(rclass=4096)  # EDNS0
)

# Create a UDP/IP packet
packet = IP(dst="8.8.8.8") / UDP(sport=12345, dport=53) / dns_query

# Print the hexdump
hexdump(packet)

