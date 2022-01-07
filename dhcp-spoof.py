#!/usr/bin/python3

import logging

# Suppress Scapy warnings before importing
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

# Constants

ETHER_BROADCAST     = 'ff:ff:ff:ff:ff:ff'
IP_BROADCAST        = '255.255.255.255'
DHCP_CLIENT_PORT    = 68 
DHCP_SERVER_PORT    = 67

class DHCP_FLAGS:
    # OP
    BOOTREQUEST=1
    BOOTREPLY=2

    # htype
    HTYPE_RES=1

    # hlen
    HTYPE_RES=6

# Checks if a packet has DHCP layers
def is_dhcp_layers(pack):
    # Filter by layers
    return pack.haslayer(DHCP) and pack.haslayer(BOOTP) and pack.haslayer(UDP)\
    and pack.haslayer(IP) and pack.haslayer(Ether)

# Checks if a packet is DHCP type discover
def is_discover_filter(pack):
    if is_dhcp_layers(pack):
        # Check ports
        if pack[UDP].sport == DHCP_CLIENT_PORT and pack[UDP].dport == DHCP_SERVER_PORT:
            # Check if broadcast
            if pack[Ether].dst == ETHER_BROADCAST and  pack[IP].dst == IP_BROADCAST:
                 opts = pack[DHCP].options
                 return opts[0][1] == DHCP_FLAGS.BOOTREQUEST

    return False

# Prints an example discovery
def handle_DHCP_discover(pack):
    print('Got Discover from ----> ', end='')
    print(pack[Ether].src)

print('Listening...')
sniff(lfilter=is_discover_filter, prn=handle_DHCP_discover)
