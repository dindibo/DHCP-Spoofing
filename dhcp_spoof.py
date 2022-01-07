#!/usr/bin/python3

import logging

# Suppress Scapy warnings before importing
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from sys import argv, exit
import re
import socket

# Globals
my_mac=None
my_ip=None

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

def is_mac_valid(x):
    return bool(re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", x.lower()))

def is_ip_valid(x):
    try:
        socket.inet_aton(x)
        return True
    except:
        pass
    
    return False

def escape(reason):
    print(reason)
    sys.exit(1)

def print_help():
    print('dhcp-spoof attacker_mac attacker_ip [flags]')
    print('')
    print('Flags: ')
    print('\t-h,  help')

def build_offer_message(discover):
    global my_mac, my_ip

    to_mac = discover[Ether].src
    from_mac = my_mac

# Prints an example discovery
def handle_DHCP_discover(pack):
    print('Got Discover from ----> ', end='')
    print(pack[Ether].src)


def main():
    if len(sys.argv) != 3 or '-h' in sys.argv:
        print_help()
    else:
        my_mac, my_ip = sys.argv[1], sys.argv[2]
        if not(is_mac_valid(my_mac) and is_ip_valid(my_ip)):
            print('Invalid IP or MAC')
            exit(1)

        print('Listening...')
        sniff(lfilter=is_discover_filter, prn=handle_DHCP_discover)


if __name__ == "__main__":
    main()
