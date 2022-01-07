#!/usr/bin/python3

import unittest

import logging

# Suppress Scapy warnings before importing
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from sys import argv, exit
import re
import socket

# Module imports
from dhcp_spoof import import_scapy
import_scapy()
from dhcp_spoof import (build_offer_message, is_discover_filter, mac_to_bytes, build_acknowledge_message)

def get_discover():
    if get_discover.disc is not None:
        return get_discover.disc
    else:
        discover = Ether(src='11:22:33:44:55:66', dst='ff:ff:ff:ff:ff:ff') / IP(src='0.0.0.0', dst='255.255.255.255')\
        / UDP(sport=68, dport=67) / BOOTP()

        discover[BOOTP].op = 1
        discover[BOOTP].htype = 1
        discover[BOOTP].hlen = 6
        discover[BOOTP].hops = 0
        discover[BOOTP].xid = 123456
        discover[BOOTP].secs = 0
        discover[BOOTP].flags = None

        opts = [('message-type', 1),\
                ('client_id', b'\x01\xd8\xf8\x83\x90\xde\xd1'),\
                ('requested_addr', '192.168.1.127'),\
                ('hostname', b'DESKTOP-L1VH27D'),\
                ('vendor_class_id', b'MSFT 5.0'),\
                ('param_req_list', [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),\
                'end']

        discover /= DHCP(options=opts)

        get_discover.disc = discover
        return discover

get_discover.disc = None

def get_request():
    if get_request.req is not None:
        return get_request.req
    else:
        pack = Ether(src='11:22:33:44:55:66', dst='ff:ff:ff:ff:ff:ff') / IP(src='0.0.0.0', dst='255.255.255.255')\
        / UDP(sport=68, dport=67) / BOOTP()

        pack[BOOTP].op = 1
        pack[BOOTP].htype = 1
        pack[BOOTP].hlen = 6
        pack[BOOTP].hops = 0
        pack[BOOTP].xid = 123456
        pack[BOOTP].secs = 0
        pack[BOOTP].flags = None
        pack[BOOTP].ciaddr = '0.0.0.0'
        pack[BOOTP].yiaddr = '0.0.0.0'
        pack[BOOTP].siaddr = '0.0.0.0'
        pack[BOOTP].giaddr = '0.0.0.0'
        pack[BOOTP].chaddr = mac_to_bytes(pack[Ether].src)

        opts = [('message-type', 3),\
                ('client_id', b'\x01\x02\x03\x03\x03\x03\x03'),\
                ('requested_addr', '192.168.1.127'),\
                ('server_id', '192.168.1.1'),\
                ('hostname', b'DESKTOP-LOLXDXD'),\
                ('client_FQDN', b'\x00\x00\x00DESKTOP-LOLXDXD.cyber.local'),\
                ('vendor_class_id', b'MSFT 5.0'),\
                ('param_req_list', [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),\
                'end']

        pack /= DHCP(options=opts)

        get_request.req = pack
        return pack

get_request.req = None

class TestDHCPSpoof(unittest.TestCase):
    def test_is_discover_filter__regular(self):
        discover = get_discover()

        self.assertEqual(is_discover_filter(discover), True)


    def test_build_offer_message__regular(self):
        discover = get_discover()

        mac, ip = '11:22:33:44:55:66', '192.168.1.100'

        offer = build_offer_message(discover, mac, ip, '2.2.2.2', '8.8.8.8')

        # Check MACs
        self.assertEqual(offer[Ether].dst, discover[Ether].src)
        self.assertEqual(offer[Ether].src, mac)

        # Check IPs are not specific
        self.assertEqual(offer[IP].src, ip)
        self.assertTrue(offer[IP].dst != '255.255.255.255')
        self.assertTrue(offer[IP].dst != '0.0.0.0')

        # Check UDP
        self.assertEqual(offer[UDP].sport, 67)
        self.assertEqual(offer[UDP].dport, 68)

        # Check BOOTP
        self.assertEqual(offer[BOOTP].op, 2)
        self.assertEqual(offer[BOOTP].xid, discover[BOOTP].xid)

        # Check DHCP
        opts = offer[DHCP].options

        # Check headers
        for x in opts:
            if x[0] == 'message-type':
                self.assertEqual(x[1], 2)
                break

        headers = [x[0] for x in opts]

        self.assertTrue('server_id'         in headers)
        self.assertTrue('lease_time'        in headers)
        self.assertTrue('subnet_mask'       in headers)
        self.assertTrue('broadcast_address' in headers)
        self.assertTrue('router'            in headers)
        self.assertTrue('name_server'       in headers)


#def build_acknowledge_message(request, my_mac, my_ip, assigned_ip):
    def test_build_acknowledge_message__regular(self):
        mac, ip = '11:22:33:44:55:66', '192.168.1.100'
     
        req = get_request()
        ack = build_acknowledge_message(req, mac, ip, '192.168.1.127', '8.8.8.8')

        # Check MACs
        self.assertEqual(req[Ether].src, ack[Ether].dst)
        self.assertEqual(req[Ether].dst, 'ff:ff:ff:ff:ff:ff')
        self.assertTrue(ack[Ether].dst != 'ff:ff:ff:ff:ff:ff')
        self.assertTrue(ack[Ether].dst != 'ff:ff:ff:ff:ff:ff')

        # Check IPs
        self.assertEqual(req[IP].src, '0.0.0.0')
        self.assertEqual(req[IP].dst, '255.255.255.255')
        self.assertTrue(ack[IP].src not in ['255.255.255.255', '0.0.0.0'])
        self.assertTrue(ack[IP].dst not in ['255.255.255.255', '0.0.0.0'])

        # Check UDP
        self.assertEqual(req[UDP].sport, ack[UDP].dport)
        self.assertEqual(req[UDP].dport, ack[UDP].sport)

        # Check BOOTP
        self.assertEqual(ack[BOOTP].op, 2)
        self.assertEqual(ack[BOOTP].xid, req[BOOTP].xid)

        # Addresses
        self.assertTrue(ack[BOOTP].yiaddr != '0.0.0.0')
        self.assertTrue(ack[BOOTP].siaddr != '0.0.0.0')

        # TODO: No check for values
        # Check DHCP options
        ack_opts = ack[DHCP].options

        headers = [x[0] for x in ack_opts]

        # Check headers
        self.assertTrue('server_id'         in headers)
        self.assertTrue('subnet_mask'       in headers)
        self.assertTrue('broadcast_address' in headers)
        self.assertTrue('router'            in headers)
        self.assertTrue('name_server'       in headers)



if __name__ == '__main__':
    unittest.main()
