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
from dhcp_spoof import (build_offer_message, is_discover_filter)

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

class TestDHCPSpoof(unittest.TestCase):
    def test_is_discover_filter__regular(self):
        discover = get_discover()

        self.assertEqual(is_discover_filter(discover), True)


    def test_build_offer_message__regular(self):
        discover = get_discover()

        mac, ip = '11:22:33:44:55:66', '192.168.1.100'

        offer = build_offer_message(discover, mac, ip, '2.2.2.2')

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



if __name__ == '__main__':
    unittest.main()
