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
from dhcp_spoof import build_offer_message

class TestDHCPSpoof(unittest.TestCase):
    def test_upper(self):
        self.assertEqual('foo'.upper(), 'FOO')

    def test_isupper(self):
        self.assertTrue('FOO'.isupper())
        self.assertFalse('Foo'.isupper())

    def test_split(self):
        s = 'hello world'
        self.assertEqual(s.split(), ['hello', 'world'])
        # check that s.split fails when the separator is not a string
        with self.assertRaises(TypeError):
            s.split(2)

if __name__ == '__main__':
    unittest.main()
