# DHCP-Spoofing
This is a POC project of DHCP Spoofing attack


## Introduction

DHCP  attack is a layer 2 networking attack, it exploits the DHCP protocol.  The DHCP protocol is a very common networking protocol used in almost all computers and
Windows specifically.  The idea behind this protocol is to allow clients that connect to a new network to automatically configure their  network  configuration,  in
this  protocol, the default gateway is usually also the DHCP server and it tells the client the network's parameters e.g. Default gateway, Broadcast address, Subnet
mask and also an unsed IP address to be assigned to the client. DHCP messages are sent in group of 4: Discover, Offer, Request and Ackknowledge,  because  initially
the  client don't know who the gateway is and don't have an IP address, it sends the first 3 messages in broadcast. Therotically, an attacker can impersonate a DHCP
server (rogue DHCP server) and offer the client a different configuration before the legitimate DHCP server does. Or alternativally, if there's no DHCP server,  the
attacker  can  simply  send a malicious configuration. The attacker has control on the client's default gateway configuration and also the DNS server, hence the at‐
tacker can perform man-in-the-middle attack on the default gateway and the victim and also, the attacker can resolve malicious DNS queris


## Usage 

dhcp-spoof attacker_mac attacker_ip [flags]

Flags:
  h - help

## Dependencies

* Scapy

## Future development

* Integration with DHCP Starving

    DHCP Starving starving is when an attacker floods the DHCP Server with forged DHCP Messages, with fake MAC address to empty the
    IP Pool allocated making the legitimate DHCP server useless. The attacker can then run the DHCP Spoofing and allocate IP addreses
    on the fake IPs, this way the attacker eliminates the race condition between him and the legitimate server.

## POC

dhcp_spoof

![](https://raw.githubusercontent.com/dindibo/DHCP-Spoofing/main/imgs/dhcp-poc.png)



Network PCAP on wireshark

![wireshark](https://raw.githubusercontent.com/dindibo/DHCP-Spoofing/main/imgs/proof.png)



Malicious network configuration on victim

![proof](https://raw.githubusercontent.com/dindibo/DHCP-Spoofing/main/imgs/wireshark.png)
