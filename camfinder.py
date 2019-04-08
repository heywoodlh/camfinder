#!/usr/bin/env python3
import argparse
import os, sys
import netifaces
import socket, fcntl, struct
from getmac import get_mac_address
from scapy.all import srp,Ether,ARP,conf

parser = argparse.ArgumentParser(description="Utility for identifying wifi cams")

parser.add_argument('-i', '--interface', help='network interface', metavar='NIC', required=True)
parser.add_argument('-a', '--all', help='print all arp entries', action='store_true')
parser.add_argument('-v', '--verbose', help='show more information', action='store_true')


args = parser.parse_args()


offending_mac_prefix = { 
    "30:8C:FB": "dropcam", 
    "00:24:E4": "withings", 
    "2C:AA:8E": "wyze", 
    "64:16:66": "nest", 
    "18:B4:30": "nest" 
}


def get_ip_address(interface):
    ip_address = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    return(ip_address)

def get_netmask(interface):
    netmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
    netmask = sum(bin(int(x)).count('1') for x in netmask.split('.'))
    return(netmask)

def arp_scan(interface, cidr_range, mac_list):
    if args.verbose:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = cidr_range), timeout = 2, iface = interface, inter = 0.1)
    else:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = cidr_range), timeout = 2, iface = interface, inter = 0.1, verbose = 0)
    for snd,rcv in ans:
        remote_mac = rcv.sprintf(r"%Ether.src%")
        remote_ip = rcv.sprintf(r"%ARP.psrc%")
    
            
        if args.all:
            print(remote_mac + ' - ' + remote_ip)
        else:
            for mac in mac_list.keys():
                if mac.lower() in remote_mac:
                    print('FOUND CAM: ' + mac_list[mac] + ' -- ' + remote_ip)


def main():
    interface = args.interface
    ip_address = get_ip_address(interface)
    netmask = get_netmask(interface)
    cidr_range = ip_address + '/' + str(netmask)
    arp_scan(interface, cidr_range, offending_mac_prefix)


if __name__ == '__main__':
    main()
