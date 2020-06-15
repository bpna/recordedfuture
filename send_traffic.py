#!/bin/python3.8

# Created by Patrick Kinsella 6/14/2020
# Last Edited 6/14/2020
#
# Takes a list of source and destination IPs created with get_demoevents.py
# and sends spoofed packets with those IP addresses in the IP packet header.
# Payloads are empty
# Does not handle IPv6 addresses

from scapy.all import sr1, IP
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create and send packets for\
                                                  IP addresses in\
                                                  watchlist.file')
    parser.add_argument('ips', type=argparse.FileType('r'))
    args = parser.parse_args()

    ips = args.ips
    ips.readline()
    x = 0
    for line in ips:
        x += 1
        # get source and destination IP address
        addrs = line.split()
        src   = addrs[0]
        dst   = addrs[1]

        # detect and ignore IPv6 addresses
        if ':' not in src and ':' not in dst:
            # craft and send packet with above IPs, do not wait for a reply
            print('sending packet #' + str(x) + ' w/ src=' + src + ', dst=' + dst)
            p = IP(src=src, dst=dst)
            sr1(p, timeout=0)
