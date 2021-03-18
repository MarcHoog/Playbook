from scapy.all import *
from time import sleep
from threading import Thread
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import sys

class Attack:
    def __init__(self,dhcpsrv):
        self.hwaddr = str(RandMAC())
        self.dhcpsrv = dhcpsrv



    def run():