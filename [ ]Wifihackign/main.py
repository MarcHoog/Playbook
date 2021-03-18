from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.l2 import Ether
from randmac import randmac

interface = "wlan0"

mac = str(RandMAC())

ssid = "Gaming"

dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
# Type = 0              Management Frame
# subtype = 8           Beacon Frame
# addr1:                MAC address of the reciever
# addr2:                MAC address of the sender
# addr3:                MAC address of the Access point (AP)

beacon = Dot11Beacon()
#  IEEE 802.11 beacon message the big message that contains it contains all the information of the network

essid = Dot11Elt(ID=ssid, info=ssid, len=len(ssid))
# IEEE 802.11 information element

frame = RadioTap() / dot11 / beacon / essid

sendp(frame)
