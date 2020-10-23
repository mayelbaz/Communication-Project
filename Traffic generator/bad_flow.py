from scapy.all import *
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether
import os


if __name__ == '__main__':
    out = sendpfast(IP(), mbps=8000000, loop=10000000, iface="enp1s0f1", parse_results=1)
