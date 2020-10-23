
import sys
import random
from scapy.all import *
from threading import Thread
from functools import partial


def send_wrap(*args, **kwargs):
    try:
        send(*args, **kwargs)
    except:
        pass

def generate_random_ip():
    return str(ri(0,256)) + "." + str(ri(0,256)) + "." + str(ri(0,256)) + "." + str(ri(0,256))

def main(src_ip, dst_ip, src_port, dst_port, tcp_or_udp, mask_value):
	try:
		all_packet = 0
		mirror_packet = 0
		mask, value = list(map(int, mask_value.split("@")))
		for _ in range(5000):  
                    chksum = random.randint(0,256)
                    if tcp_or_udp == "TCP":
                        thr = Thread(target=lambda: send_wrap(IP(src=src_ip, dst=dst_ip, chksum=chksum) / TCP(sport=int(src_port), dport=int(dst_port)),verbose=False))
                        thr.start()
                    else:
                        thr = Thread(target=lambda: send_wrap(IP(src=src_ip, dst=dst_ip, chksum=chksum) / UDP(sport=int(src_port), dport=int(dst_port)), verbose=False))
                        thr.start()
                    if random.randint(0,1) == 0:
                        thr = Thread(target=lambda: send_wrap(IP(src=generate_random_ip, dst=generate_random_ip) / TCP(sport=random.randint(0,2 ** 16), dport=random.randint(0,2 ** 16)), verbose=False))
                        thr.start()
                    else:
                        thr = Thread(target=lambda: send_wrap(IP(src=generate_random_ip, dst=generate_random_ip) / UDP(sport=random.randint(0,2 ** 16), dport=random.randint(0,2 ** 16)), verbose=False))
                        thr.start()
                    all_packet += 2
                    if (mask & chksum) == value:
                        mirror_packet += 1
	finally:
		print("mirror %s packets out of %s" % (mirror_packet, all_packet))

if __name__ == '__main__':
    try:
        src_ip = sys.argv[1]
        dst_ip = sys.argv[2]
        src_port = sys.argv[3] 
        dst_port = sys.argv[4]
        tcp_or_udp = sys.argv[5]
        mask_value = sys.argv[6]
    except:
        print("format: send_pcap.py src_ip dst_ip src_port dst_port tcp_or_udp mask@value")
        sys.exit(0)
    main(src_ip, dst_ip, src_port, dst_port, tcp_or_udp, mask_value)

