import sys

from scapy.all import *
from scapy.utils import rdpcap
from threading import Thread

def main(pcap_file, mask_value_list):
	try:
		all_packet = 0
		sample_on_demande_packet = 0
		pkts=PcapReader(pcap_file)  
		for pkt in pkts:
			if IP not in pkt:
				continue
			all_packet += 1
			for mask, value in [list(map(int, mask_value.split("@"))) for mask_value in mask_value_list]:
				if (pkt.chksum & mask) == value:
					sample_on_demande_packet += 1
			thr = Thread(target=send, args=[pkt], kwargs={'verbose': False})
			thr.start()
	finally:
		print("mirror %s packets out of %s" % (sample_on_demande_packet, all_packet))
		
		
if __name__ == '__main__':
    try:
        pcap_file = sys.argv[1]
        mask_value_list =sys.argv[2].split(",")
    except:
        print("format: send_pcap.py pcap_file mask_value_list")
        sys.exit(0)
    main(pcap_file, mask_value_list)