import threading
from scapy.all import *
import csv
import time
import sys
from os import system, name
from threading import Lock
import p4runtime_sh.shell as sh # open source code

ingress_port = 0  # length 2 bytes mask 0000 1111 1111 000
timestamp_sec = 6  # length 6 bytes
timestamp_ns = 12  # length 4 bytes
mirror_reason = 39  # ingress or egress mirror
psn_idx = 20  # 2 bytes
latency = 31  # one byte
lsb_ing_occup = 23  # three bytes
lsb_eg_occup = 27  # three bytes
eg_port = 18
graph_interval = 10 # seconds
stop_threads = False

IS_USER = 5
USER_TOS = 104

#################### Globals ##################

list_lock = Lock()
known_lock = Lock()
user_lock = Lock()
congestion_lock = Lock()
info_lock = Lock()
shell_lock = Lock()
packets = []  # Global list containing all of the packets
known_tuples = []
full_info = []
still_congested = [[False, None], True]
user_found = [False]
standard_frequency = 10
connection_set = [False]


# ======================================#
'''
This is the P4Runtime shell-related setup. We are using p4runtime-shell
open-souce code from the git found at https://github.com/p4lang/p4runtime-shell
and installed on the lab's Collector.
the setup & teardown should only be done once!
'''
if not connection_set[0]:
    shell_lock.acquire()
    try:
        sh.setup(
            device_id=0,
            grpc_addr='132.68.36.62:50051',
            election_id=(0, 1),
            config=sh.FwdPipeConfig('/tmp/OurMirror.p4info', '/tmp/OurMirror.bin')
        )
        te = sh.TableEntry('control_out_port.ipv4_check_checksum')(action='DoMirror')
        connection_set[0] = True
        print("connection acomplished")
    finally:
        shell_lock.release()


# ======================================#

def clear():
    # for windows
    if name == 'nt':
        _ = system('cls')

        # for mac and linux(here, os.name is 'posix')
    else:
        _ = system('clear')

# ======================================#
class ErspanPacket:
    def __init__(self, reason, psn, flow_five, time_sec, time_nanosec, ingress_port, ingress_occupancy, egress_port,
                 egress_occupancy, latency):
        self.reason = reason
        self.psn = psn
        self.flow_five = flow_five
        self.time_sec = time_sec
        self.time_nanosec = time_nanosec
        self.ingress_port = ingress_port
        self.ingress_occupancy = ingress_occupancy
        self.egress_port = egress_port
        self.egress_occupancy = egress_occupancy
        self.latency = latency

    def is_egress(packet):
        if packet.reason == "EG":
            return True
        else:
            return False

    def is_ingress(packet):
        if packet.reason == "IN":
            return True
        else:
            return False


# ======================================#
def should_stop_threads(_ignore):
    if stop_threads is True:
        return True
    else:
        return False


def sniff_packets():
    sniff(iface="eth0", prn=packet_handler, stop_filter=should_stop_threads)

# ======================================#

def get_five_tuple(receivedPacket):
    user_traffic = False
    # receivedPacket=rawSocket.recv(2048)
    # print("****************************")
    # IP_header
    inner_pkt_IP = receivedPacket[14:34]
    src_0 = str(int(hex(inner_pkt_IP[12]), 16))
    src_1 = str(int(hex(inner_pkt_IP[13]), 16))
    src_2 = str(int(hex(inner_pkt_IP[14]), 16))
    src_3 = str(int(hex(inner_pkt_IP[15]), 16))
    inner_IP_source = src_0 + '.' + src_1 + '.' + src_2 + '.' + src_3
    # print(inner_IP_source)
    dst0 = str(int(hex(inner_pkt_IP[16]), 16))
    dst1 = str(int(hex(inner_pkt_IP[17]), 16))
    dst2 = str(int(hex(inner_pkt_IP[18]), 16))
    dst3 = str(int(hex(inner_pkt_IP[19]), 16))
    inner_IP_dest = dst0 + '.' + dst1 + '.' + dst2 + '.' + dst3
    # print(inner_IP_dest)
    protocol = str(int(hex(inner_pkt_IP[9]), 16))
    tos = int(hex(inner_pkt_IP[1]), 16)
    if tos == 104:
        # print("Got ya! TOS is 104, which means DSCP is 26")
        user_traffic = True
    # print(protocol)

    # TCP Header...
    pkt_gre = receivedPacket[34:54]
    src_0 = (int(hex(pkt_gre[0]), 16))
    src_1 = (int(hex(pkt_gre[1]), 16))
    port_source = str(int(hex((src_0 << 8) | src_1), 16))
    dest_0 = (int(hex(pkt_gre[0]), 16))
    dest_1 = (int(hex(pkt_gre[1]), 16))
    port_dest = str(int(hex((dest_0 << 8) | dest_1), 16))
    # print("Source Port: " + port_source)
    # print("Destination Port: " + port_dest)
    # print("****************************")
    return (inner_IP_source, inner_IP_dest, protocol, port_source, port_dest, user_traffic, tos)


# ======================================#

# TODO - check what is protocol 47, what should ours be
def packet_handler(pkt):
    if IP not in pkt:
        return
    if pkt[IP].proto != 47:
        return

    pkt_gre = list(pkt.load)

    if pkt_gre[mirror_reason] == 1:
        pkt_mirror = "IN"
    elif pkt_gre[mirror_reason] == 2:
        pkt_mirror = "EG"
    else:
        return

    flow_five_tuple = get_five_tuple(pkt_gre[50:])
    # Calculate the PSN
    psn_msb = int(hex(pkt_gre[psn_idx]), 16)
    psn_lsb = int(hex(pkt_gre[psn_idx + 1]), 16)
    psn = int(hex((psn_msb << 8) | psn_lsb), 16)
    # print("psn : " , psn)

    # Calculate the ingress_port
    ing_port_msb = int(hex(pkt_gre[ingress_port]), 16)
    ing_port_lsb = int(hex(pkt_gre[ingress_port + 1]), 16)
    ing_port = int(hex((((ing_port_msb << 8) | ing_port_lsb) << 4) >> 8), 16)
    # print("ingress port : " , ing_port)

    # Calculate the egress_port
    egress_port_msb = int(hex(pkt_gre[eg_port]), 16)
    egress_port_lsb = int(hex(pkt_gre[eg_port + 1]), 16)
    egress_port = int(hex((((egress_port_msb << 8) | egress_port_lsb) << 4) >> 8), 16)
    # print("egress port: ",egress_port)

    # Calculate ingress buff occupancy
    buff_1 = int(hex(pkt_gre[lsb_ing_occup]), 16)
    buff_2 = int(hex(pkt_gre[lsb_ing_occup + 1]), 16)
    buff_3 = int(hex(pkt_gre[lsb_ing_occup + 2]), 16)
    buff_ing_occupancy = int(hex((((buff_1 << 8) | buff_2) << 8) | buff_3), 16)
    # print('ingress_buff_occupancy :',buff_ing_occupancy)

    # Calculate egress buffer_occupancy
    buff_1 = int(hex(pkt_gre[lsb_eg_occup]), 16)
    buff_2 = int(hex(pkt_gre[lsb_eg_occup + 1]), 16)
    buff_3 = int(hex(pkt_gre[lsb_eg_occup + 2]), 16)
    buff_eg_occupancy = int(hex((((buff_1 << 8) | buff_2) << 8) | buff_3), 16)
    # print('egress_buff_occupancy :',buff_eg_occupancy)

    # Calculate latency
    buff_1 = int(hex(pkt_gre[latency]), 16)
    buff_2 = int(hex(pkt_gre[latency + 1]), 16)
    buff_3 = int(hex(pkt_gre[latency + 2]), 16)
    latency_ns = int(hex((((buff_1 << 8) | buff_2) << 8) | buff_3), 16)
    # print("latency = " , latency_ns)

    # TODO - check the latency process, what type of latency is it

    # Calculate timestamp_sec
    ts_sec_msb = int(hex(pkt_gre[timestamp_sec]), 16)
    for i in range(1, 6):
        ts_sec_lsb = int(hex(pkt_gre[i + timestamp_sec]), 16)
        res_sec = int(hex((ts_sec_msb << 8) | ts_sec_lsb), 16)
        ts_sec_msb = res_sec
    # Calculate timestamp_ns
    ts_msb = int(hex(pkt_gre[timestamp_ns]), 16)
    for i in range(1, 4):
        ts_lsb = int(hex(pkt_gre[i + timestamp_ns]), 16)
        res_ns = int(hex((ts_msb << 8) | ts_lsb), 16)
        ts_msb = res_ns
    # print('timestamp (sec) = ',res_ns)

    if flow_five_tuple[2] == 17:
        protocol = "TCP"
    else:
        protocol = "UDP"
    # (inner_IP_source, inner_IP_dest, protocol, port_source, port_dest, user_traffic)
    if flow_five_tuple[IS_USER] and flow_five_tuple not in known_tuples:
        info_lock.acquire()
        try:
            full_info.append([flow_five_tuple, ing_port, egress_port, protocol])
        finally:
            info_lock.release()
        known_lock.acquire()
        try:
            known_tuples.append(flow_five_tuple)
        finally:
            known_lock.release()
        if not user_found[0]:
            user_lock.acquire()
            try:
                user_found[0] = True
            finally:
                user_lock.release()
    elif flow_five_tuple not in known_tuples:
        info_lock.acquire()
        try:
            full_info.append([flow_five_tuple, ing_port, egress_port, protocol])
        finally:
            info_lock.release()
        known_lock.acquire()
        try:
            known_tuples.append(flow_five_tuple)
        finally:
            known_lock.release()

    # Add packet to list
    list_lock.acquire()
    try:
        # print("APPENDING")
        packets.append(
            ErspanPacket(pkt_mirror, psn, flow_five_tuple, res_sec, res_ns, ing_port, buff_ing_occupancy, egress_port,
                         buff_eg_occupancy, latency_ns))
    finally:
        list_lock.release()

    if buff_eg_occupancy > 3000 and not still_congested[0][0]:
        congestion_lock.acquire()
        try:
            #print("\n\tcongestions detected on port ", egress_port)
            still_congested[0] = [True, egress_port]
            if still_congested[1]:
                print("\n\tcongestions detected on port ", egress_port)
                print("\tcongestion diagnosed due to the following information:")
                print("\t - buffer occupancy on port is: ", buff_eg_occupancy)
                print("\t - latency (ns): ", latency_ns)
                print("\twhich exceeded normal behavior.")
                orig_std = sys.stdout
                logs_file = open("logs.txt","a")
                sys.stdout = logs_file
                logs_file.write("Congestion detected at time: ")
                logs_file.write(str(time.asctime( time.localtime(time.time()) )) + "\n\n")
                logs_file.write("congestions detected on port " + str(egress_port))
                logs_file.write("\ncongestion diagnosed due to the following information:")
                logs_file.write("\n\t - buffer occupancy on port is: " + str(buff_eg_occupancy))
                logs_file.write("\n\t - latency (ns): " + str(latency_ns))
                logs_file.write("\nwhich exceeded normal behavior.\n\n")
                still_congested[1] = False
                sys.stdout = orig_std
        finally:
            congestion_lock.release()
    elif still_congested[0][0] and buff_eg_occupancy < 3000:
        congestion_lock.acquire()
        try:
            still_congested[0] = [False, None]
        finally:
            congestion_lock.release()

# ======================================#

def extractFlowInformation():
    info_lock.acquire()
    i = 0
    clear()
    for tup in full_info:
        five_tup = tup[0]
        print("Flow informtion number: ", i)
        print("\t Ingress port: ", tup[1])
        print("\t Egress port: ", tup[2])
        print("\t Source IP: ", five_tup[0])
        print("\t Dest IP: ", five_tup[1])
        print("\t L4 protocol: ", tup[3])
        print("\t Source L4 Port: ", five_tup[3])
        print("\t Dest L4 Port: ", five_tup[4])
        print("\t TOS value: ", five_tup[6])
        print()
        i+=1
    info_lock.release()


def showUser():
    user_lock.acquire()
    if user_found[0]:
        info_lock.acquire()
        clear()
        for tup in full_info:
            five_tup = tup[0]
            if five_tup[6] == USER_TOS:
                print("***************************************")
                print("User's flow informtion:")
                print("\t Ingress port: ", tup[1])
                print("\t Egress port: ", tup[2])
                print("\t Source IP: ", five_tup[0])
                print("\t Dest IP: ", five_tup[1])
                print("\t L4 protocol: ", tup[3])
                print("\t Source L4 Port: ", five_tup[3])
                print("\t Dest L4 Port: ", five_tup[4])
                print("\t TOS value: ", five_tup[6])
                print("***************************************")
        info_lock.release()
    else:
        print("User's flow was not found")
    user_lock.release()

def stopShell():
    shell_lock.acquire()
    try:
        te = sh.TableEntry('control_out_port.ipv4_check_checksum')(action='DoMirror')
        sh.TableEntry('control_out_port.ipv4_check_checksum').read(lambda t: t.delete())
        sh.teardown()
        print("disconnected")
    finally:
        shell_lock.release()


def analyzeCongestion():
    congestion_lock.acquire()
    if still_congested[0][0]:
        print("Congestion found on port", still_congested[0][1])
        print("Setting up P4Runtime entry to match on port")
        shell_lock.acquire()
        try:
            te = sh.TableEntry('control_out_port.ipv4_check_checksum')(action='DoMirror')
            te.match['standard_metadata.egress_port'] = hex(still_congested[0][1])
            te.match['headers.ip.ipv4.hdr_checksum'] = '0x7f00&&&0x7f00'
            te.action['analyzer_port'] = '0x04'
            te.priority = 1
            te.insert()
        finally:
            shell_lock.release()
    else:
        print("No Congestion found")
    congestion_lock.release()



def maintain_list(clean_freq, clean_interval):
    while stop_threads == False:
        time.sleep(clean_freq)
        if len(packets) > 0:
            newest_ts = list(packets)[-1].time_sec
            list_lock.acquire()
            try:
                for pkt in packets:
                    if newest_ts - pkt.time_sec > clean_interval:
                        packets.remove(pkt)
            finally:
                list_lock.release()


