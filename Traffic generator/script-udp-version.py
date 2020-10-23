#!/usr/bin/env python2
import argparse
import os
import sys
from time import sleep


import pwd
import os
import re
import glob

import ntpath

PROC_UDP = "/proc/net/udp"
STATE = {
        '01':'ESTABLISHED',
        '02':'SYN_SENT',
        '03':'SYN_RECV',
        '04':'FIN_WAIT1',
        '05':'FIN_WAIT2',
        '06':'TIME_WAIT',
        '07':'CLOSE',
        '08':'CLOSE_WAIT',
        '09':'LAST_ACK',
        '0A':'LISTEN',
        '0B':'CLOSING'
        }
VIEW_IPTABLES = 1
DELETE_RULES = 2
TERMINATE = 3


def _load():
    ''' Read the table of tcp connections & remove header  '''
    with open(PROC_UDP,'r') as f:
        content = f.readlines()
        content.pop(0)
    return content

def _hex2dec(s):
    return str(int(s,16))

def _ip(s):
    ip = [(_hex2dec(s[6:8])),(_hex2dec(s[4:6])),(_hex2dec(s[2:4])),(_hex2dec(s[0:2]))]
    return '.'.join(ip)

def _remove_empty(array):
    return [x for x in array if x !='']

def _convert_ip_port(array):
    host,port = array.split(':')
    return _ip(host),_hex2dec(port)

def _get_pid_of_inode(inode):
    '''
    To retrieve the process pid, check every running process and look for one using
    the given inode.
    '''
    for item in glob.glob('/proc/[0-9]*/fd/[0-9]*'):
        try:
            if re.search(inode,os.readlink(item)):
                return item.split('/')[2]
        except:
            pass
    return None

def netstat():
    '''
    Function to return a list with status of tcp connections at linux systems
    To get pid of all network process running on system, you must run this script
    as superuser
    '''

    content=_load()
    result = []
    for line in content:
        line_array = _remove_empty(line.split(' '))     # Split lines and remove empty spaces.
        l_host,l_port = _convert_ip_port(line_array[1]) # Convert ipaddress and port from hex to decimal.
        r_host,r_port = _convert_ip_port(line_array[2]) 
        tcp_id = line_array[0]
        state = STATE[line_array[3]]
        uid = pwd.getpwuid(int(line_array[7]))[0]       # Get user from UID.
        inode = line_array[9]                           # Need the inode to get process pid.
        pid = _get_pid_of_inode(inode)                  # Get pid prom inode.
        try:                                            # try read the process name.
            exe = os.readlink('/proc/'+pid+'/exe')
        except:
            exe = None

        nline = [tcp_id, uid, l_host+':'+l_port, r_host+':'+r_port, state, pid, exe]
        result.append(nline)
    return result

if __name__ == '__main__':
    '''
    dest_ip = sys.argv[1]
    dest_tcp_port = sys.argv[2]
    '''
    app = sys.argv[1]
    found_conn = False
    added_rules = []
    ongoing = True
    for conn in netstat():
        app_loc = str(conn[6])
        curr_app = ''+ntpath.basename(app_loc)+''
        if curr_app == app:
            dest = conn[3].split(":")
            source = conn[2].split(":")
            source_ip = source[0]
            source_tcp_port = source[1]
            dest_ip = dest[0]
            dest_tcp_port = dest[1]
            if dest_ip == '0.0.0.0' or source_ip == '0.0.0.0':
                continue
            os.system('sudo iptables -t mangle -A OUTPUT -d '+dest_ip+' -p udp --dport '+dest_tcp_port+
                ' -s '+source_ip+' --sport '+source_tcp_port+
                ' -m statistic --mode nth --every 1000 --packet 1 -j DSCP --set-dscp 26')
            new_rule = [source_ip, source_tcp_port, dest_ip, dest_tcp_port]
            added_rules.append(new_rule)
            if not found_conn:
                found_conn = True
    if not found_conn:
        print("No such connection exists.")
    elif added_rules != []:
        deleted = False
        while ongoing:
            choice_number = input("\nNew rules have been added to your Iptables. \nChoose:\n"+
                "\t(1) to view your modified iptables\n"+
                "\t(2) to delete the newly added rules.\n"+
                "\t(3) to terminate this program.\n")
            choice = int(choice_number)
            if choice == VIEW_IPTABLES:
                print("\n")
                os.system('sudo iptables -t mangle -L -v')
                if deleted:
                    print("\nNOTE: All script-added rules have been removed.\n" + 
                        "They should NOT appear in the above iptables.\n")
            elif choice == DELETE_RULES:
                if deleted:
                    print("\n *************** The new rules have already been deleted. ***************")
                    continue
                for rule in added_rules:
                    os.system('sudo iptables -t mangle -D OUTPUT -d '+rule[2]+' -p udp --dport '+rule[3]+
                        ' -s '+rule[0]+' --sport '+rule[1]+
                        ' -m statistic --mode nth --every 1000 --packet 1 -j DSCP --set-dscp 26')
                print("\n *************** All script-added rules have been removed. *************** \n")
                deleted = True
            elif choice == TERMINATE:
                if not deleted:
                    while ongoing:
                        ans = raw_input("\nThere are iptables rule created by this script that have not been deleted.\n" +
                            "Would you still like to terminate? (y/N)\n")
                        #ans = string(raw)
                        if ans == 'y' or ans == 'Y':
                            print("\n\nGoodbye\n\n")
                            ongoing = False
                        elif ans == 'n' or ans == 'N':
                            break
                        else:
                            print("Unrecongnised command.\n\n")
                else:
                    print("\n\nGoodbye\n\n")
                    ongoing = False
            else:
                print("Unrecongnised command.\n\n")
