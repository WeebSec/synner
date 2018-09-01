#! /usr/bin/python
# coding: utf-8 

from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys
from datetime import datetime
import time
import optparse
import threading
import signal
import re
import os
os.system("clear")

banner = '\033[90m'+ """
███████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔════╝╚██╗ ██╔╝████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████╗ ╚████╔╝ ██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║  ╚██╔╝  ██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║   ██║   ██║ ╚████║██║ ╚████║███████╗██║  ██║
╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
\033[92mby: wulfz\033[0m                                                 
"""

print banner.decode('utf-8')

SYNACK = 0x12
RSTACK = 0x14


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def c_print(text, color):
    print color + text + bcolors.ENDC

def parse_ports(port_range):
    ports = port_range.split("-")
    ports = range(int(ports[0]),int(ports[1])+1)
    return ports



def error(error_msg):
    c_print(error_msg, bcolors.FAIL)
    sys.exit(0)

def get_service(port):
    service = os.popen("cat /etc/services | grep -m1 %d/tcp" % (port)).read().split("\t")
    if(len(service) > 0 ):
        return service[0]
    return ""

def scan_port(target,port):
    src_port = RandShort()
    conf.verb = 0
    for i in range(0,3):
        syn_ack_pkt = sr1(IP(dst=target)/TCP(sport=src_port, dport=port, flags = "S"),timeout=1)
        if(str(type(syn_ack_pkt))=="<type 'NoneType'>"):
            if i != 2:
                continue
            c_print("[-] %d/TCP is Filtered.\t(%s)"% (port, get_service(port)), bcolors.OKGREEN)
            return
        if(syn_ack_pkt.haslayer(TCP)):
            if(syn_ack_pkt.getlayer(TCP).flags == SYNACK):
                send_rst = sr(IP(dst=target)/TCP(sport=src_port,dport=port,flags="AR"),timeout=1)
                c_print("[+] %d/TCP is Open.\t(%s)" % (port, get_service(port)), bcolors.OKGREEN)
                return
            if(syn_ack_pkt.getlayer(TCP).flags == RSTACK):
                return
    
def ping_target(target):
    conf.verb = 0
    ping=sr1(IP(dst=target)/ICMP(),timeout=10)
    if(ping != None):
        c_print("[*] Target is up.",bcolors.OKBLUE)
        return
    error("[!] Target did not respond to ICMP, is it up?")

def main():
    if os.name == 'nt':
        error("THIS TOOL IS FOR LINUX ONLY!")
    parser = optparse.OptionParser("")
    parser.add_option("-t", dest="target", type="string", help="Target IP Address")
    parser.add_option("-p", dest="portrange", type="string", help="Port Range Seperated by - Example: 1-1024")
    parser.add_option("-n",action="store_true" ,dest="noPing", default=False, help="don't check if host is up")
    (options, args) = parser.parse_args()
    if(options.target == None or options.portrange == None):
        parser.print_help()
        sys.exit(0)
    if os.getuid() is not 0:
        error("[!] This program needs root privileges..")
    if not options.target:
        error("Please specify a target.")
    if not options.portrange:
        error("Please specify a port range.")
        
    target = options.target
    ip_pattern = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
    if ip_pattern.match(target) == None:
        error("[!] Invalid IP address given.")
    try:
        ports = parse_ports(options.portrange)
    except:
        error("[!] Invalid port range format given.")
    
    if (ports[0]<=0 or ports[-1]>=65535):
        error("[!] invalid port number given.")
    if(options.noPing == False):
        ping_target(target)
    c_print("[*] Scanning %s" % (target), bcolors.OKBLUE) 
    for port in ports:
        scan_port(target,port)
    c_print("[*] Scan Finished!", bcolors.OKBLUE)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)


