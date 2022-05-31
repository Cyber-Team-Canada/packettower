#!/usr/bin/env python3

"""
Packettower will listen to network traffic through a specified interface and
display payloads of any incoming and outgoing traffic

Packettower will also attempt to write data to a `.pcap` file (./data.pcap)
"""

import codecs
from datetime import datetime
from hashlib import sha256
import os
import pyshark
import random
import shutil
import subprocess as subp
import sys
import traceback

# randomly generate a tmp file for this process to use
TEMPPATH = f"./.{sha256(str(random.randint(0,10000000)).encode('utf-8')).hexdigest()}.pcap"

# keep tcpdump process as a global process to easily kill it
tcpdump_p = None
nullfd = open(os.devnull, "w")

def listen(interface, service_port, pcap_file_base=None):
    global tcpdump_p
    # mapping: port number : (filename, tcpdump_process)
    port_pcap_map = {}

    print(f"[info] capturing on interface {interface}")
    print("[note] to exit, send two SIGINTs")

    capture = pyshark.LiveCapture(interface=interface, use_json=True, include_raw=True)

    # start tcp_dump process if output path is specified
    if(pcap_file_base != None):
        tcpdump_p = subp.Popen(["tcpdump", "-i", interface, "-w", TEMPPATH, "-U"], stdout=nullfd, stderr=nullfd)

    while(True):
        for packet in capture.sniff_continuously(packet_count=100):
            # ignore ARP packets and DHCP packets
            if(packet.highest_layer == "ARP_RAW" or packet.highest_layer == "DHCP_RAW"):
                continue

            # get information about a given packet
            try:
                # get packet payload, if it exists
                payload = None
                src_addr = packet.ip.addr[0]
                dst_addr = packet.ip.addr[1]
                src_port = None
                dst_port = None
                if(hasattr(packet, "udp")):
                    # not for the correct service, continue
                    if(service_port not in packet.udp.port): continue
                    payload = packet.udp.payload
                    # get port information
                    src_port = packet.udp.port[0]
                    dst_port = packet.udp.port[1]
                    packet_type = "udp"
                else: # not udp, likely tcp
                    # not for the correct service, continue
                    if(service_port not in packet.tcp.port): continue
                    payload = packet.tcp.payload
                    # get port information
                    src_port = packet.tcp.port[0]
                    dst_port = packet.tcp.port[1]
            except AttributeError:
                continue
            # attempt to decode payload if it exists
            try:
                raw_payload = payload.replace(':', '')
                decoded_payload = str(codecs.decode(raw_payload, "hex"), "utf-8")
            except UnicodeDecodeError:
                continue

        if(pcap_file_base != None):
            # close and restart tcpdump process to write pcap file
            tcpdump_p.terminate()
            # move generated pcap file to desired location
            shutil.copy(TEMPPATH, pcap_file_base+"/packettower_dump-"
                    + datetime.now().strftime("%H-%M-%S-%s")+".pcap")
            tcpdump_p = subp.Popen(["tcpdump",
                "-i",
                interface,
                "-w",
                TEMPPATH,
                "-U"],
                stdout=nullfd,
                stderr=nullfd)

def print_help():
    print(f"Usage: {sys.argv[0]} <interface> [options]")
    print("optional args:")
    print("| -o /path/to/dump/folder - write to the location to write files\n" \
          "|    note: this will generate a file called packettower_dump-%H-%M-%S-%s.pcap" \
          " if not specified, no pcap file will be generated.\n" \
          "| -h - displays this help menu")

if __name__ == "__main__":
    if(len(sys.argv) < 2):
        print_help()
        exit(1)

    # parse arguments
    interface = None
    pcap_file_base = None

    for index, arg in enumerate(sys.argv):
        if(arg[0] != '-' and interface == None):
            interface = arg
        if(arg == "-o"):
            pcap_file_base = sys.argv[index+1]
            continue
        if(arg == "-h"):
            print_help()
            exit(0)

    try:
        listen(sys.argv[1], pcap_file_base)
    except Exception as e:
        print(f"[err] General execption thrown:")
        traceback.print_exc()
        # cleanup
        if(pcap_file_base != None):
            tcpdump_p.terminate()
            os.remove(TEMPPATH)
        nullfd.close()
