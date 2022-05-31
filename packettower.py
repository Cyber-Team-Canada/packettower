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

def listen(interface, pcap_file_base=None):
    global tcpdump_p

    print(f"[info] capturing on interface {interface}")
    print("[note] to exit, send two SIGINTs")

    capture = pyshark.LiveCapture(interface=interface, use_json=True, include_raw=True)

    # start tcp_dump process if output path is specified
    if(pcap_file_base != None):
        tcpdump_p = subp.Popen(["tcpdump", "-i", interface, "-w", TEMPPATH, "-U"], stdout=nullfd, stderr=nullfd)

    while(True):
        for packet in capture.sniff_continuously(packet_count=25):
            # ignore ARP packets and DHCP packets
            if(packet.highest_layer == "ARP_RAW" or packet.highest_layer == "DHCP_RAW"):
                continue

            try:
                # get packet payload, if it exists
                payload = None
                src = packet.ip.src
                dst = packet.ip.dst
                packet_type = "tcp"
                if(hasattr(packet, "udp")):
                    payload = packet.udp.payload
                    # get port information
                    src += ":" + packet.udp.port[0]
                    dst += ":" + packet.udp.port[1]
                    packet_type = "udp"
                else: # not udp, likely tcp
                    payload = packet.tcp.payload
                    # get port information
                    src += ":" + packet.tcp.port[0]
                    dst += ":" + packet.tcp.port[1]

                # print(f"\n{packet.sniff_time.isoformat()} - {packet_type} packet from: {src} -> to: {dst} ({packet.highest_layer} packet)")
                # print(f"[info] payload detected")
                # print(f"(raw):\n{payload}")

                # place all hex values consecutively
                # raw_payload = payload.replace(':', '')
                # decoded_payload = codecs.decode(raw_payload, "hex")
                # print(f"(decoded):\n{str(decoded_payload, 'utf-8')}")
                # print("-----------------------")
            except AttributeError:
                # print("[info] packet has no data")
                continue
            except UnicodeDecodeError:
                # print("[info] failed to decode payload, try using CyberChef?")
                # print("-----------------------")
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
