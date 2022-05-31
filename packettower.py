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
import re
import shutil
import subprocess as subp
import sys
import traceback

# randomly generate a tmp file for this process to use
TEMPPATH = f"./.{sha256(str(random.randint(0,10000000)).encode('utf-8')).hexdigest()}.pcap"

# keep tcpdump process as a global process to easily kill it
tcpdump_p = None
nullfd = open(os.devnull, "w")

def listen(interface, service_port, **kwargs):
    """
    required args:
    | interface - the network interface to listen for traffic from
    | service_port - the port a service is running on
    |    traffic to and from this port will be recorded
    optional args:
    | pcap_file_base ( = ".") - write to the location to write pcap files
    |    note: will create files in the form "packettower_port-<port>_<attacker
    |    info>.pcap" within the specified folder
    |    if not specified, will write to working directory
    | port_listen ( = False) - differentiate traffic by host address and port number
    |    note: only useful depending on the infrastructure of the CTF. for
    |    example, if all attackers are passing through a router with a NAT table,
    |    then using `--port_listen` would be beneficial.
    | flag_pattern ( = None) - attempt to read packet payloads for outgoing flags
    |                          that match the regex pattern.
    |    note: most commonly, this argument will be in the form of `FLAG{.*}` and
    |    is dependent on the CTF
    |    eg: for SaarCTF, `SAAR{.*}`
    """
    print(f"[info] capturing on interface {interface} for port {service_port}")

    # handle arguments
    pcap_file_base = "."
    if("pcap_path" in kwargs.keys()): pcap_file_base = kwargs["pcap_path"]
    port_listen = False
    if("port_listen" in kwargs.keys()): port_listen = kwargs["port_listen"]
    flag_pattern = None
    if("flag_pattern" in kwargs.keys()):
        print(f"[info] using flag regex {kwargs['flag_pattern']}")
        flag_pattern = kwargs['flag_pattern']

    # mapping: port number : (filename, tcpdump_process)
    port_pcap_map = {}

    capture = pyshark.LiveCapture(interface=interface, use_json=True, include_raw=True)

    while(True):
        for packet in capture.sniff_continuously(packet_count=10):
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
            except AttributeError as e:
                continue

            # if it's a new port making a request, start listening to it with a
            # new tcpdump process

            # one port must be the service port, ignore it
            attacker_port = src_port
            attacker_addr = src_addr
            if(src_port == service_port):
                attacker_port = dst_port
                attacker_addr = dst_addr

            attacker_key = attacker_addr
            if(port_listen): attacker_key += attacker_port

            if(attacker_key not in port_pcap_map.keys()):
                pcap_path = f"{pcap_file_base}/packettower_port-{service_port}_{attacker_addr}"
                if(port_listen): pcap_path += f"-{attacker_port}"
                pcap_path += ".pcap"

                # filter for only this service
                tcpdump_expr = f"port {service_port} and host {attacker_addr}"
                if(port_listen): tcpdump_expr += f" and port {attacker_port}"

                tcpdump_proc = subp.Popen(["tcpdump", "-i", interface, "-w", pcap_path, "-U"] + tcpdump_expr.split())
                port_pcap_map[attacker_key] = (pcap_path, tcpdump_proc)

                print(f"[info] found new potential attacker: {attacker_addr}:{attacker_port}, " \
                      f"generating new pcap file {pcap_path}")

            # attempt to decode payload if it exists
            if(flag_pattern == None):
                continue # no point decoding if flag format is unknown

            flag_regex = re.compile(flag_pattern)
            try:
                raw_payload = payload.replace(':', '')
                decoded_payload = str(codecs.decode(raw_payload, "hex"), "utf-8")
                if(not flag_regex.search(decoded_payload)): continue
                print(f"[info] ({datetime.now().strftime('%H-%M-%S-%s')}) packet " \
                      f"payload matches flag regex - see file {port_pcap_map[attacker_key][0]}")
            except UnicodeDecodeError:
                print("could not decode")
                continue

def print_help():
    print(f"Usage: {sys.argv[0]} <interface> <port> [options]")
    print("Packettower will generate .pcap files for a given service hosted at" \
          "a specific port from a specified network interface\n")
    print("required args:")
    print("| interface - the network interface to listen for traffic from\n" \
          "| port - the port a service is running on\n" \
          "|    traffic to and from this port will be recorded")
    print("optional args:")
    print("| -o /path/to/dump/folder - write to the location to write pcap files\n" \
          "|    note: will create files in the form \"packettower_port-<port>_<attacker info>.pcap\"" \
          " within the specified folder. if not specified, will write to working directory\n" \
          "| --port_listen - differentiate traffic by host address and port number\n" \
          "|    note: only useful depending on the infrastructure of the CTF." \
          " for example, if all attackers are passing through a router with a NAT table, then" \
          " using `--port_listen` would be beneficial.\n" \
          "| --flag_pattern <flag pattern in regex> - attempt to read packet payloads for outgoing" \
          " flags that match the regex pattern.\n" \
          "|    note: most commonly, this argument will be in the form of `FLAG{.*}` and is dependent on the CTF\n" \
          "|    eg: for SaarCTF, `SAAR{.*}`\n" \
          "| -h - displays this help menu")

if __name__ == "__main__":
    if(len(sys.argv) < 3):
        print_help()
        exit(1)

    if(shutil.which("tcpdump") == None or shutil.which("tshark") == None):
        print("[err] packettower requires `tcpdump` and `tshark` to run. please install them")
        exit(1)

    # parse arguments
    interface = None
    port = None
    pcap_file_base = None
    port_listen = False
    flag_pattern = None

    for index, arg in enumerate(sys.argv):
        if(index == 0): continue # ignore call
        if(arg[0] != '-' and interface == None):
            interface = arg
            continue
        if(arg[0] != '-' and port == None):
            port = arg
            continue
        if(arg == "-o"):
            pcap_file_base = sys.argv[index+1]
            continue
        if(arg == "--port_listen"):
            port_listen = True
            continue
        if(arg == "--flag_pattern"):
            flag_pattern = sys.argv[index+1]
        if(arg == "-h"):
            print_help()
            exit(0)

    try:
        listen(interface, port,
                pcap_path=pcap_file_base,
                port_listen=port_listen,
                flag_pattern=flag_pattern
              )
    except Exception as e:
        print(f"[err] General execption thrown:")
        traceback.print_exc()
        # cleanup
        if(pcap_file_base != None):
            tcpdump_p.terminate()
            os.remove(TEMPPATH)
        nullfd.close()
