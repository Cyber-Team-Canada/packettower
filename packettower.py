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

pcap_file_base = "./test_dumps/dump"
# randomly generate a tmp file for this process to use
TEMPPATH = f"/tmp/{sha256(str(random.randint(0,10000000)).encode('utf-8')).hexdigest()}.pcap"

# keep tcpdump process as a global process to easily kill it
tcpdump_p = None

def listen(interface, pcap_file_base=None):
    global tcpdump_p

    print(f"[info] capturing on interface {interface}")
    print("[note] to exit, send two SIGINTs")

    capture = pyshark.LiveCapture(interface=interface, use_json=True, include_raw=True)

    # start tcp_dump process
    tcpdump_p = subp.Popen(["tcpdump", "-i", interface, "-w", TEMPPATH, "-U"])

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

                print(f"\n{packet.sniff_time.isoformat()} - {packet_type} packet from: {src} -> to: {dst} ({packet.highest_layer} packet)")
                print(f"[info] payload detected")
                print(f"(raw):\n{payload}")

                raw_payload = payload.replace(':', '') # place all hex values consecutively
                decoded_payload = codecs.decode(raw_payload, "hex")
                print(f"(decoded):\n{str(decoded_payload, 'utf-8')}")
                print("-----------------------")
            except AttributeError:
                # print("[info] packet has no data")
                continue
            except UnicodeDecodeError:
                print("[info] failed to decode payload, try using CyberChef?")
                print("-----------------------")
                continue

        # close and restart tcpdump process to write pcap file
        tcpdump_p.terminate()
        # move generated pcap file to desired location
        shutil.copy(TEMPPATH, pcap_file_base+"-"+datetime.now().strftime("%H-%M-%S-%sss")+".pcap")
        tcpdump_p = subp.Popen(["tcpdump", "-i", interface, "-w", TEMPPATH, "-U"])

if __name__ == "__main__":
    if(len(sys.argv) < 2):
        print(f"Usage: {sys.argv[0]} <interface>")
        exit(1)

    # todo: ensure written pcap file is readable by tcpdump
    # set headers of pcap file
    # with open(DUMPPATH, "wb+") as pcap_file:
    #     pcap_file.write(
    #             b"\xd4\xc3"\
    #             b"\xb2\xa1"\
    #             b"\x02\x00"\
    #             b"\x04\x00"\
    #             b"\x00\x00"\
    #             b"\x00\x00"\
    #             b"\x00\x00"\
    #             b"\x00\x00"\
    #             b"\xff\xff"\
    #             b"\xff\xff"\
    #             b"\x01\x00"\
    #             b"\x00\x00"\
    #             b"\xb5\xd5"\
    #             b"\x85\x62"\
    #             b"\x92\xac"\
    #             b"\x01\x00"\
    #             b"\x4a\x00"\
    #             b"\x00\x00"\
    #             b"\x4a\x00"\
    #             b"\x00\x00"
    # )

    listen(sys.argv[1])


    try:
        listen(sys.argv[1])
    except Exception as e:
        print(f"[err] General execption thrown:")
        traceback.print_exc()
        # cleanup
        tcpdump_p.terminate()
        os.remove(TEMPPATH)
