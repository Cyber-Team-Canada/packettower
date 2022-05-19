#!/usr/bin/env python3

"""
Packettower will listen to network traffic through a specified interface and
display payloads of any incoming and outgoing traffic

Packettower will also attempt to write data to a `.pcap` file (./data.pcap)
"""

import codecs
import datetime
import os
import pyshark
import sys
import traceback

DUMPPATH = "./data.pcap"

def listen(interface):

    print(f"[info] capturing on interface {interface}")
    print("[note] to exit, send two SIGINTs")

    capture = pyshark.LiveCapture(interface=interface, use_json=True, include_raw=True)

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
            except Exception as e:
                print(f"[err] General execption thrown:")
                traceback.print_exc()

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

