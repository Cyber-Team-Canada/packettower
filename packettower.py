#!/usr/bin/env python3

"""
Packettower will listen to network traffic through a specified interface and
display payloads of any incoming and outgoing traffic

Packettower will also attempt to write data to a `.pcap` file (./data.pcap)
"""

import os
import pyshark
import sys

DUMPPATH = "./data.pcap"

def listen(interface):

    print(f"[info] capturing on interface {interface}")
    print("[note] to exit, send two SIGINTs")

    capture = pyshark.LiveCapture(interface=interface, use_json=True, include_raw=True)

    while(True):
        for packet in capture.sniff_continuously(packet_count=25):
            # ignore ARP packets
            if(packet.highest_layer == "ARP_RAW"):
                continue

            print("-----------------------")
            print(f"from: {packet.ip.src} -> to: {packet.ip.dst} ({packet.highest_layer} packet)")
            try:
                print(f"payload:\n{packet.tcp.payload}")
            except AttributeError:
                print("[info] packet has no data")
                continue
            except Exception as e:
                print(f"[err] General execption thrown:")
                print(e)
            finally:
                with open("./data.pcap", "ab+") as pcap_file:
                    pcap_file.write(packet.get_raw_packet())

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

