#!/usr/bin/env python3

import pyshark

def listen(interface):
    print(f"[info] capturing on interface {interface}")
    print("[note] to exit, send two SIGINTs")

    capture = pyshark.LiveCapture(interface=interface)

    while(True):
        for packet in capture.sniff_continuously(packet_count=10):
            try:
                print(packet.tcp.payload)
            except AttributeError:
                print("[info] packet has no data")
                continue
            except Exception as e:
                print(f"[err] General execption thrown:")
                print(e)

if __name__ == "__main__":
    import sys

    if(len(sys.argv) < 2):
        print(f"Usage: {sys.argv[0]} <interface>")
        exit(1)

    listen(sys.argv[1])

