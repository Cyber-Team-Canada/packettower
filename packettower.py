#!/usr/bin/env python3

import pyshark

capture = pyshark.LiveCapture(interface="wlan0")

for packet in capture.sniff_continuously(packet_count=5):
    print(packet)
