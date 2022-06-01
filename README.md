# packettower
a tool to listen to and monitor network traffic

_sample output_
```
# packettower wlan0 5885 -o test_dumps --flag_pattern "FLAG{.*}"

[info] capturing on interface wlan0 for port 5885
[info] using flag regex FLAG{.*}
[info] found new potential attacker: 10.0.0.18:50423, generating new pcap file test_dumps/packettower_port-5885_10.0.0.18.pcap
tcpdump: listening on wlan0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
[info] (17-59-23-1654041563) packet payload matches flag regex - see file test_dumps/packettower_port-5885_10.0.0.18.pcap
```

## installation

```bash
$ git clone https://github.com/e-seng/packettower.git
$ pip3 install -r ./packettower/requirements.txt
```

## running it

requires hightened privileges, as this will run `tcpdump` to listen to network
traffic.

packet information parsed by packettower will be written to `stdout`

```bash
Usage: ./packettower.py <interface> [options]
optional args:
| -o /path/to/dump/folder - write to the location to write files
|    note: this will generate a file called packettower_dump-%H-%M-%S-%s.pcap if not specified, no pcap file will be generated.
| -h - displays this help menu
```

eg. `$ sudo ./packettower.py docker0 -o test_dumps`

`./test_dumps` must be a directory that already exists

*written for Attack/Defense CTFs*
