# packettower
a tool to listen to and monitor network traffic for a particular service

this tool will automatically filter the source of all traffic to distinguish
different attackers

_sample output_

```bash
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
$ cd ./packettower
$ ./publish_scripts/publish.sh
$ source ./packettower_env/bin/activate
```

## running it

requires hightened privileges, as this will run `tcpdump` to listen to network
traffic.

stdout will contain notifications of new attackers, and the generated pcap file
that tracks their traffic. if set, `packettower` will also attempt to match the
payloads of traffic to a provided flag regex.

```bash
# packettower -h

Usage: packettower <interface> <port> [options]
Packettower will generate .pcap files for a given service hosted ata specific port from a specified network interface

required args:
| interface - the network interface to listen for traffic from
| port - the port a service is running on
|    traffic to and from this port will be recorded
optional args:
| -o /path/to/dump/folder - write to the location to write pcap files
|    note: will create files in the form "packettower_port-<port>_<attacker info>.pcap" within the specified folder. if not specified, will write to working directory
| --port_listen - differentiate traffic by host address and port number
|    note: only useful depending on the infrastructure of the CTF. for example, if all attackers are passing through a router with a NAT table, then using `--port_listen` would be beneficial.
| --flag_pattern <flag pattern in regex> - attempt to read packet payloads for outgoing flags that match the regex pattern.
|    note: most commonly, this argument will be in the form of `FLAG{.*}` and is dependent on the CTF
|    eg: for SaarCTF, `SAAR{.*}`
| -h - displays this help menu
```

eg. `# packettower wlan0 5885 -o test_dumps --flag_pattern "FLAG{.*}"`

`./test_dumps` must be a directory that already exists

*written for Attack/Defense CTFs*
