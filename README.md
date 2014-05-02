#Rainfall

This is a small project that i'm developing while learning Python.

Rainfall is a console based TCP port scanner that allows you to do stealth scans.
I used [scapy](http://www.secdev.org/projects/scapy/) for it, as it turns out to ease packet manipulation.
This version is currently single-threaded, i'm looking forward to turn it multi-threaded in order to speed up the scans.

Currently, it can do:
* SYN scanning
* XMAS scanning
* FIN scanning
* NULL scanning
* ACK scanning

##Tasks
- [ ] Show service name next to the corresponding port number.
- [ ] Turn the scanner into a multi-threaded one.
- [ ] Do some OS fingerprinting assessment


##How to use

```
sudo python rainfall.py -h
usage: rainfall [-h] [--version] -p PORTS PORTS -t TARGET -m MODE

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -p PORTS PORTS, --ports PORTS PORTS
                        Port interval to scan
  -t TARGET, --target TARGET
                        Target host
  -m MODE, --mode MODE  scan mode: 1-syn, 2-xmas, 3-fin, 4-null, 5-ack
  ```
  
  _Must be run in sudo because scapy demands it._
