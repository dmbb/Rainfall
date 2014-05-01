#!/usr/bin/env python

import logging
from scapy.all import *
import sys
import socket

conf.verb=0 #disables scapy default verbose mode
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #disables 'No route found for IPv6 destination' warning


t_wait=.25 #timeout for the answer to each packet
openPorts = [] #holds the open ports to show as a summary
closedPorts = [] #holds the closed ports to show as a summary
filteredPorts = [] #holds the filtered ports to show as a summary
opfilPorts = [] #holds the open/filtered ports to show as a summary

def syn_scan(tgt, bP, eP):
  for port in xrange(bP, eP+1):
    answer = sr1(IP(dst=tgt)/TCP(dport=port,flags="S"),timeout=t_wait)
    if(str(type(answer))=="<type 'NoneType'>"):
      filteredPorts.append(int(port))
      print "Port %d - Filtered" % port
    elif(answer.haslayer(TCP)):
      if(answer.getlayer(TCP).flags == 0x12):
	send_rst = sr(IP(dst=tgt)/TCP(dport=port,flags="R"),timeout=t_wait)
	openPorts.append(int(port))
	print "Port %d - Open" % port
      elif (answer.getlayer(TCP).flags == 0x14):
	closedPorts.append(int(port))
	print "Port %d - Closed" % port
      elif(answer.haslayer(ICMP)):
	if(int(answer.getlayer(ICMP).type)==3 and int(answer.getlayer(ICMP).code) in [1,2,3,9,10,13]):
	  filteredPorts.append(int(port))
          print "Port %d - Filtered" % port
  summary()


def xmas_scan(tgt, bP, eP):
  for port in xrange(bP, eP+1):
    answer = sr1(IP(dst=tgt)/TCP(sport=bP,dport=eP,flags="FPU"),timeout=t_wait)
    if (str(type(answer))=="<type 'NoneType'>"):
      opfilPorts.append(int(port))
      print "Port %d - Open/Filtered" % port
    elif(answer.haslayer(TCP)):
      if(answer.getlayer(TCP).flags == 0x14):
	closedPorts.append(int(port))
	print "Port %d - Closed" % port
      elif(answer.haslayer(ICMP)):
	if(int(answer.getlayer(ICMP).type)==3 and int(answer.getlayer(ICMP).code) in [1,2,3,9,10,13]):
	  filteredPorts.append(int(port))
	  print "Port %d - Filtered" % port
  summary()


def fin_scan(tgt, bP,eP):
  for port in xrange(bP, eP+1):
    answer = sr1(IP(dst=tgt)/TCP(sport=bP,dport=eP,flags="F"),timeout=t_wait)
    if (str(type(answer))=="<type 'NoneType'>"):
      opfilPorts.append(int(port))
      print "Port %d - Open/Filtered" % port
    elif(answer.haslayer(TCP)):
      if(answer.getlayer(TCP).flags == 0x14):
	closedPorts.append(int(port))
	print "Port %d - Closed" % port
      elif(answer.haslayer(ICMP)):
	if(int(answer.getlayer(ICMP).type)==3 and int(answer.getlayer(ICMP).code) in [1,2,3,9,10,13]):
	  filteredPorts.append(int(port))
	  print "Port %d - Filtered" % port
  summary()


def null_scan(tgt, bP, eP):
  for port in xrange(bP, eP+1):
    answer = sr1(IP(dst=tgt)/TCP(sport=bP,dport=eP,flags=""),timeout=t_wait)
    if (str(type(answer))=="<type 'NoneType'>"):
      opfilPorts.append(int(port))
      print "Port %d - Open/Filtered" % port
    elif(answer.haslayer(TCP)):
      if(answer.getlayer(TCP).flags == 0x14):
	closedPorts.append(int(port))
	print "Port %d - Closed" % port
      elif(answer.haslayer(ICMP)):
	if(int(answer.getlayer(ICMP).type)==3 and int(answer.getlayer(ICMP).code) in [1,2,3,9,10,13]):
	  filteredPorts.append(int(port))
	  print "Port %d - Filtered" % port
  summary()


def ack_scan(tgt, bP, eP):
  for port in xrange(bP, eP+1):
    answer = sr1(IP(dst=tgt)/TCP(sport=bP,dport=eP,flags="A"),timeout=t_wait)
    if (str(type(answer))=="<type 'NoneType'>"):
      filteredPorts.append(int(port))
      print "Port %d - Filtered by Stateful Firewall" % port
    elif(answer.haslayer(TCP)):
      if(answer.getlayer(TCP).flags == 0x4):
	print "Port %d - Unfiltered by Firewall" % port
      elif(answer.haslayer(ICMP)):
	if(int(answer.getlayer(ICMP).type)==3 and int(answer.getlayer(ICMP).code) in [1,2,3,9,10,13]):
	  filteredPorts.append(int(port))
	  print "Port %d - Filtered by Stateful Firewall" % port
  summary()
  
  
def summary():
  print "============================================================================================"
  print "There are {0} open ports, {1} filtered ports, {2} open/filtered ports and {3} closed ports".format(len(openPorts), len(filteredPorts), len(opfilPorts),len(closedPorts))
  print "The following ports are open:"
  for port in openPorts:
    print "[+] %d Open" % port


def scan(tgt, bP, eP, mode):
  scanModes = {1 : syn_scan,
                2 : xmas_scan,
                3 : fin_scan,
                4 : null_scan,
                5 : ack_scan,
}
  
  scanModes[mode](tgt, bP, eP)