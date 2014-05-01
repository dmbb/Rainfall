#!/usr/bin/env python

import argparse
import sys
import socket
import scanner
from scanner import scan


parser = argparse.ArgumentParser(prog='rainfall')
parser.add_argument('--version', action='version', version='%(prog)s 1.0')
parser.add_argument('-p', '--ports', nargs=2, required=True, help='Port interval to scan')
parser.add_argument('-t', '--target', required=True, help='Target host')
parser.add_argument('-m', '--mode', nargs=1, required=True, help='scan mode: 1-syn, 2-xmas, 3-fin, 4-null, 5-ack ')


args = parser.parse_args()

try:
    beginPort = int(args.ports[0])
    endPort = int(args.ports[1])
    assert beginPort > 0 and endPort > 0 and beginPort <= endPort
except AssertionError:
    print "[ERROR] Port range is invalid - startPort must be <= endPort, both of which > 0"
    sys.exit()


target = args.target
mode = args.mode

scan(target, beginPort, endPort, int(mode[0]))