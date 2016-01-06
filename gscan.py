#!/usr/bin/env python
#-*- coding: utf-8 -*-

'a scan tool like nmap'

__author__ = 'GZW'

import sys
import icmp

def isUnIP(IP):
	IP = [int(x) for x in IP.split('.') if x.isdigit()]
	if(len(IP) == 4):
		if(0<IP[0]<223 and IP[0]!=127 and 0<=IP[1]<256 and 0<=IP[2]<256 and 0<IP[3]<256):
			return True
	return False

args = sys.argv
if(len(args) < 2):
	print "123"
elif(args[1] == '-icmp'):
	if(len(args) >3):
		if(isUnIP(args[2]) and isUnIP(args[3])):
			if(args[4] == '-v6'):
				icmp.icmpScan(args[2], args[3], True)
			else:
				icmp.icmpScan(args[2], args[3], False)
		else:
			print "error: the IP adress is illegal."
	else:
		print "warm: please input starIP and stopIP."
else:
	print "arguments are follows:"
	print "-icmp [start ip] [stop ip] {-v6}\t use icmp method to scan(defaults ipv4)."