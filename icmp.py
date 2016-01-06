#!/usr/bin/env python
#-*- coding: utf-8 -*-

'a icmp module for gscan'

__author__ = 'GZW'

import sys
import struct
import socket
import IPy
import time
import threading
import array
import os

result =set()

class sendThr(threading.Thread):
	def __init__(self, icmpPacket, ipPool, icmpSocket, timeout=3):
		threading.Thread.__init__(self)
		self.icmpPacket = icmpPacket #已构造好的icmp包
		self.ipPool = ipPool #i地址池
		self.icmpSocket = icmpSocket #icmp套接字
		self.timeout = timeout #超时时间
		self.icmpSocket.settimeout(timeout + 3)

	def run(self): #重写run
		time.sleep(0.01)
		for ip in self.ipPool:
			try:
				self.icmpSocket.sendto(bytes(self.icmpPacket), (ip, 0))
			except socket.timeout:
				break	
		time.sleep(self.timeout)

class recvThr(threading.Thread):
	def __init__(self, icmpSocket, ipPool, sendThr):
		threading.Thread.__init__(self)
		self.icmpSocket = icmpSocket
		self.ipPool = ipPool
		self.sendThr = sendThr

	def run(self):
		recvFroms = set()
		while True:
			try:
				aliveIp = self.icmpSocket.recvfrom(1024)[1][0]
				print aliveIp
				recvFroms.add(aliveIp)
			except Exception,e:
				print e
			finally:
				if not self.sendThr.isAlive():
					break
		print recvFroms & self.ipPool
		result = recvFroms & self.ipPool

class icmp:
	def __init__(self, timeout=3, isV6=False):
		self.timeout = timeout
		self.isV6 = isV6

		self.__id = os.getpid()
		self.__data = struct.pack('d', 0)

	def creatIpPool(self, startIP, stopIP):
		ipPool = set()
		if self.isV6:
			print "this function is not develop"
		else:
			ipToInt = lambda ip: IPy.IP(ip).int()
			ipPool = {IPy.intToIp(ip, 4) for ip in range(ipToInt(startIP), ipToInt(stopIP)+1)}
		return ipPool

	def __checkSum(self, packet):
		cksum = 0
		if len(packet) & 1:
			packet = packet + '\0'
		words = array.array('h', packet)
		for word in words:
			cksum += (word & 0xffff)

		cksum = (cksum >> 16) + (cksum & 0xffff)
		cksum = (cksum >> 16) + (cksum & 0xffff)

		return (~cksum) & 0xffff

	@property
	def __icmpSocket(self):
		if self.isV6:
			Sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname("ipv6-icmp"))
		else:
			Sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
		return Sock

	@property
	def __icmpPacket(self):
		if self.isV6:
			header = struct.pack('BbHHh', 128, 0, 0, self.__id, 0)
		else:
			header = struct.pack('bbHHh', 8, 0, 0, self.__id, 0)
		packet = header + self.__data
		cksum = self.__checkSum(packet)

		if self.isV6:
			header = struct.pack('BbHHh', 128, 0, 0, self.__id, 0)
		else:	
			header = struct.pack('bbHHh', 8, 0, cksum, self.__id, 0)
		return header + self.__data

	def scan(self, ipPool):
		sock = self.__icmpSocket
		packet = self.__icmpPacket

		send = sendThr(packet, ipPool, sock)
		recv = recvThr(sock, ipPool, send)

		send.start()
		recv.start()

		if not recv.isAlive():
			print result

def icmpScan(startIP, stopIP, isV6):
	s = icmp()
	ipPool = s.creatIpPool(startIP, stopIP)
	s.scan(ipPool)