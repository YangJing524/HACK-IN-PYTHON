# !/usr/bin/python
# coding=utf-8
# Time:20220807
# author:YANG-JING


import optparse
from scapy.all import *

def findGoogle(pkt):
	if pkt.haslayer(Raw):
		payload = pkt.getlayer(Raw).load
		# import gzip
		# ret = gzip.decompress(payload).decode("utf-8")
		# print(ret)

		print()
		if 'GET' in payload:
			if 'sogou' in payload:
				r = re.findall(r'(?i)\&q=(.*?)\&', payload)
				if r:
					search = r[0].split('&')[0]
					search = search.replace('q=', '').replace('+', ' ').replace('%20', ' ')
					print('[+] Searched For:' + search)


def main():
	parser = optparse.OptionParser('[*]Usage: python 键盘记录器.py -i ')
	parser.add_option('-i', dest='interface', type='string', help='specify interface to listen on')
	(options, args) = parser.parse_args()
	if options.interface == None:
		conf.iface = 'MERCURY Wireless N Adapter'
		print(parser.usage)
		print('[*] Starting Sougo Sniffer.')
		sniff(filter='tcp port 80 tcp port 8080', prn=findGoogle)
		# exit(0)
	else:
		conf.iface = options.interface
		try:
			print('[*] Starting Sougo Sniffer.')
			sniff(filter='tcp port 80', prn=findGoogle)
		except KeyboardInterrupt:
			exit(0)


if __name__ == '__main__':
	main()
