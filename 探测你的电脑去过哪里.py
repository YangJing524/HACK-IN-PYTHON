# !/usr/bin/python
# coding=utf-8
# Time:20220807
# author:YANG-JING


from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq

# interfacs = 'WLAN'
interfacs = 'MERCURY Wireless N Adapter'
# interfacs='eth0'
probeReqs = []


def sniffProbe(p):
	if p.haslayer(Dot11ProbeReq):
		netName = p.getlayer(Dot11ProbeReq).info
		if netName not in probeReqs:
			probeReqs.append(netName)
			print('[+] Detect New probeRequest:' + netName)


sniff(iface=interfacs, prn=sniffProbe)
