#!/usr/bin/python

import os
from scapy.all import *
import dpkt
import pcap
import time

def http_handle(req,smac,dmac,sip,dip,spo,dpo):
	if(dip!='10.0.0.1'):
		http=dpkt.http.Response()
		http.reason='Moved temporarily'
		http.status=302
		http.headers['Location']='http://10.0.0.1'
		pkt=Ether(src=dmac,dst=smac)/IP(src=dip,dst=sip)/TCP(sport=dpo,dport=spo)/Raw(str(http))
		send(pkt,iface="wlan0")


wlan=pcap.pcap("wlan0")

id=0

for rtime,pack in wlan:
	id=id+1
	print "["+str(id)+"]"+time.ctime(rtime)
	ep=dpkt.ethernet.Ethernet(pack)
	smac='%d:%d:%d:%d:%d:%d'%tuple(map(ord,list(ep.src)))
	dmac='%d:%d:%d:%d:%d:%d'%tuple(map(ord,list(ep.dst)))
	print "[ether] "+smac+" -> "+dmac

	if isinstance(ep.data,dpkt.arp.ARP):
		ap=ep.data
		sip='%d.%d.%d.%d'%tuple(map(ord,list(ap.spa)))
		dip='%d.%d.%d.%d'%tuple(map(ord,list(ap.tpa)))
		qmac='%d:%d:%d:%d:%d:%d'%tuple(map(ord,list(ap.sha)))
		rmac='%d:%d:%d:%d:%d:%d'%tuple(map(ord,list(ap.tha)))
		print '[arp] op=%d'%ap.op
		print 'src: %s\t%s'%(sip,qmac)
		print 'dst: %s\t%s'%(dip,rmac)
	elif isinstance(ep.data,dpkt.ip.IP):
		ip=ep.data
		sip='%d.%d.%d.%d'%tuple(map(ord,list(ip.src)))
		dip='%d.%d.%d.%d'%tuple(map(ord,list(ip.dst)))
		print '[ip] %s -> %s len=%d'%(sip,dip,ip.len)
		if isinstance(ip.data,dpkt.icmp.ICMP):
			print '[icmp]'
		elif isinstance(ip.data,dpkt.udp.UDP):
			print '[udp]'
		elif isinstance(ip.data,dpkt.tcp.TCP):
			print '[tcp]'
			tp=ip.data
			sport=tp.sport
			dport=tp.dport
			if isinstance(tp.data,dpkt.http.Request):
				http_handle(tp.data,smac,dmac,sip,dip,sport,dport)
		else:
			print type(ip.data)
	else:
		print type(ep.data)
	print
