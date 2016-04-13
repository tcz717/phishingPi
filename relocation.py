#!/usr/bin/python

import os
from scapy.all import *
import dpkt
import pcap
import time, threading
import socket
import logging

logging.basicConfig(level=logging.INFO)

str2ip= lambda x:'%c%c%c%c'%tuple(map(int,x.split('.')))
def mac16(mac):
	return '%x:%x:%x:%x:%x:%x' % tuple(map(int,mac.split(':')))

try:
	def http_handle(req,smac,dmac,sip,dip,spo,dpo):
		print str(req)


	def dns_handle(req,smac,dmac,sip,dip,spo,dpo):
		if not isinstance(req,dpkt.dns.DNS):
			return
		logging.info('get a DNS pack')
		if req.qr==dpkt.dns.DNS_Q and req.opcode==dpkt.dns.DNS_QUERY\
		and len(req.qd)==1 and len(req.an)==0 and len(req.ns)==0\
		and req.qd[0].cls==dpkt.dns.DNS_IN and req.qd[0].type==dpkt.dns.DNS_A:
			
			req.op = dpkt.dns.DNS_RA
			req.rcode = dpkt.dns.DNS_RCODE_NOERR
			req.qr = dpkt.dns.DNS_R

			arr = dpkt.dns.DNS.RR()
			arr.cls = dpkt.dns.DNS_IN
			arr.type = dpkt.dns.DNS_A
			arr.name = req.qd[0].name
			arr.rdata = str2ip('10.0.0.1')
			arr.rlen=4
			req.an.append(arr)

			pkt=IP(src=dip,dst=sip)/UDP(sport=dpo,dport=spo)/Raw(str(req))
			pkt.summary()

			send(pkt,iface="wlan0")

			print '---------dns replyed---------'
		else:
			logging.info('DNS pack not matches')

	def tcp_trip(ip):
		logging.info('get a tcp pack')
		pk=IP(str(ip))
		if pk.dst=='97.98.99.100' and pk.flags==2:
			logging.info('first shack')
			rep=\
			IP(src=pk.dst,dst=pk.src)/\
			TCP(sport=pk.payload.dport,dport=pk.payload.sport,seq=233,\
			ack=pk.payload.seq+1,flags='SA')

			send(rep,iface="wlan0")

	def tcplink(sock, addr):
	    print 'Accept new connection from %s:%s...' % addr
	    data = sock.recv(1024)
	    time.sleep(1)
	    if data.startswith('GET'):
			http=dpkt.http.Response()
			http.reason='Moved temporarily'
			http.status=302
			http.headers['Location']='http://10.0.0.1:8000'
			sock.send(str(http))
	    sock.close()
	    print 'Connection from %s:%s closed.' % addr
	def http_listener():
		print 'http start'
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind(('10.0.0.1', 80))
		s.listen(5)
		while True:
			sock, addr = s.accept()
			t = threading.Thread(target=tcplink, args=(sock, addr))
			t.start()

	wlan=pcap.pcap("wlan0")

	id=0

	t = threading.Thread(target=http_listener)
	t.start()

	for rtime,pack in wlan:
		id=id+1
		ep=dpkt.ethernet.Ethernet(pack)
		smac='%d:%d:%d:%d:%d:%d'%tuple(map(ord,list(ep.src)))
		dmac='%d:%d:%d:%d:%d:%d'%tuple(map(ord,list(ep.dst)))

		if isinstance(ep.data,dpkt.arp.ARP):
			ap=ep.data
		elif isinstance(ep.data,dpkt.ip.IP):
			ip=ep.data
			sip='%d.%d.%d.%d'%tuple(map(ord,list(ip.src)))
			dip='%d.%d.%d.%d'%tuple(map(ord,list(ip.dst)))
			if isinstance(ip.data,dpkt.icmp.ICMP):
				print '[icmp]'
			elif isinstance(ip.data,dpkt.udp.UDP):
				up=ip.data
				sport=up.sport
				dport=up.dport
				if up.dport == 53:
					dns_handle(dpkt.dns.DNS(up.data),smac,dmac,sip,dip,sport,dport)
			elif isinstance(ip.data,dpkt.tcp.TCP):
				tp=ip.data
				sport=tp.sport
				dport=tp.dport
				if tp.dport == 80 and tp.data.startswith('GET'):
					http_handle(tp.data,smac,dmac,sip,dip,sport,dport)
except KeyboardInterrupt:
    import sys
    sys.exit()
