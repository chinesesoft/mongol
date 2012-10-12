from scapy.all import *
import socket
import logging

def ackattack(host):
	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
	ipaddr = socket.gethostbyname(host)
	port = RandNum(1024,65535)

        ack = IP(dst=ipaddr, ttl=(1,145))/TCP(sport=port, dport=80, flags="A")
        ans,unans = sr(ack, timeout=4)
	
	for snd,rcv in ans:
		print rcv.summary()
		endpoint = isinstance(rcv.payload, TCP)
		print snd.ttl, rcv.src, endpoint
		if endpoint:
			break

ackattack("thinkshop.cn")
