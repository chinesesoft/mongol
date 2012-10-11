from scapy.all import *
import socket
import logging

def ackattack(host):
	loggin.getLogger("scapy.runtime").setLevel(logging.ERROR)
	ipaddr = socket.gethostbyname(host)
	port = RandNum(1024,65535)

        ack = IP(dst=ipaddr, ttl=(1,255))/TCP(sport=port, dport=80, flags="A")
        ans,unans = sr(ack, timeout=4)
	
	for snd,rcv in ans:
		endpoint = isinstance(rcv.payload, TCP)
		print snd.ttl, rcv.src, endpoint
		if endpoint:
			break

host = "thinkshop.cn"
port = 80
MESSAGE = "GET %s HTTP/1.1" + "\x0d\x0a" + "Host: %s" + "\x0d\x0a\x0d\x0a"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
	s.connect((host, port))
except socket.timeout:
        print "connection to " + host + " has timedout moving on"
s.send(MESSAGE % ("/", host))
response = s.recv(1024)
print response
