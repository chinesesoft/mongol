#!/usr/bin/env python

import socket

def ackattack(host):
	from scapy.all import *

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


MESSAGE = "GET %s HTTP/1.1" + "\x0d\x0a" + "Host: %s" + "\x0d\x0a\x0d\x0a"
hostnames = ["thinkshop.cn"]
port = 80

for host in hostnames:
	# first we create a real handshake and send the censored term
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	# why 5 seconds?  idk you got a better idea?
	s.settimeout(5)
	try:
		s.connect((host, port))
	except socket.timeout:
		print "connection to " + host + " has timedout moving on"
	s.send(MESSAGE % ("/", host))
	
	try:
		response = s.recv(1024)
	except socket.timeout:
		print "connection to " + host + " has timedout moving on, Possibly not a webserver"
		continue
	except socket.error:
		print "RST: Possibly already blocked"
		continue

	if response.find("200 OK") != -1:
		# http://en.wikipedia.org/wiki/List_of_blacklisted_keywords_in_the_People%27s_Republic_of_China
		# tibetalk
		s.send(MESSAGE % ("/tibetalk", host) )

		try:
			response = s.recv(1024)
		except socket.error:
			print "Found a filter"
			ackattack(host)

	else:
		print "Bad response code from " + host
		continue

