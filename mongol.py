#!/usr/bin/env python

import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def ackattack(host):
        port = RandNum(1024,65535)

        ack = IP(dst=host, ttl=(1,255))/TCP(sport=port, dport=80, flags="A")
        ans,unans = sr(ack, timeout=4)

	retdata = ""
        for snd,rcv in ans:
		print rcv.summary()
                endpoint = isinstance(rcv.payload, TCP)
                retdata += "%s %s %s\n" % (snd.ttl,rcv.src,endpoint)
                if endpoint:
                        break
	return retdata


MESSAGE = "GET %s HTTP/1.1" + "\x0d\x0a" + "Host: %s" + "\x0d\x0a\x0d\x0a"
hostnames = ["thinkshop.cn", "d.cn"]
port = 80

for host in hostnames:
	# first we create a real handshake and send the censored term
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	# why 5 seconds?  idk you got a better idea?
	s.settimeout(5)

	try:
		ipaddr = socket.gethostbyname(host)
	except socket.gaierror:
		print "Could not resolve " + host
		continue

	try:
		s.connect((ipaddr, port))
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
		traceNoFW = ackattack(ipaddr)

		# possibly a delay from the IDS to reaction time
		time.sleep(1)

		print "Sending stimulus"		
		s.send(MESSAGE % ("/tibetalk", host) )

		try:
			response = s.recv(1024)
		except socket.error:
			print "Found a filter\n\n"
			traceFW = ackattack(ipaddr)
			print "\n\nIPADDR: " + ipaddr
			print "Without FW:\n\n"
			print traceNoFW
			print "\n\nWith FW:\n\n"
                	print traceFW
		else:
			#print response
			print "Appears not to be blocking"

	else:
		print "Bad response code from " + host
		continue

