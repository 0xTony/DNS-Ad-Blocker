# Welcome to the pre pre alphav4 of my dns proxy ad/malware/pron blocker
# it is an attempt to reduce network traffic, bandwidth, load times, malware, 
# bad things for kids, and ads which I dislike so very much
# You should still use firefox with adblock plus, noscript, ghostery and privacy badger
# but this will help block ads for android and ios devices as well. 
#
# requires a blocklist file with a listing of domains to block
# and a whitelisting file of string to allow in URLs. 
# at the very least make sure an empty file exists. touch whitelist
# to generate the block listing, use the createblocklist.py python script
#
# Config information can be found in the config file
#
# Also, to bind the listening ports, the program needs sudo
#
# you will also need to run the following to install the needed python lib
#
# sudo pip install dnslib
#
# -*- coding: utf-8 -*-
__version__ = "0.0.0.0.4"

from multiprocessing import Process, Manager, Lock, Value
import multiprocessing
import socket

import ConfigParser
import timeit
from time import sleep
#sudo pip install dnslib
from dnslib import *
import sys
import re

# Need to see about getting rid of globals... save for locks...

# needs more work to make better
# also need to write to disk caught URLs
# Need to make the regex list loadable. TODO
RegExList = ""
WhiteList = ""

#block list is a pair, host and count blocked. For now blocked number stays at 0
BlockListDict = { 'initialval':'initial' }

# Mutexes so only one process reads the socket at a time
ClientMutex = Lock()
ServerMutex = Lock()

# reporting globals
PrintSummary = False
#PrintBlocked = False
#PrintServed = False
#PrintTime = False

# Open file and add to contents
def addToFile(filename, data):
	target = open(filename, 'a')
	target.write(data) 
	target.write("\n")  
	target.close()
	
#download list of sources from github 
def readFile(filename):
	target = open(filename, 'r')
	data = target.read()
	target.close()
	return data
	
# load the block list into the dictionary
def loadBlockList(filename):
	i = 0
	data = readFile(filename)
	data=filter(None, data.split('\n')) 
	for line in data: #Simple checking for hostname match
		BlockListDict[line] = 0
		i = i + 1
	print "Loaded " + str(i) + " urls to block"


# load the white list
def loadWhiteList(filename):
	global WhiteList
	WhiteList = readFile(filename)
	WhiteList = filter(None, WhiteList.split('\n')) 
	print "Loaded White List"

# check if the host needs to be blocked.
# return True is needs blocking - else False is ok
def isBlocked(host):
	# strip any www. from the url because the blocklist removed them all
	# TODO, make sure its not www.com ittr = host.count('.') 
	if host.startswith("www."):
		host = host.replace("www.", "") # no longer in host files
	
	# Checking whitelist after a block match is overall faster. 
	# Need to check regex and block cache for all requests no matter what. 
	# Will only his a match on block <20% of the time. White list checking only then 
	# Saves overall performance response rate for the majority of the requests
	if (checkCache(host)): 
		if (checkWhiteList(host)):
			return False
		return True
	if (checkRegEx(host)):
		if (checkWhiteList(host)): 
			return False
		return True
	return False

# returns true if host contains string match. We dont want to block these URLs
def checkWhiteList(host):
	for line in WhiteList: #Simple checking for hostname match
		if line in host:
			print "White List " + line + " matches " + host
			return True
	return False
	
# Check if it matches a regex
# if so, enter it into the block list
# then return failed
# need to write to disk caught URLs

def checkRegEx(host):
	if re.match(RegExList, host):
		print "Blocking Regex " + host
		BlockListDict[host] = 0
		addToFile("regexblock", host)
		return True
	return False
	
# Check the host, and progressively strip the left part of the URL looking for a subdomain match
def checkCache(host):
	ittr = host.count('.') # how far do we go 
	# check if ittr is too high, if so bail because it bogus
	if ittr > 10: return True # more then 10 dots in the request address is bogus, fail.
	while ittr > 0:
		if BlockListDict.get(host) is not None:
			#print "URL in list " + host
			return True
		temp, host = host.split('.', 1)
		ittr = ittr - 1
	return False;

# Craft the packet to send the UDP response of a failure and send
def sendFailedLookup(s, datagram, addr):
	temp=datagram.find('\x00',12)
	packet=datagram[:2] + '\x81\x83' + datagram[4:6] +  '\x00\x00\x00\x00\x00\x00' + datagram[12:temp+5]
	s.sendto(packet, addr)


# Handing incoming DNS requests from clients. 
# First check host file
# Then check regex
# then send to DNS server
def handleClientSocket(client_socket, dns_socket, pending_requests_dict, blocked_urls, served_urls, counter_lock):
	totaltime = 0
	totaltrans = 0

	loadBlockList("blocklist")
	loadWhiteList("whitelist")
	
	clientmutex = ClientMutex # Locals are faster then globals
	
	status = ''
	
	#print "Handle DNS side socket"
	while 1:
		# Currently there is a min of two processes so a mutex is needed. 
		# TODO Run stats to see if a single thread without Mutex is faster then two with mutex
		clientmutex.acquire()
		try:
			datagram, addr = client_socket.recvfrom(1024) # overkill for buffer size for DNS, still should only get 1 packet
			starttime = timeit.default_timer()
			clientmutex.release() #Got the response from the socket, release the mutex and process packet
			host=str(DNSRecord.parse(datagram).q.qname)[0:-1]
			if (isBlocked(host)): 
				printsting = "Blocked URL " + host   #printsting = "Blocked URL %(host)s"   
				sendFailedLookup(client_socket, datagram, addr)
				# If we are doing a counter summary, to get an accurate number, need a global mutuex
				# This can be made faster by making it a local mutex or better removing mutex
				# With no mutux, we might lose some block numbers but even if the numebr isnt perfect, it shouold be ok
				if PrintSummary:
					with counter_lock: #costly operation
						blocked_urls.value += 1 #costly operation
			else :
				# Not blocked so send the packet to the configured DNS server
				# TODO Add caching later. 
				sent = dns_socket.send(datagram)
				printsting = "Served URL  " + host
				lookupval = datagram[0:2].encode('hex') + host
				lookupvalip = lookupval + ":ip"
				lookupvalport = lookupval + ":port"
				ipport = addr[0] + "::" + str(addr[1])

				pending_requests_dict[lookupval] = ipport
				if PrintSummary: 
					with counter_lock: #costly operation
						served_urls.value += 1 #costly operation
			
			transactiontime = timeit.default_timer() - starttime
			print printsting, " for ", addr[0], " with transaction time of ", transactiontime
		except Exception as e:
			print "!!!BAD READ. Error", e # Sometimes the parser cannot handle the incoming packet

	clientmutex.release()
	return

# for now, just receive and reply
# eventually will thread pool the handling to loopup the ip addr
# in a negative list and handle the write out to the socket
def handleDNSSocket(client_socket, dns_socket, pending_requests_dict):
	#print "Handle DNS side socket"
	servermutex = ServerMutex # locals are faster then globals
	
	while 1:
		# Lets get the mutex for this process to proces DNS result
		# TODO If just a single process handlign DNS, no need for mutex
		servermutex.acquire()
		current = multiprocessing.current_process()
		#print "Reading DNS side socket"
		try:
			datagram, addr = dns_socket.recvfrom(1024) # overkill for buffer size for DNS, still should only get 1 packet
		except socket.error, e:
			servermutex.release()
			print "SYSTEM ERROR caught on handleDNSSocket.dns_socket.recvfrom ", e
		else: 			
			servermutex.release() #Got data from the DNS socket, release mutex so others can get and respond dns items
			#print "Got DNS data"
			# Get the DNS info so we can figure out who this response needs to be delivered to
			host=str(DNSRecord.parse(datagram).q.qname)[0:-1]
			#print "Host is " + host
			lookupval = datagram[0:2].encode('hex') + host
			#print "lookupval is " + lookupval
			lookupvalip = lookupval + ":ip"
			lookupvalport = lookupval + ":port"
			#print "Got host " + host + " lookupvalip " + lookupvalip  + " lookupvalport " + lookupvalport 
			# data in dictionary is stored as DNS packet ID + ip address 
			# - with this is stored the return IP address
			# - so we know how to build the return packet
			returnaddr = pending_requests_dict.get(lookupval)
			if returnaddr is None:
				print "SYSTEM ERROR. No dict entry for ADDR: " + lookupval
				# cant fint it, should probably clean up the dictionary... one some long interval
			else:
				try: # a few potentially dangerous calls here
					returnaddr = returnaddr.split('::')
					#make sure values are right - validate
					addr = returnaddr[0], int(returnaddr[1])
					client_socket.sendto(datagram, addr)
					del pending_requests_dict[lookupval]
				except Exception as e:
					del pending_requests_dict[lookupval]
					print "SYSTEM ERROR. caught around handleDNSSocket.client_socket.sendto ", e # need to log
	servermutex.release()
	return

def printStats(blocked_urls, served_urls):
	print "Served " +  str(served_urls) + " URLS, Blocked " + str(blocked_urls) + " attempts so far" 
				

# Main entry point
if __name__ == "__main__":

	# get config file info
	config = ConfigParser.ConfigParser()
	config.read('config')
	# What IP Address to bind to
	listen_address = config.get('config', 'LOCALADDR').split(',', 1)
	# DNS Server to use if a request isn't found
	target_address = config.get('config', 'TARGETDNS').split(',', 1)
	
	# Number threads/processes to serve incoming client requests. Min 2
	client_proc_count = config.getint('config', 'INPROC')
	# Number of threads/process to serve DNS responses back to clients. Min 1
	dns_proc_count = config.getint('config', 'OUTPROC')
	
	# sanity check the process count
	if (client_proc_count < 2) or (client_proc_count > 10):
		client_proc_count = 2
	if (dns_proc_count < 1) or (dns_proc_count > 5):
		dns_proc_count = 1
	
	print client_proc_count, " ", dns_proc_count
		
	if 'True' in config.get('reporting', 'SUMMARY'): PrintSummary = True
	# TODO support reporting options 
	#if 'True' in config.get('reporting', 'BLOCKED'): PrintBlocked = True
	#if 'True' in config.get('reporting', 'SERVED'): PrintServed = True
	#if 'True' in config.get('reporting', 'TIME'): PrintTime = True
	
	# Get regex of blockable items
	RegExList = config.get('regex', 'REGEXLIST')
	
	# set up sync items for multi processes
	mgr = Manager()
	pending = mgr.dict() # so multiple processes can share the same structure for simple MPI
	blocked_urls = Value('i', 0)  # defaults to 0
	served_urls = Value('i', 0)  # defaults to 0
	counter_lock = Lock()

	# make socket connections
	# TODO support multiple DNS entries
	target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	target.connect((target_address[0], int(target_address[1])))
	client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		client.bind((listen_address[0], int(listen_address[1])))
	except socket.error, err:
		print "Couldn't bind server on %r" % (listen_address, )
		time.sleep(1)
		raise SystemExit

	# Launching processes results in a system running much faster than threads but need to clean up the launcher
	for i in range(0,client_proc_count):
		process = Process(target=handleClientSocket, args=(client, target, pending, blocked_urls, served_urls, counter_lock))
		process.start()

	for i in range(0,dns_proc_count):	
		process = Process(target=handleDNSSocket, args=(client, target, pending))
		process.start()

	while 1:
		if PrintSummary: printStats(blocked_urls.value, served_urls.value)
		sleep(30)
	
	print "Done"
