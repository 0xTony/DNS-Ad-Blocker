# -*- coding: utf-8 -*-
__version__ = "0.0.0.0.4 Pre Alpha Alpha"
__author__ = "Tony Martin 0xTony"

# Creating a host file for blocking ads
# This program will grab the host files from the sources file,
# download and merge them into a single file for DNS based blocking

import sys
import urllib2
import subprocess
import hashlib
import zipfile,os
import tarfile

# a few of the sources need use agent headers or the close the connection
headers = { 'User-Agent' : 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.6) Gecko/20070802 SeaMonkey/1.1.4' }

# TODO remove all substring matches. will need to add a . before and then check
            
# Trash old file and overwrite with new contents
def writeToFile(filename, data):
	target = open(filename, 'w')
	target.truncate() 
	target.write(data)  
	target.close()

# Trash old file and overwrite with new contents
def addToFile(filename, data):
	target = open(filename, 'a')
	target.write(data)  
	target.close()

#download list of sources from github 
def getSources():
	response = urllib2.urlopen(sourcelist)
	return response.read()
	
	
#download list of sources from github 
def readFile(filename):
	target = open(filename, 'r')
	data = target.read()
	target.close()
	return data

def unzipData(data, line):

	if line.endswith(".zip"):
		writeToFile("tempzipdata.zip", data)
		file = zipfile.ZipFile("tempzipdata.zip", "r")
		for name in file.namelist():
			# there should only be one name, if there are more, ignore
			data = file.read(name)
			os.remove("tempzipdata.zip")
			return data
	if line.endswith(".gz"):
		writeToFile("tempzipdata.tar.gz", data)
		t = tarfile.open('tempzipdata.tar.gz', 'r:gz')
		print t.getnames()
		print t.getmembers()
		for member in t.getmembers():
			print member.name
			if member.name == "adult/domains":
				try:
					f = t.extractfile(member.name)
				except KeyError:
					print 'ERROR: Did not find %s in tar archive' % filename
				else:
					print member.name
					# there should only be one name, if there are more, ignore
					data = f.read()
					os.remove("tempzipdata.tar.gz")
					return data
	
# With the list of source host files, download each and save
# if the file doesnt download - it will use the old file so not data lost on the latest. 
# will download contents into a file sources-xyz
# boolean operators if include in filtering (ms and porn)
def downloadSources(sources, porn, ms):
	data = ""
	for line in sources.splitlines():

		#print line

		if not line.startswith("#") and len(line) > 1:
			#if ".zip" in line:			
			data = ''
			# get data. if it exists, overwrite source file - else if error it wil use old
			try:
				req = urllib2.Request(line, None, headers)
				data = urllib2.urlopen(req).read()
				
				if line.endswith(".zip") or line.endswith(".gz"):
					print "Got zip " + line
					data = unzipData(data, line)
					sourcehash = "source-adult" + hashlib.md5(line).hexdigest()[:8] # for file name
				else:
					sourcehash = "source-" + hashlib.md5(line).hexdigest()[:8] # for file name

				data = data.replace('127.0.0.1', '')
				data = data.replace('0.0.0.0', '')
				data = data.replace("\r", "\n")
				data = data.replace("\t", "")
				data = data.replace(" ", "")
				print "Downloaded " + line + " saving data to file " + sourcehash 
				writeToFile(sourcehash, data)
			except urllib2.URLError, e:
				print "An error %s " %e
				print line
			except:
				print "Bad Source for line " + line

	
# Take all source-* files, merge and remove duplicates and remove unwanted data
def mergeSources():	
	# Merge the files and filter out unwanted data 
	print "Merging Ads"
	process = subprocess.Popen('sort -u source-* | grep -v "#" | grep -v "localhost" | grep -v "broadcasthost"  > tempblocklist',
                             shell=True,stdout=subprocess.PIPE)
    #force a wait for Popen to finish
	process.communicate()

# load the block list into the dictionary
def loadBlockList(filename):
	i = 0
	data = readFile(filename)
	data=filter(None, data.split('\n')) 
	for line in data: #Simple checking for hostname match
		BlockListDict[line] = 0
		i = i + 1
	print "Loaded " + str(i) + " urls to block"

def subUrlInDict(block_list_dict, host):
	ittr = host.count('.') # how far do we go 
	if ittr > 1: # not a base URL
		temp, host = host.split('.', 1)
		ittr = ittr -1
		while ittr > 0:
			if block_list_dict.get(host) is not None:
				#print "URL in list " + host
				return True
			temp, host = host.split('.', 1)
			ittr = ittr - 1
	return False
		
def isIpAddr(host):
    split_count = host.split('.')
    if len(split_count) != 4: return False
    try: return all(0<=int(p)<256 for p in split_count)
    except ValueError: return False
    
# if we are already blocking crappyads.com then there is not need
# have entries for adseverX.crappyads.com, etc 
def deDupBlockList():

	block_list_dict = {}
	dedup_block_list = ""
	writeToFile("tempremoveurls", dedup_block_list)
	i = 0
	data = readFile("tempblocklist")
	data=filter(None, data.split('\n')) 
	for host in data: #Simple checking for hostname match
		if host.startswith("www."):
			host = host.replace("www.", "") # simplify the search
		block_list_dict[host] = 0
		i = i + 1

	print "De-dupping " + str(i) + " URLs. This may take some time"

	i = 0
	for host in data: #Simple checking for hostname match
		if host.startswith("www."):
			host = host.replace("www.", "") # simplify the search
		if not subUrlInDict(block_list_dict, host) and not isIpAddr(host):
			# not in the list, add to master list
			dedup_block_list = dedup_block_list + "\n" + host
		i = i + 1
		if i > 10000:
			i = 0
			sys.stdout.write('.')
			sys.stdout.flush()
			addToFile("tempremoveurls", dedup_block_list)
			dedup_block_list = "\n"

	addToFile("tempremoveurls", dedup_block_list)
					
	print "Writing final blocklist"
	process = subprocess.Popen('sort -u tempremoveurls > blocklist',
                             shell=True,stdout=subprocess.PIPE)
    #force a wait for Popen to finish
	process.communicate()

def cleanUp():
	# leave the source-* files. This way, if on a refresh, the block list is
	# not available, the prior version can still be used. 
	os.remove("tempremoveurls")
	os.remove("tempblocklist")
		

# Main program entry here
def main(argv):

	downloadSources(readFile("sources"), True, False)
	mergeSources() 
	deDupBlockList()   
	cleanUp()

if __name__ == "__main__":
  main(sys.argv[1:])
  print("Done")


