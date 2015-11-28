# DNS-Ad-Blocker
Filter Ads, Malware and even adult sites (configurable) - a python based, DNS server you can run on your local network.

Welcome to the pre pre alphav4 of my dns proxy ad/malware/pron blocker.
The default block list includes ads, trackers and malware sites; adult site
blocking can be easily added via the config file.
It is an attempt to reduce network traffic, bandwidth, load times, malware, 
bad things for kids, and tracking ads, which I dislike so very much.
The project includes a script to build a listing of identified hosts/urls to block. 
The dnsproxy will also block urls via a configurable grep string.
Last, any blocked URLs will be checked against a white list of sites you configure to allow. 

You should still use firefox with adblock plus, noscript, ghostery and privacy badger
but this will help block ads for android and ios devices as well. 

The project is written in python - something I wanted to play with while learning
a new programing language. It is designed to work with Python 2.7 and higher and
run on both Linux and OSX.

The proxy is designed to be fast; on a first gen, core 2 mobile processor (test laptop), 
total processing time is sub millisecond.

Please note: this assumes the reader has some knowledge about programming, networking,
Linux/OSX, and hopefully some python. 

Before Running:
First, download the following files: 
createblocklist.py = This file uses sources to download various lists of URLs
to block and will create a file blocklist that the dns filter uses.

sources = This file contains a listing of resources used to create the blocklist.
If you find any other good sources, please let me know. Add and/or remove sources
as you desire. 

dnsproxy.py = This is the DNS proxy, it accepts DNS requests, looks them up against
the valued in the blocklist. If a match is found, it returns to the requester
a DNS response that the URL is not valid. If no match is found, it requests
the DNS entry from the configured DNS server, gets and returns the response. 
config = This file holds the configuration information used by dnsproxy. It includes
information such as the local IP address to bind, the DNS server to use, etc
 
whitelist = This file contains a listing of strings, that if match as a substring of 
a URL, will allow the request and prevent any blocking. 

config = Configuration used by the dnsproxy to set the listening ip address, the DNS server
to send requests, URL blocking grep string, etc.

dnsproxy.py requires the installation of the dnslib python package. This can be installed
by running:
sudo pip install dnslib
If you do not have pip installed, there are multiple resources available by search.

Steps to Run
1. Edit the sources file as needed.  (instructions in the file itself)
2. run createblcoklist.py via the following command
python createblocklist.py
This will take a few minutes to download all the sources and parse/prune the information
At the end, there should be a file called blocklist that should be a non-zero size. 
3. Edit the whitelist file as needed. (instructions in the file itself)
4. Edit the config file as needed. (instructions in the file itself)
5. Run the DNS proxy via the following command
sudo python dnsproxy.py
The program requires sudo to bind the listening address/port. 
6. Point your client's DNS entries to the bound IP address.

To stop the dnsproxy, use control-C
