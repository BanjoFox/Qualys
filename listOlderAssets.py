#-
# Source URL: https://github.com/SBB-Mx/Qualys
#

#-
# "Fix" for Self-signed certificates in chain.
# Does this actually work?  Should we just remove it?
#
import ssl

try:
	_create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
# Legacy Python that doesn't verify HTTPS certificates by default
	pass
else:
# Handle target environment that doesn't support HTTPS verification
	ssl._create_default_https_context = _create_unverified_https_context

#-
# Original Script
#

import qualysapi 
import sys, datetime 
from lxml import objectify
from datetime import datetime
from datetime import timedelta
import logging
logging.basicConfig()
logger = logging.getLogger('logger')
		
def title():
	#print ("******************************************************")
	#print ("		 				  ")
	#print ("		Vulnerability Management Team				  ")
	#print ("		 				  ")
	#print ("******************************************************")
	print ("*** Query Data ***")
def get_data(days):
	try:
		a = qualysapi.connect('config.ini')
		assets = a.request('/api/2.0/fo/asset/host/',{
			'action':'list',
			'details':'All/AGs',
			'no_vm_scan_since':days,
			'use_tags':'1',
			'tag_set_by':'name',
			'tag_include_selector':'any',
			'tag_set_include':'PRODOPS',
			},verify=False)  # Prevent 'Self-Signed Certificate in Chain' from blocking activity
		
		root = objectify.fromstring(assets.encode('utf-8'))
		file = open("ips.csv","w+")
		#file.write ("******************************************************"+'\n')
		#file.write ("		 				  "+'\n')
		#file.write ("		Vulnerability Management Team				  "+'\n')
		#file.write ("		 				  "+'\n')
		#file.write ("******************************************************"'\n')
		file.write ("*** Query Data ***"'\n')
		file.write("IP , DNSHostname ,LastScanDate"'\n')
		for host in root.RESPONSE.HOST_LIST.HOST:
			#ipList = (host.DNS.text+host.IP.text+","+host.LAST_VULN_SCAN_DATETIME.text+'\n')
			print ('\n'"++++++++++++++++++++++++++++++++++++++++"'\n')
			print ("ID: "+host.ID.text)
			print ("IP: "+host.IP.text)
			file.write(host.IP.text+",")
			try: 
				print ("DNS: "+host.DNS.text)
				file.write(host.DNS.text+",")
			except AttributeError:
				print ("NO DNS ")
				file.write("NO HOSTNAME"+",")
			try: print ("OS: "+host.OS.text)
			except AttributeError:
				print ("No OS")
			print ("Last day scanned: "+host.LAST_VULN_SCAN_DATETIME.text)
			file.write(host.LAST_VULN_SCAN_DATETIME.text+'\n')
			try: 
				print ("Asset group: "+host.ASSET_GROUP_IDS.text)
			except AttributeError: 
				print ("No Asset group")
			print ('\n'"++++++++++++++++++++++++++++++++++++++++"'\n')
		file.close()
	except AttributeError:
		print("error", "I don't find data for host not scanned since "+ days)	
title()
day = (datetime.today()  - timedelta(days=int(sys.argv[1])) ).strftime('%Y-%m-%d')
print("Host not scanned since : "+day)
get_data(day)