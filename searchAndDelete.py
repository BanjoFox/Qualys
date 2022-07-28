#-
# Source URL: https://github.com/SBB-Mx/Qualys
#

import qualysapi 
import sys 
from lxml import objectify

import logging
logging.basicConfig()
logger = logging.getLogger('logger')


def title():
	print ("******************************************************")
	print ("		 				  ")
	print ("		Vulnerabilty Management Team				  ")
	print ("		 				  ")
	print ("******************************************************")
		
class search:
	## constructor is defined
	def __init__(self,ip):
		self.ip = ip

	def search_ip(self):
		try:
			a = qualysapi.connect('config.ini') # Connection to Qualys API
			reportScans = a.request('/api/2.0/fo/asset/host/',{
				'action':'list',
				'details':'All',
				'ips':(self.ip)
				},verify=False)  # Prevent 'Self-Signed Certificate in Chain' from blocking activity
			
			#print (reportScans) ## Enable for troubleshooting ONLY 
			root = objectify.fromstring(reportScans.encode('utf-8'))
			print(root.RESPONSE.HOST_LIST.HOST)	
		except AttributeError:
			print ('\n'"++++++++++++++++++++++++++++++++++++++++"'\n')
			print ("host "+ self.ip + " is not on Qualys")			
			print ('\n'"++++++++++++++++++++++++++++++++++++++++"'\n')
		else:						
			for host in root.RESPONSE.HOST_LIST.HOST:
				print ("++++++++++++++++++++++++++++++++++++++++"'\n')
				print ("Server Information "'\n')
				print ("----------------------------------------")
				print ("IP: "+host.IP.text)
				try: # Validate DNS
					print ("DNS: "+host.DNS.text)
				except AttributeError:
					print ("No DNS")
				print ("OS: "+host.OS.text)
				try: #Validate Hostname
					print ("NETBIOS: "+host.NETBIOS.text)
				except AttributeError:
					print ("No Netbios")
				print ("ID: "+host.ID.text)
				try: # Validate Last Scan
					print ("LAST VULN SCAN: "+host.LAST_VULN_SCAN_DATETIME.text)
				except AttributeError:
					print ("No last vuln info")
				print ("----------------------------------------")
				print ('\n'"++++++++++++++++++++++++++++++++++++++++"'\n')
				# Return host.IP.text		
	def delete_ip(self):	
		try:
			a = qualysapi.connect('config.ini') # Connection to Qualys API
			#--v This is probably safe to delete
			#reportScans = a.request('/api/2.0/fo/asset/host/',{'action':'purge','echo_request':'1','ips':(self.ip)})
			reportScans = a.request('/api/2.0/fo/asset/host/',{
				'action':'purge',
				'ips':(self.ip)
				},verify=False)  # Prevent 'Self-Signed Certificate in Chain' from blocking activity
			## For debugging Only
			#print (reportScans)
			root = objectify.fromstring(reportScans.encode('utf-8'))
			print(root.RESPONSE.BATCH_LIST.BATCH.ID_SET.ID)
		except AttributeError:
			print ("++++++++++++++++++++++++++++++++++++++++"'\n')
			print("Error Code " +  root.RESPONSE.BATCH_LIST.BATCH.CODE.text)
			print("Description "+root.RESPONSE.BATCH_LIST.BATCH.TEXT.text + '\n')
			print ("++++++++++++++++++++++++++++++++++++++++")
		else:
			for host in root.RESPONSE.BATCH_LIST.BATCH:
				print(host.TEXT.text)
				print(host.ID_SET.ID.text)
	def add_ip(self):
		a = qualysapi.connect('config.ini') # Connection to Qualys API
		reportScans = a.request('/api/2.0/fo/asset/ip/',{
			'action':'add',
			'details':'All',
			'ips':(self.ip),
			'enable_vm':'1'
			},verify=False)  # Prevent 'Self-Signed Certificate in Chain' from blocking activity

### Validate Arguments
### Call the title() function
title()

### Validate input data; '-s' or '-d'
if len(sys.argv) != 1:
	if sys.argv[1] == "-s":
		### Call the search class and pass it the argument
		cs = search(sys.argv[2])
		cs.search_ip()
	elif sys.argv[1] == "-d":
		answ = input("Do you want to delete this host? " +sys.argv[2]+ ",  y " "or" " n "'\n')
		if answ == "y":
			### Call the function delete_ip and pass it the argument
			cs = search(sys.argv[2])
			cs.delete_ip()
			#print("Deleted")
		## Cancel when 'n'
		elif answ == "n":
			print ("Action Cancelled")
		## Cancel if not 'n' or 'y' 
		elif answ != ["y","n"]:
			print ("Action cancelled [Input Error]")
	elif sys.argv[1] != ["-s","-d"]:
		# Validate use of '-s' or '-d'
		print("You have to use -s (Search) or -d (Delete)")
else:	
	## Validate that an IP is given
	print("please add valid IP address")
