import qualysapi 
import sys, datetime 
from lxml import objectify
from datetime import datetime
from datetime import timedelta
import logging
logging.basicConfig()
logger = logging.getLogger('logger')
		
def titulo():
	print ("******************************************************")
	print ("		 				  ")
	print ("		Vulnerabilty Management Team				  ")
	print ("		 				  ")
	print ("******************************************************")		
def purge(days):
	try:
		a = qualysapi.connect('config.ini')
		assets = a.request('/api/2.0/fo/asset/host/',{'action':'list','details':'All/AGs','no_vm_scan_since':days})
		#print(assets)
		root = objectify.fromstring(assets.encode('utf-8'))
		file = open("ips.csv","w+")
		file.write ("******************************************************"+'\n')
		file.write ("		 				  "+'\n')
		file.write ("		Vulnerabilty Management Team				  "+'\n')
		file.write ("		 				  "+'\n')
		file.write ("******************************************************"'\n')
		file.write("IP , NETBIOS ,Last vuln scan"'\n')
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
		print("error", "I don't find data for host not scanned sice "+ days)	
titulo()
day = (datetime.today()  - timedelta(days=int(sys.argv[1])) ).strftime('%Y-%m-%d')
print("Host not scanned sice : "+day)
purge(day)
