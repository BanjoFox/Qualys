import qualysapi 
import sys 
from lxml import objectify

import logging
logging.basicConfig()
logger = logging.getLogger('logger')
#def conection():
#	a = qualysapi.connect('config.ini')

def titulo():
	print ("******************************************************")
	print ("		 				  ")
	print ("		Vulnerabilty Management Team				  ")
	print ("		 				  ")
	print ("******************************************************")
		
class search:
	## se define el constructor
	def __init__(self,ip):
		self.ip = ip

	def search_ip(self):
		try:
			a = qualysapi.connect('config.ini') #conexion a la API de Qualys
			reportScans = a.request('/api/2.0/fo/asset/host/',{'action':'list','details':'All','ips':(self.ip)})
			#print (reportScans)# Activar solo para troubleshoting
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
				try:# Validar DNS
					print ("DNS: "+host.DNS.text)
				except AttributeError:
					print ("No DNS")
				print ("OS: "+host.OS.text)
				try:# Validar hostname
					print ("NETBIOS: "+host.NETBIOS.text)
				except AttributeError:
					print ("No Netbios")
				print ("ID: "+host.ID.text)
				try:# validad ultimo scan
					print ("LAST VULN SCAN: "+host.LAST_VULN_SCAN_DATETIME.text)
				except AttributeError:
					print ("No last vuln info")
				print ("----------------------------------------")
				print ('\n'"++++++++++++++++++++++++++++++++++++++++"'\n')
				#return host.IP.text		
	def delete_ip(self):	
		try:
			a = qualysapi.connect('config.ini')#conexion a la API de Qualys
			#reportScans = a.request('/api/2.0/fo/asset/host/',{'action':'purge','echo_request':'1','ips':(self.ip)})
			reportScans = a.request('/api/2.0/fo/asset/host/',{'action':'purge','ips':(self.ip)})
			### solo para debuging
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
		a = qualysapi.connect('config.ini')#conexion a la API de Qualys
		reportScans = a.request('/api/2.0/fo/asset/ip/',{'action':'add','details':'All','ips':(self.ip),'enable_vm':'1'})
### Valida argumentos

### se llama la funcion titulo 
titulo()
### se valida los datos de entrada -s or -d
if len(sys.argv) != 1:
	if sys.argv[1] == "-s":
		### se llama la clase search y se le pasa el argumento
		cs = search(sys.argv[2])
		cs.search_ip()
	elif sys.argv[1] == "-d":
		answ = raw_input("Do you want to delete this host? " +sys.argv[2]+ ",  y " "or" " n "'\n')
		if answ == "y":
			### se llama la funcion delete_ip y se le pasa el argumento
			cs = search(sys.argv[2])
			cs.delete_ip()
			#print("Deleted")
		## se cancela cuando es n
		elif answ == "n":
			print ("Action Cancelled")
		## se cancela si no es escribe n o y
		elif answ != ["y","n"]:
			print ("Action cancelled [Input Erro]")
	elif sys.argv[1] != ["-s","-d"]:
		# se valida el uso de -s or -d
		print("You have to use -s (Search) or -d (Delete)")
else:	
	## se valida que se escriba una ip
	print("please add valid IP address")
