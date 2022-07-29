import argparse, csv
from lxml import objectify

import qualysapi 

#-
# Initialize variables
#
DATA_FILE = "bulk_test.csv"
args = []


#-
# Build dictionary
#
def build_dict_from_file(input_file):
   with open(input_file, newline='') as csvfile:
      reader = csv.DictReader(csvfile)
   return reader


def purge_asset_data(reader):
   purge_list = ",".join([row["IP"] for row in reader])
   
   #Debug/testing ONLY
   print(ips_to_purge)
#	try:
#     a = qualysapi.connect('config.ini')
#		assets = a.request('/api/2.0/fo/asset/host/',{
#         'action':'purge',
#         'data_scope':'pc,vm',
#			'ips':purge_list,
#			},verify=False)  # Prevent 'Self-Signed Certificate in Chain' from blocking activity
#	except AttributeError:
#		print("error", "Can't find the data")


