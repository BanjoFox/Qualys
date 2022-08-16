
# encoding:utf-8
# **Owned by Squaretrade Security Operations team**
# https://github.squaretrade.com/secops/qualys_api_scripts
#
# Pull in csv file of tickets and make API calls to backend 
# KnowledgeBase API for updating solution comments
#
# Created by P. Alexander 7/28/2022 
#

import csv, os, qualysapi
from datetime import datetime, date
from lxml import objectify
#from pyramid.paster import get_app
#from waitress import serve

#-
# Initialize variables
#
#qualys_password = os.environ['qualys_password']
DATA_FILE = "ticket_test.csv"
getday = date.today()
today = getday.strftime('%Y-%m-%d')

def main():

   worker = parse_csv(kb_call)
   
#-
# Build dictionary, then convert that into a comma-separated list that is usable by the API
#
def parse_csv(kb_call):
   
   # Build log file
   file = open("processed_qids-" + today +".csv","w+")
   file.write("QID,Ticket,Date Modified"'\n')
      
   root = objectify.fromstring(kb_call.encode('utf-8'))
   
   with open(DATA_FILE, 'r') as csvfile:
      ticket_list = csv.DictReader(csvfile)
      for row in ticket_list:
         try:
            qid = row['QID']
            ticket = row['Ticket']
            callAPI(qid,ticket)
            # Log the KB update
            file.write(qid+","+ticket+","+root.RESPONSE.TEXT.text+","+today+"\n")
            
         except:
            #print("ERROR: "+qid+" Is invalid")
            file.write(qid+","+ticket+","+root.RESPONSE.TEXT.text+"\n")
   file.close()

#-
# API Call
#
def callAPI(qid,ticket):
   a = qualysapi.connect('config.ini')
#   serve(app, host='0.0.0.0', port=8000, threads=50)
   kb_call = a.request('/api/2.0/fo/knowledge_base/vuln/',{
         'action':'edit',
         'qid':qid,
         'solution_comment':'Jira Ticket: ' + ticket,
      },verify=False)  # Prevent 'Self-Signed Certificate in Chain' from blocking activity
   
   # Print Full API response
   #print(kb_call)
   return kb_call
#-
# Run the code
#
if __name__ == "__main__":
    main()
