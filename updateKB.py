# encoding:utf-8
#-
# Pull in csv file of tickets and make API calls to back-end 
# KnowledgeBase API for updating solution comments
#
# Created by B. Fox 7/28/2022 
#

import csv, os, qualysapi
from datetime import datetime, date
from lxml import objectify

#-
# Initialize variables
#
DATA_FILE = "ticket_test.csv"
getday = date.today()
today = getday.strftime('%Y-%m-%d')

def main():

   worker = parseCSV()
   
#-
# Build dictionary, then convert that into a comma-separated list that is usable by the API
#
def parseCSV():
   
   # Build log file
   file = open("processed_qids-" + today +".csv","w+")
   file.write("QID,Ticket,Date Modified,Comment"'\n')
    
   with open(DATA_FILE, 'r') as csvfile:
      ticket_list = csv.DictReader(csvfile)
      for row in ticket_list:
         try:
            qid = row['QID']
            ticket = row['Ticket']
            kb_call = callAPI(qid,ticket)
            
            # Objectify the XML to log responses --> https://lxml.de/objectify.html   
            xml_root = objectify.fromstring(kb_call.encode('utf-8'))          
           
            # Log the KB update
            file.write(qid+","+ticket+","+today+","+xml_root.RESPONSE.TEXT.text+","+"\n")
            #file.write(qid+","+ticket+","+today+", Custom Vuln Data has been updated successfully"+"\n")
            
         except:
            file.write(qid+","+ticket+","+today+xml_root.RESPONSE.TEXT.text+"\n")
            #file.write(qid+","+ticket+","+today+", ERROR"+"\n")
            #print("There was an issue")
            print(xml_root.RESPONSE.TEXT.text)
          
   file.close()

#-
# API Call
#
def callAPI(qid,ticket):
   a = qualysapi.connect('config.ini')
   kb_call = a.request('/api/2.0/fo/knowledge_base/vuln/',{
         'action':'edit',
         'qid':qid,
         'solution_comment':'Jira Ticket: ' + ticket,
      },verify=False)  # Prevent 'Self-Signed Certificate in Chain' from blocking activity
   
   # Print Full API response
   #print(kb_call) - DEBUGGING?
   return kb_call
#-
# Run the code
#
if __name__ == "__main__":
    main()