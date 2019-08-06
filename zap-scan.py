# A helpful reference: https://github.com/zaproxy/zaproxy/wiki/ApiPython
import time
import os
import sys
import urllib2
from pprint import pprint
from zapv2 import ZAPv2

# The value of api must match api.key when running the daemon
api = "<CHANGE-ME>"


def banner():
	print "____________________ZAP SCAN Beta v0.01____"
	print "---------------------------------------by:es0----"


#The following line must be the ip of where ZAP is, so for us it is localhost:8090
#Also if you are not running ZAP on port 8080 then you must include the line below 
#with the correct port numbers.

zap = ZAPv2(apikey = api, proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})



def progress(count, total, status=''):
	bar_len = 60
	filled_len = int(round(bar_len * count / float(total)))
	
	percentage = round(100.0 * count / float(total), 1)
	bar = '=' * filled_len + '-' * (bar_len - filled_len)
	sys.stdout.write('[%s] %s%s....%s\r' % (bar, percentage, '%', status))
	sys.stdout.flush()

# The script must be loaded prior to importing the context otherwise it will fail.

# Additionally, the APIKEY must be the last parameter on every method.

# Importing the context using the full file path.

print("IMPORTING CONTEXT")

zap.context.import_context('${workspace}/sbir-security/sbir.context', apikey = api)

def access_target(targetIP):
	# The URL must be opened before it can be tested on.

	print('Accessing target %s' % targetIP)

	zap.urlopen(targetIP)

	time.sleep(2)

def spider_target(targetIP):
	# Start the spider and wait until it's complete

	print ('[Action] Spidering target ' + targetIP)

	scanid = zap.spider.scan(targetIP, apikey = api)

	time.sleep(5)

	while (int(zap.spider.status(scanid)) < 100):
		prog=int(zap.spider.status(scanid))
	    	progress(prog, 100, status="Spider_Scan")
	    	time.sleep(2)

	print 'Spider completed'

def passivescan_target(targetIP):
# Wait for passive scanning to complete
	start_num_records = int(zap.pscan.records_to_scan)
		
	while (int(zap.pscan.records_to_scan) > 0):
	  #prog=int(zap.pscan.records_to_scan)
	  #progress(prog, start_num_records, status="Passive Scan")
	  sys.stdout.write('[Info] Records to passive scan : %s\r' % zap.pscan.records_to_scan)
	  sys.stdout.flush()
	  time.sleep(2)

	print ('Passive scanning complete')

def activescan_target(targetIP):
	# Start the active scan and wait till it's complete

	print ('[Action] Active Scanning target ' + targetIP)

	ascan_id = zap.ascan.scan(targetIP, apikey = api)

	while (int(zap.ascan.status(ascan_id)) < 100):
	    prog=int(zap.ascan.status(ascan_id))
	    progress(prog, 100, status="Active_Scan")
	    time.sleep(2)

	print ('Scan completed')

def get_report(targetIP):
	# Report the results

	print ('Hosts: ' + ', '.join(zap.core.hosts))
	print ('Sites: ' + ', '.join(zap.core.sites))
	#print ('Urls: ' + ', '.join(zap.core.urls(baseurl=targetIP)))
	print ('Alerts: ')
	print "==========================="

	pprint (zap.core.alerts(baseurl=targetIP, riskid=3))
	http, crap, target_dir, crap1=targetIP.split('/',-1)
	# Writes the XML and HTML reports that will be exported to the workspace.
	d = 'scan/'+target_dir
	if not os.path.exists(d):
		os.makedirs(d)
	f = open('scan/'+target_dir+'/xmlreport.xml','w+')
	f2 = open('scan/'+target_dir+'/htmlreport.html','w+')
	f.write(zap.core.xmlreport(apikey = api))
	f2.write(zap.core.htmlreport(apikey = api))

	f.close()
	f2.close()
	print "[i] RESULTS WRITTEN TO: "
	sys.stdout.write('scan/%s/xmlreport.xml\n' % target_dir)
	sys.stdout.write('scan/%s/htmlreport.xml\n' % target_dir)


def main():

	if len(sys.argv) == 2:
		banner()
		targetIP = sys.argv[1]
		print "[i] ADDING TARGETS TO SCAN"
		access_target(targetIP)
		spider_target(targetIP)
		passivescan_target(targetIP)
		activescan_target(targetIP)
		get_report(targetIP)


	else:
		print "Usage:  python zap-scan.py <target_url>"
	
	




if __name__ == "__main__":
	main()



