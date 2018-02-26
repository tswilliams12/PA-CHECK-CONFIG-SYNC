#!/usr/bin/python
# Verify that a Palo Alto firewall's configuration is in-sync with it's HA peer.
# 
# By: Timothy S. Williams, TSW Security LLC
#
# Based on "apitraining.py" by author unknown. 
#
# Usage: pa-check-config-sync.py [-h] [-f FIREWALL] [-u USERNAME] [-p PASSWORD] [-N xxx]
#   or run "./pa-check-config-sync.py" from the command line and answer the prompts or any
#   combination of the two.
#
# Note: If the password has a special character in it, it may need to be 
# delimited with "\" when typing in
#
import string
import getpass
import subprocess
import argparse
import urllib
import urllib2
import ssl
import sys
import requests
from xml.etree import ElementTree as ET
from xml.dom import minidom

nomorerules = '<response status="success" code="7"><result/></response>'
noverify = False

sys.tracebacklimit = 0

# Handler for the command line arguments, if used.
parser = argparse.ArgumentParser()
parser.add_argument("-f", "--firewall", help="Name or IP address of the firewall")
parser.add_argument("-u", "--username", help="User login")
parser.add_argument("-p", "--password", help="Login password")
parser.add_argument("-N", "--NOVERIFY", help="Do not verify SSL certificate")
args = parser.parse_args()

# Gather the user defined variables, either from the command-line options, 
# or if they are not provided, from a user prompt
if args.firewall:
    firewall = args.firewall
else:
    firewall = raw_input("Enter the name or IP of the firewall: ")
if args.username:
    user = args.username
else:
    user = raw_input("Enter the user login: ")
if args.password:
    pw = args.password
else:
    pw = getpass.getpass()
if args.NOVERIFY:
	noverify = True

def send_api_request(url, values):
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	global code
	data = urllib.urlencode(values)
	request = urllib2.Request(url, data)
	if noverify:
		response = urllib2.urlopen(request,context=ctx).read()
	else:
		response = urllib2.urlopen(request).read()
	DOMTree = minidom.parseString(response)
	el = DOMTree.documentElement
	code = el.getAttribute("code")
	return minidom.parseString(response)


def get_api_key(hostname, username, password):
    url = 'https://' + hostname + '/api/?'
    values = {'type': 'keygen', 'user': username, 'password': password}
    parsedKey = send_api_request(url, values)
    nodes = parsedKey.getElementsByTagName('key')
    key = nodes[0].firstChild.nodeValue
    return key


def main():
	key = get_api_key(firewall, user, pw)
	if key == "":
		print "Exit code 2 - Unable to login."
		sys.exit(2)
	url = 'https://' + firewall + '/api/?'
	element = "type=op&cmd=<show><system><state><filter>ha.app.peer.cfg-sync<%2Ffilter><%2Fstate><%2Fsystem><%2Fshow>&"
	if noverify:
		requests.packages.urllib3.disable_warnings()
		r = requests.get(url + element + "key=" + key,stream=True, verify=False)
	else:
		r = requests.get(url + element + "key=" + key,stream=True)
	tree = ET.parse(r.raw)
	root = tree.getroot()
	ret = root[0].text
	status = ret.split("sync: ",1)[1]
	print "Sync Status: " + status
	if status.strip() == "in-sync":
		print "Exit code 0 - Normal"
		sys.exit(0)
	elif status.strip() == "out-sync":
		print "Exit code 2 - Critical"
		sys.exit(2)
	else:
		print "Exit code 1 - Warning"
		sys.exit(1)

main()

