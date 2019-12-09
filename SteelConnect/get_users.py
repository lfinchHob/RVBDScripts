#!/usr/bin/env python
""" Short description of this Python module.
Longer description of this module.
This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""
import urllib
import requests
import hashlib
import time
import base64
import sys
import argparse
import json
import time
import requests
import getpass
from prettytable import PrettyTable
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from time import gmtime, strftime

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Dependancies
# python-requests
# python-backports
# python-backports-ssl_match_hostname
# python-chardet
# python-six
# python-urllib3
# python-prettytable

requests.packages.urllib3.disable_warnings()

# fqdn or ip address of our test host
test_host = "127.0.0.1"

# Define the start of a URL
host_part = 'https://{host_id}'

# We will need a wrapper of the request methods because of the number of times
# we will be doing this.
def do_request(host, url, data=None, headers=None, auth=None):
	url_start = host_part.format(host_id = host)
	request_url = "{0}{1}".format(url_start, url)
	r = None
	if data is None:
		# no data is a get request.
		# verify is set to false so SSL errors don't cause problems
		# allow_redirects is false because the NetProfiler REST API
		# uses the location header in a redirect to pass back OAuth2
		# key data.
		r = requests.get(request_url,
						 headers=headers,
						 verify=False,
						 allow_redirects=False,
						auth=auth)
	else:
		r = requests.post(request_url,
						  data=data,
						  headers=headers,
						  verify=False,
						  allow_redirects=False)
	return r

def put_request(host, url, data=None, headers=None):
	url_start = host_part.format(host_id = host)
	request_url = "{0}{1}".format(url_start, url)
	r = None
	if data is None:
		# no data is a get request.
		# verify is set to false so SSL errors don't cause problems
		# allow_redirects is false because the NetProfiler REST API
		# uses the location header in a redirect to pass back OAuth2
		# key data.
		r = requests.get(request_url,
						 headers=headers,
						 verify=False,
						 allow_redirects=False)
	else:
		r = requests.put(request_url,
						  data=data,
						  headers=headers,
						  verify=False,
						  allow_redirects=False)
	return r

def main(argv):
	# ENTER HERE
	# First thing I am doing is a bit of simple argparse. This just
	# allows the sample script to take in arguments with very little code.
	parser = argparse.ArgumentParser(description='SteelConnect - REST API')
	parser.add_argument('-s', '--SCM_host',
						help='SCM host name or IP.',
						type=str,
						default=test_host)
	parser.add_argument('-u', '--username',
						help=('username for the SCM.'),
						type=str,
						default="admin")
	parser.add_argument('-d', '--debug',
						help='Disable Printing debug.',
						action='store_false')
	parser.add_argument('-l', '--listusers',
						action='store_true',
						help='List users on SCM',
						default=False)
	args = parser.parse_args()


	auth_hdr = {
			'Accept': 'application/json',
			'Content-Type': 'application/json'}

	if args.listusers:
		username = args.username
		password = getpass.getpass("password: ")
		reports_url = '/api/scm.config/1.0/users/'

		reports_req = do_request(args.SCM_host,
				reports_url,
				headers=auth_hdr,
				auth=(username, password))

		reports_obj = reports_req.json()
		table = PrettyTable(['Username', 'Name', 'Org', 'Email', 'Groups'])
		for report in reports_obj['items']:
			table.add_row([str(report['username']), str(report['name']),  str(report['org']), str(report['email']), str(report['usergrps'])])
		print(table)


if __name__ == "__main__":
   main(sys.argv[1:])
