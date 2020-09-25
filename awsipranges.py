import argparse
import getpass
import ipaddress
import json
import os
import requests
from typing import Any, IO
import yaml
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

### YAML Loader, as default Loader is not safe
class YAMLLoader(yaml.SafeLoader):
    """YAML Loader with `!include` constructor."""

    def __init__(self, stream: IO) -> None:
        """Initialise Loader."""

        try:
            self._root = os.path.split(stream.name)[0]
        except AttributeError:
            self._root = os.path.curdir

        super().__init__(stream)


def construct_include(loader: YAMLLoader, node: yaml.Node) -> Any:
    """Include file referenced at node."""

    filename = os.path.abspath(os.path.join(loader._root, loader.construct_scalar(node)))
    extension = os.path.splitext(filename)[1].lstrip('.')

    with open(filename, 'r') as f:
        if extension in ('yaml', 'yml'):
            return yaml.load(f, YAMLLoader)


yaml.add_constructor('!include', construct_include, YAMLLoader)

###

AWSIPRANGESURL ='https://ip-ranges.amazonaws.com/ip-ranges.json' 

def aws_ipranges ():

	result = requests.get (AWSIPRANGESURL)

	if result.status_code in [200, 201, 204]:
		return result.json ()
	else:
		print ("Failed to pull AWS IP ranges from %s" % AWSIPRANGESURL)
		return None

def appresponse_authenticate (hostname, username, password):
	
	credentials = {"username":username, "password":password}

	payload = {"generate_refresh_token":False, "user_credentials":credentials}
	headers = {"Content-Type":"application/json"}
	result = requests.post ('https://' + hostname + '/api/mgmt.aaa/2.0/token', data=json.dumps(payload), headers=headers, verify=False)

	if result.status_code not in [200, 201, 204]:
		print ("Status code was %s" % result.status_code)
		print ("Error: %s" % result.content)
		return None
	else:
		token_json = result.json ()
		access_token = token_json ["access_token"]
		return access_token

def appresponse_awsipranges_to_hostgroups (result_json, region_filter=None, service_filter=None):

	awsipprefixes = result_json["prefixes"]
	
	awsiprange_hostgroups = {}
	for awsipprefix in awsipprefixes:
		region = awsipprefix["region"]
		if (region_filter != None) and (region not in region_filter):
			continue
		service = awsipprefix["service"]
		if (service_filter != None) and (service not in service_filter):
			continue
		prefix = awsipprefix["ip_prefix"]
		if region in awsiprange_hostgroups.keys ():
			awsiprange_hostgroups[region].append(prefix)
		else:
			values = [prefix]
			awsiprange_hostgroups[region] = values

	awsipv6prefixes = result_json["ipv6_prefixes"]
	for awsipv6prefix in awsipv6prefixes:
		region = awsipv6prefix["region"]
		if (region_filter != None) and (region not in region_filter):
			continue
		service = awsipprefix["service"]
		if (service_filter != None) and (service not in service_filter):
			continue
		ipv6_prefix = awsipv6prefix["ipv6_prefix"]
		if region in awsiprange_hostgroups.keys ():
			awsiprange_hostgroups[region].append(ipv6_prefix)
		else:
			values = [ipv6_prefix]
			awsiprange_hostgroups[region] = values

	hostgroups = []
	for hostgroup_name in awsiprange_hostgroups:

		hostgroup = {
			# "created":,
			"desc": "Created by script",
			"enabled": True,
			"hosts": awsiprange_hostgroups [hostgroup_name],
			#"id": ,
			#"in_speed":,
			#"in_speed_unit":,
			#"last_modified":,
			#"last_modified_username":,
			#"member_hostgroups":,
			#"member_hostgroups_names":,
			"name": hostgroup_name #,
			#"out_speed":,
			#"out_speed_unit":,
			}
	
		hostgroups.append (hostgroup)

	return hostgroups

def iprange_to_ipv4subnets (range):

	range_strs = range.split('-')
	count = len(range_strs)
	if count == 1:
		ip = ipaddress.IPv4Address(range_strs[0])
		subnets = [str(ip) + '/32']
		return subnets
	elif count == 2:
		startip = ipaddress.IPv4Address(range_strs[0])
		endip = ipaddress.IPv4Address(range_strs[1])

		subnets = [str(subnet) for subnet in ipaddress.summarize_address_range(startip,endip)]
		return subnets

	return None

def iprange_to_ipv6subnets (range):

	range_strs = range.split('-')
	count = len(range_strs)
	if count == 1:
		ip = ipaddress.IPv6Address(range_strs[0])
		subnets = [str(ip)]
		return subnets
	if count == 2:
		startip = ipaddress.IPv6Address(range_strs[0])
		endip = ipaddress.IPv6Address(range_strs[1])

		subnets = [str(subnet) for subnet in ipaddress.summarize_address_range(startip,endip)]
		return subnets

	return None

def appresponse_hostgroups_get (hostname, access_token):
	
	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}

	result = requests.get('https://' + hostname + '/api/npm.classification/3.2/hostgroups', headers=headers,
		verify=False)

	if result.status_code in [200, 201, 204]:
		result_json = result.json ()
	else:
		return None

	hostgroups = result_json ['items']

	return hostgroups	

def appresponse_hostgroups_merge (hostname, access_token, hostgroups):

	# Create headers for authentication
	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}

	# Place hostgroups in proper format
	payload = {}
	payload ['items'] = hostgroups

	# Submit
	result = requests.post('https://' + hostname + '/api/npm.classification/3.2/hostgroups/merge', headers=headers, 
		data=json.dumps(payload), verify=False)

	if result.status_code in [200, 201, 204]:
		return result
	else:
		return None

def appresponse_existing_hosts_convert (ranges):

	converted_hosts = []

	i = 0
	for range in ranges:
		if '.' in range:
			ipv4_subnets = iprange_to_ipv4subnets(range)
			if ipv4_subnets != None:
				converted_hosts.extend(ipv4_subnets)
		elif ':' in range:
			ipv6_subnets = iprange_to_ipv6subnets(range)
			if ipv6_subnets != None:
				converted_hosts.extend(ipv6_subnets)
		i+=1

	return converted_hosts
	
def appresponse_hostgroups_compare (existing_hostgroups, new_hostgroups):

	for new_hostgroup in new_hostgroups:
		found_name = False
		for existing_hostgroup in existing_hostgroups:
			if new_hostgroup['name'] == existing_hostgroup['name']:
				found_name = True
				if 'hosts' in existing_hostgroup:
					hosts_to_compare = appresponse_existing_hosts_convert (existing_hostgroup['hosts'])
				else:
					hosts_to_compare = []

				if set(new_hostgroup["hosts"]) == set(hosts_to_compare):
					break
				else:
					print ("The following Host Group %s has changed." % new_hostgroup['name'])
					removed_ranges = set(hosts_to_compare) - set(new_hostgroup['hosts']) 
					if len(removed_ranges) != 0:
						print ("Removed IP ranges: %s" % removed_ranges)
					added_ranges = set(new_hostgroup['hosts']) - set(hosts_to_compare) 
					if len(added_ranges) != 0:
						print ("Added IP ranges: %s" % added_ranges)

			if found_name == True:
				break
		if found_name == False:
			print("The following Host Groups were added.")
			print(new_hostgroup)
	
	return				

def filterread (fn):
	try:
		if fn != None:
			with open(fn) as fh:
				filter = yaml.load (fh, YAMLLoader)
		else:
			filter = None
	except FileNotFoundError:
		filter = None

	return filter

def main ():

	# Parse the arguments
	parser = argparse.ArgumentParser (description="Automated conversion of documented AWS IP ranges to Host Groups")
	parser.add_argument('--hostname')
	parser.add_argument('--username')
	parser.add_argument('--regionfilter')
	parser.add_argument('--servicefilter')
	args = parser.parse_args ()

	if args.hostname == None:
		print ("Please specify a hostname using --hostname")
		return

	if args.username == None:
		print ("Please specify a username using --username")
		return

	print ("Please provide the password for account %s" % args.username)
	password = getpass.getpass ()

	# Authenticate to appliance and pull existing Host Groups
	access_token = appresponse_authenticate (args.hostname, args.username, password)
	existing_hostgroups = appresponse_hostgroups_get (args.hostname, access_token)

	# Pull latest AWS IP Range file
	awsresult = aws_ipranges ()

	# Read filters
	regionfilter = filterread (args.regionfilter)
	servicefilter = filterread (args.servicefilter)

	# Convert and filter AWS IP ranges to Host Group definitions
	hostgroups = appresponse_awsipranges_to_hostgroups (awsresult, regionfilter, servicefilter)

	# Merge converted Host Group definitions into appliance
	result = appresponse_hostgroups_merge (args.hostname, access_token, hostgroups)
	
	# Check to see if there are differences
	appresponse_hostgroups_compare (existing_hostgroups, hostgroups)
	
	if result.status_code in [200, 201, 204]:
		#resulting_hostgroups = result.json ()
		#print (resulting_hostgroups)
		print ("Host Group definitions updated.")
	else:
		print ("Host Group definitions not updated.")

		
	return

if __name__ == "__main__":
	main ()
