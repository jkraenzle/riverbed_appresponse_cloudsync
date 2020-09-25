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

# ---- YAML helper functions -----
# Define YAML Loader, as default Loader is not safe
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

def yamlread (fn):
	try:
		if fn != None:
			with open(fn) as fh:
				yamlresult = yaml.load (fh, YAMLLoader)
		else:
			yamlresult = None
	except FileNotFoundError:
		yamlresult = None

	return yamlresult

# -----

AWSIPRANGESURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
AWSIPRANGESSYNCTIMEFILE = "synctime.yaml"

def aws_ipranges ():

	result = requests.get (AWSIPRANGESURL)

	if result.status_code in [200, 201, 204]:
		result_json = result.json()
		
		return result_json
	else:
		print("Failed to pull AWS IP ranges from %s" % AWSIPRANGESURL)
		return None

def appresponse_authenticate (hostname, username, password):
	
	credentials = {"username":username, "password":password}

	payload = {"generate_refresh_token":False, "user_credentials":credentials}
	headers = {"Content-Type":"application/json"}
	result = requests.post ('https://' + hostname + '/api/mgmt.aaa/2.0/token', data=json.dumps(payload), headers=headers, verify=False)

	if result.status_code not in [200, 201, 204]:
		print("Status code was %s" % result.status_code)
		print("Error: %s" % result.content)
		return None
	else:
		token_json = result.json ()
		access_token = token_json ["access_token"]
		return access_token

def appresponse_awsipranges_to_hostgroups (result_json, region_filter=None, service_filter=None, prepend=None):

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
	for awsiprange_hostgroup in awsiprange_hostgroups:
		hostgroup_name = prepend + awsiprange_hostgroup
		hostgroup = {
			# "created":,
			"desc": "Created by script",
			"enabled": True,
			"hosts": awsiprange_hostgroups [awsiprange_hostgroup],
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

def appresponse_hostname_form (hostgroup_name, prepend):
	if prepend != None:
		return prepend + hostgroup_name
	else:
		return hostgroup_name
	
def appresponse_hostgroups_compare (existing_hostgroups, new_hostgroups):

	hostgroups_created = []
	hostgroup_ranges_removed = {}
	hostgroup_ranges_added = {}

	for new_hostgroup in new_hostgroups:
		found_name = False
		for existing_hostgroup in existing_hostgroups:
			new_hostgroup_name = new_hostgroup['name']
			if new_hostgroup_name == existing_hostgroup['name']:
				found_name = True
				if 'hosts' in existing_hostgroup:
					hosts_to_compare = appresponse_existing_hosts_convert (existing_hostgroup['hosts'])
				else:
					hosts_to_compare = []

				if set(new_hostgroup['hosts']) == set(hosts_to_compare):
					break
				else:
					removed_ranges = set(hosts_to_compare) - set(new_hostgroup['hosts']) 
					if len(removed_ranges) != 0:
						hostgroup_ranges_removed[new_hostgroup_name] = removed_ranges
					added_ranges = set(new_hostgroup['hosts']) - set(hosts_to_compare) 
					if len(added_ranges) != 0:
						hostgroup_ranges_added[new_hostgroup_name] = added_ranges

			if found_name == True:
				break
		if found_name == False:
			hostgroups_created.append (new_hostgroup_name)

	return hostgroups_created, hostgroup_ranges_removed, hostgroup_ranges_added

def main ():

	# Parse the arguments
	parser = argparse.ArgumentParser (description="Automated conversion of documented AWS IP ranges to Host Groups")
	parser.add_argument('--hostname')
	parser.add_argument('--username')
	parser.add_argument('--regionfilter', help="YAML file containing list of regions to include in Host Groups")
	parser.add_argument('--servicefilter', help="YAML file containing list of services to include in Host Groups")
	parser.add_argument('--hostgroupprepend', help="String prepended to the AWS regions to form the Host Group names")
	parser.add_argument('--ignoresynctime', action='store_true', help="Do not store time from AWS IP range JSON that is used to check for updates. This flag is useful in testing.")
	parser.add_argument('--checkforupdates', action='store_true', help="Check if AWS IP range JSON was pulled in last run")
	args = parser.parse_args ()

	# Pull latest AWS IP Range file
	awsresult = aws_ipranges ()

	# Validate the argument --checkforupdates
	if args.checkforupdates != None: 
		if isinstance(args.checkforupdates, bool):
			if args.checkforupdates == True:
				oldsynctime = yamlread(args.hostname + AWSIPRANGESSYNCTIMEFILE)
				if oldsynctime != None and oldsynctime['syncToken'] == awsresult ['syncToken']:
					# Shortcut the rest of the script if there is no updates of IP ranges on AWS
					print("AWS has not updated their IP ranges on %s. No Host Group definitions will be updated." % AWSIPRANGESURL)
					print("If other configurations have changed, please set --checkforupdates to False.")
					return
		else:
			print ("The value for --checkforupdates is not recognized.")

	# Assuming there is a new update or the user has not requested to check for updates, validate the other arguments
	# and confirm that the script can authenticate to the AppResponse appliance
	if args.hostname == None:
		print ("Please specify a hostname using --hostname")
		return

	if args.username == None:
		print ("Please specify a username using --username")
		return

	print ("Please provide the password for account %s" % args.username)
	password = getpass.getpass ()

	access_token = appresponse_authenticate (args.hostname, args.username, password)

	# Pull existing Host Groups from appliance for comparison
	# The script allows filtering, so it will compare existing Host Groups to new definitions to provide details on changes
	existing_hostgroups = appresponse_hostgroups_get (args.hostname, access_token)

	# If there is no difference in the Host Groups after the filters are applied, do not bother to upload them to the appliance
	
	shortcut = False

	# Read filters from files specified in arguments; filters set to None implies nothing to filter
	regionfilter = yamlread (args.regionfilter)
	servicefilter = yamlread (args.servicefilter)

	# Convert and filter AWS IP ranges to Host Group definitions
	hostgroups = appresponse_awsipranges_to_hostgroups (awsresult, regionfilter, servicefilter, args.hostgroupprepend)

	# Check to see if there are differences
	new_hostgroups, hostgroup_prefixes_removed, hostgroup_prefixes_added = appresponse_hostgroups_compare (existing_hostgroups, hostgroups)
	if len(new_hostgroups) == 0 and len(hostgroup_prefixes_removed) == 0 and len(hostgroup_prefixes_added) == 0:
		# Flag the lack of differences so there is no attempt to upload the Host Groups
		shortcut = True

		print ("The set of Host Groups chosen to update have the same definitions on the appliance.")
		print ("There are no Host Group definitions to push.")
	if len(new_hostgroups) > 0:
		print ("The new Host Groups are:")
		for new_hostgroup in new_hostgroups:
			print ("\t%s" % new_hostgroup)
	
	# Get the intersection of the sets
	added_and_removed = hostgroup_prefixes_added.keys () & hostgroup_prefixes_removed.keys ()
	just_added = hostgroup_prefixes_added.keys () - added_and_removed
	just_removed = hostgroup_prefixes_removed.keys () - added_and_removed
	if len(added_and_removed) > 0:
		for changed_hostgroup in added_and_removed:
			print ("The Host Group %s had prefixes added and removed." % changed_hostgroup)
			print ("Added:")
			print ("\t%s" % hostgroup_prefixes_added[changed_hostgroup])
			print ("Removed:")
			print ("\t%s" % hostgroup_prefixes_removed[changed_hostgroup])
	if len(just_added) > 0:
		for changed_hostgroup in just_added:
			print ("The Host Group %s had prefixes added." % changed_hostgroup)
			print ("Added:")
			print ("\t%s" % hostgroup_prefixes_added[changed_hostgroup])
	if len(just_removed) > 0:
		for changed_hostgroup in just_removed:
			print ("The Host Group %s had prefixes removed." % changed_hostgroup)
			print ("Removed:")
			print ("\t%s" % hostgroup_prefixes_removed[changed_hostgroup])

	if shortcut == False:
		# Merge converted Host Group definitions into appliance
		result = appresponse_hostgroups_merge (args.hostname, access_token, hostgroups)
	
		if result.status_code in [200, 201, 204]:
			#resulting_hostgroups = result.json ()
			#print (resulting_hostgroups)
			print ("Host Group definitions updated.")

			# Write YAML file to keep track of last publication pull
			if isinstance(args.ignoresynctime, bool) and args.ignoresynctime == True:
				print ("The script is not saving a sync time.")
			else:
				synctime_dict = {'syncToken':awsresult['syncToken'], 'createDate':awsresult['createDate']}
				with open(args.hostname + AWSIPRANGESSYNCTIMEFILE, 'w') as yaml_file:
					yaml.dump(synctime_dict, yaml_file, default_flow_style=False)
		else:
			print ("Host Group definitions not updated.")
		
	return

if __name__ == "__main__":
	main ()
