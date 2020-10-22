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

M365ENDPOINTSVERSIONSURL = "https://endpoints.office.com/version?ClientRequestId=b10c5ed1-bad1-445f-b386-b919946339a7"
M365ENDPOINTSURLBEGIN = "https://endpoints.office.com/endpoints/"
M365ENDPOINTSURLEND = "?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"
M365ENDPOINTSINSTANCEFILE = "m365instances.yaml"

def m365_versions ():
	
	result = requests.get(M365ENDPOINTSVERSIONSURL)

	if result.status_code in [200, 201, 204]:
		result_json = result.json ()
		
		return result_json
	else:
		print("Failed to pull M365 Endpoints instances from %s" % M365ENDPOINTSVERSIONSURL)
		return None

def m365_endpoints (instance="worldwide"):

	result = requests.get(M365ENDPOINTSURLBEGIN + instance + M365ENDPOINTSURLEND)

	if result.status_code in [200, 201, 204]:
		result_json = result.json()
		
		return result_json
	else:
		print("Failed to pull M365 Endpoints from %s" % instance)
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

def appresponse_m365endpoints_to_hostgroups (result_json, servicearea_filter=None, prepend=None):

	m365urlgroups = result_json
	
	m365_hostgroups = {}
	for m365urlgroup in m365urlgroups:
		servicearea = m365urlgroup["serviceAreaDisplayName"]
		if (servicearea_filter != None) and (servicearea not in servicearea_filter):
			continue
		if 'ips' in m365urlgroup:
			endpoints = m365urlgroup['ips']
			if servicearea in m365_hostgroups.keys ():
				m365_hostgroups[servicearea].extend (endpoints)
			else:
				m365_hostgroups[servicearea] = endpoints

	hostgroups = []
	for m365_hostgroup in m365_hostgroups:
		if prepend != None:
			hostgroup_name = prepend + m365_hostgroup
		else:
			hostgroup_name = m365_hostgroup
		hostgroup = {
			# "created":,
			"desc": "Created by script",
			"enabled": True,
			"hosts": m365_hostgroups[m365_hostgroup],
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
		ip = ipaddress.IPv6Network(range_strs[0])
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
	parser = argparse.ArgumentParser (description="Automated coninstance of documented M365 IP ranges to Host Groups")
	parser.add_argument('--hostname')
	parser.add_argument('--username')
	parser.add_argument('--instancefilter', help="YAML file containing list of services to include in Host Groups")
	parser.add_argument('--serviceareafilter', help="YAML file containing list of regions to include in Host Groups")
	parser.add_argument('--hostgroupprepend', help="String prepended to the M365 regions to form the Host Group names")
	parser.add_argument('--ignoreversions', action='store_true', help="Do not store instance from M365 endpoints. This flag is useful in testing.")
	parser.add_argument('--checkforupdates', action='store_true', help="Check if M365 endpoints instance was pulled in last run")
	args = parser.parse_args ()

	instancefilter = yamlread (args.instancefilter)

	# Pull latest M365 Endpoints instance
	m365versions = m365_versions ()

	# Validate the argument --checkforupdates
	instances_to_update = []
	if args.checkforupdates != None and isinstance(args.checkforupdates, bool) and args.checkforupdates == True:
		oldversions = yamlread(args.hostname + M365ENDPOINTSINSTANCEFILE)
			
		# Walk through new list of instances and add to list to pull
		for m365item in m365versions:
			m365instance_found = False
			for olditem in oldversions:
				if olditem['instance'] == m365item['instance']:
					m365instance_found = True
					if olditem['latest'] != m365item['latest']:
						if instancefilter == None or m365item in instancefilter:
							instances_to_update.append(m365item['instance'])
					else:
						print("Instance %s has not been updated." % m365item)
			if m365instance_found == False:
				if instancefilter == None or m365item in instancefilter:
					instances_to_update.append(m365instance['instance'])				

	else:
		if instancefilter != None:
			instances_to_update.extend(instancefilter)
		else:
			print("Please use --instancefilter to specify M365 endpoint instances to use to create Host Group definitions.")
			print("Or check for updates against previous instances.")
			return

	if len(instances_to_update) == 0:			
		# Shortcut the rest of the script if there is no updates of IP ranges on M365
		print("M365 has not updated their endpoint file instance on %s." % M365ENDPOINTSVERSIONSURL)
		print("No Host Group definitions will be updated.")
		print("If other configurations have changed, please set --checkforupdates to False.")
		return

	# Assuming there is a new update or the user has not requested to check for updates, validate the other arguments
	# and confirm that the script can authenticate to the AppResponse appliance
	if args.hostname == None:
		print ("Please specify a hostname using --hostname")
		return

	if args.username == None:
		print ("Please specify a username using --username")
		return

	if args.password == None:
		print ("Please provide the password for account %s" % args.username)
		password = getpass.getpass ()
	else:
		password = args.password
		
	access_token = appresponse_authenticate (args.hostname, args.username, password)

	# Pull latest M365 Endpoints file
	instances_updated = []
	for instance in instances_to_update:
		m365result = m365_endpoints (instance)


		# Pull existing Host Groups from appliance for comparison
		# The script allows filtering, so it will compare existing Host Groups to new definitions to provide details on changes
		existing_hostgroups = appresponse_hostgroups_get (args.hostname, access_token)

		# If there is no difference in the Host Groups after the filters are applied, do not bother to upload them to the appliance
	
		shortcut = False

		# Read filters from files specified in arguments; filters set to None implies nothing to filter
		serviceareafilter = yamlread (args.serviceareafilter)

		# Convert and filter M365 IP ranges to Host Group definitions
		hostgroups = appresponse_m365endpoints_to_hostgroups (m365result, serviceareafilter, args.hostgroupprepend)

		# Check to see if there are differences
		new_hostgroups, hostgroup_prefixes_removed, hostgroup_prefixes_added = appresponse_hostgroups_compare (existing_hostgroups, hostgroups)
		if len(new_hostgroups) == 0 and len(hostgroup_prefixes_removed) == 0 and len(hostgroup_prefixes_added) == 0:
			# Flag the lack of differences so there is no attempt to upload the Host Groups
			shortcut = True

			print ("The set of Host Groups chosen to update have the same definitions on the appliance.")
			print ("There are no Host Group definitions to push for instance %s." % instance)
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
	
			if result != None and result.status_code in [200, 201, 204]:
				#resulting_hostgroups = result.json ()
				#print (resulting_hostgroups)
				print ("Host Group definitions updated for instance %s." % instance)
				instances_updated.append(instance)
			else:
				print("Host Group definitions for instance %s were not updated." % instance)
		else:
			print ("Host Group definitions for instance %s not updated." % instance)

	# Write YAML file to keep track of last publication pull
	instances_dict = []
	if isinstance(args.ignoreversions, bool) and args.ignoreversions == True:
		print("")
		print("The --ignoreversions flag was specified, so the script did not cache M365 instance and version information for future comparison.")
	else:
		for instance in instances_updated:
			for m365item in m365versions:
				if instance == m365item['instance']:
					instances_dict.append ({'instance':instance, 'latest':m365item['latest']})
		if args.hostname != None:
			with open(args.hostname + M365ENDPOINTSINSTANCEFILE, 'w') as yaml_file:
				yaml.dump(instances_dict, yaml_file, default_flow_style=False)
		
	return

if __name__ == "__main__":
	main ()
