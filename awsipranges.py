
import requests
import json
import argparse
import getpass

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

	payload = {"generate_refresh_token":True, "user_credentials":credentials}
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

def appresponse_awsipranges_to_hostgroups (result_json):

	awsipprefixes = result_json["prefixes"]
	
	awsiprange_hostgroups = {}
	for awsipprefix in awsipprefixes:
		region = awsipprefix["region"]
		prefix = awsipprefix["ip_prefix"]
		if region in awsiprange_hostgroups.keys ():
			awsiprange_hostgroups[region].append(prefix)
		else:
			values = [prefix]
			awsiprange_hostgroups[region] = values

	awsipv6prefixes = result_json["ipv6_prefixes"]
	for awsipv6prefix in awsipv6prefixes:
		region = awsipv6prefix["region"]
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

def appresponse_hostgroups_merge (hostname, access_token, hostgroups):

	# Create headers for authentication
	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}

	# Place hostgroups in proper format
	payload = {}
	payload ['items'] = hostgroups

	# Submit
	result = requests.post ('https://' + hostname + '/api/npm.classification/3.2/hostgroups/merge', headers=headers, 
		data=json.dumps(payload), verify=False)

	if result.status_code in [200, 201, 204]:
		return result
	else:
		return None

def main ():

	# Parse the arguments
	parser = argparse.ArgumentParser (description="Automated conversion of documented AWS IP ranges to Host Groups")
	parser.add_argument ('--hostname')
	parser.add_argument ('--username')
	args = parser.parse_args ()

	if args.hostname == None:
		print ("Please specify a hostname using --hostname")
		return

	if args.username == None:
		print ("Please specify a username using --username")
		return

	print ("Please provide the password for account %s" % args.username)
	password = getpass.getpass ()

	access_token = appresponse_authenticate (args.hostname, args.username, password)

	awsresult = aws_ipranges ()

	hostgroups = appresponse_awsipranges_to_hostgroups (awsresult)

	resulting_hostgroups = appresponse_hostgroups_merge (args.hostname, access_token, hostgroups)
	if resulting_hostgroups == None:
		print ("Merge failed")
	else:
		print ("Merge successful")
		print (resulting_hostgroups)
		
	return

if __name__ == "__main__":
	main ()
