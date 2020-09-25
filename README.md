Script to grab and convert the JSON file of AWS IP ranges from https://ip-ranges.amazonaws.com/ip-ranges.json to AppResponse Host Groups and automatically post them to the desired appliance. The script includes an optional region filter to limit what gets updated to select AWS regions.

Command line execution is:

<i>python awsipranges.py --hostname [hostname] --username [username] [--regionfilter [filename]] [--servicefilter [filename]] [--hostgroupprepend [string]] [--ignoresynctime] [--checkforupdates]</i>

Required:
--hostname
--username

Optional:
--regionfilter [YAML file]
	Regions specified in file are included in Host Groups
--servicefilter [YAML file]
	Services specified in file are included in Host Groups
--hostgroupprepend [string]
	String to prepend to region names to include in Host Groups in AppResponse (e.g. "AWS ")
--ignoresynctime
	Flag, no parameter value. Including this flag stops the script from storing the syncToken from the AWS IP range JSON file in a YAML file. This is useful when testing and not wanting to update a process that regularly syncs to the same appliance.
--checkforupdates
	Flag, no parameter value. Including this flag has the script check the current syncToken in the AWS IP range JSON file against the previous synchronization time that was saved during the last run of the script. This avoids synchronizing the same data when no changes have been made. This flag should not be included if a configuration change has been made to the YAML files.

Notes:
The provided file regionfilter.yaml provides the list of all AWS regions provided as of 9/25/2020. Use comments to add or remove regions from being converted to Host Group definitions.

The provided file servicefilter.yaml provides the list of all AWS services provided as of 9/25/2020. Use comments to add/remove services from being converted to Host Group definitions.

Not yet implemented:
* Filter by network_border_group
* Aggregation of Host Groups into larger entities automatically; updates of lower level Host Groups will impact Host Groups for which the lower level Host Groups are members
* Ability to push to more than one appliance at a time
* Log; currently output goes to stdout
* Optional email notification after script has completed

Please upvote ability to push this through Portal to appliances:
https://steelcentral.ideas.riverbed.com/ideas/PO-I-329

Please also upvote ability for REST API to update tags:
https://steelcentral.ideas.riverbed.com/ideas/AR-I-485
