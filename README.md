Scripts to convert public list of Cloud IPs to Host Groups.
<ul><li>AWS</li> 
	<ul><li>https://ip-ranges.amazonaws.com/ip-ranges.json</li></ul>
<li>Microsoft Office 365</li>
	<ul><li>https://endpoints.office.com/version?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7</li>
	<li>https://endpoints.office.com/endpoints/[instance]?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7</li></ul>
</ul>

The script awsipranges.py grabs and converts the JSON file of AWS IP ranges from https://ip-ranges.amazonaws.com/ip-ranges.json to AppResponse Host Groups and automatically post them to the desired appliance. The script includes an optional region filter to limit what gets updated to select AWS regions.

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

The script m365endpoints.py grabs and converts the JSON file of Office 365 endpoints from https://endpoints.office.com/endpoints/[instance]?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7 for each instance specified in the instance filter.

Command line execution is:

<i>python m365endpoints.py --hostname [hostname] --username [username] [--serviceareafilter [filename]] [--instancefilter [filename]] [--hostgroupprepend [string]] [--ignoreversions] [--checkforupdates]</i>

Required:
--hostname
--username

Optional:
--instancefilter [YAML file]
        Instances specified in file are included in Host Groups
--serviceareafilter [YAML file]
        Service areas specified in file are included in Host Groups
--hostgroupprepend [string]
        String to prepend to region names to include in Host Groups in AppResponse (e.g. "AWS ")
--ignoreversions
        Flag, no parameter value. Including this flag stops the script from storing the syncToken from the AWS IP range JSON file in a YAML file. This is useful when testing and not wanting to update a process that regularly syncs to the same appliance.
--checkforupdates
        Flag, no parameter value. Including this flag has the script check the current syncToken in the AWS IP range JSON file against the previous synchronization time that was saved during the last run of the script. This avoids synchronizing the same data when no changes have been made. This flag should not be included if a configuration change has been made to the YAML files.

Notes:
The provided file serviceareafilter.yaml provides the list of all M365 Service Areas provided as of 9/25/2020. Use comments to add or remove regions from being converted to Host Group definitions.

The provided file instancefilter.yaml provides the list of all M365 instances provided as of 9/25/2020. Use comments to add/remove services from being converted to Host Group definitions.

Not yet implemented:
* Common code pulled into helper Python scripts for import independently
* Filter by network_border_group in AWS
* Aggregation of Host Groups into larger entities automatically; updates of lower level Host Groups will impact Host Groups for which the lower level Host Groups are members
* Ability to push to more than one appliance at a time
* Log; currently output goes to stdout
* Optional email notification after script has completed

Please upvote ability to push this through Portal to appliances:
https://steelcentral.ideas.riverbed.com/ideas/PO-I-329

Please also upvote ability for REST API to update tags:
https://steelcentral.ideas.riverbed.com/ideas/AR-I-485
