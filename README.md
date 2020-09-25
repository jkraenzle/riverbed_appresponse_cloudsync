Script to grab and convert the JSON file of AWS IP ranges from https://ip-ranges.amazonaws.com/ip-ranges.json to AppResponse Host Groups and automatically post them to the desired appliance. The script includes an optional region filter to limit what gets updated to select AWS regions.

Command line execution is:

<i>python awsipranges.py --hostname [hostname] --username [username] --regionfilter [filename] --servicefilter [filename] --hostgroupprepend [string]</i>

Required:
--hostname
--username

Optional:
--regionfilter
--servicefilter
--hostgroupprepend

Notes:
The provided file regionfilter.yaml provides the list of all AWS regions provided as of 9/25/2020. Use comments to add or remove regions from being converted to Host Group definitions.

The provided file servicefilter.yaml provides the list of all AWS services provided as of 9/25/2020. Use comments to add/remove services from being converted to Host Group definitions.

Not yet implemented:
* Filter by network_border_group
* Aggregation of Host Groups into larger entities
* Storage and comparison of dates within Amazon file to avoid running rest of script in AppResponse if nothing has changed
* Ability to push to more than one appliance at a time
* Optional email notification after script has completed

Please upvote ability to push this through Portal to appliances:
https://steelcentral.ideas.riverbed.com/ideas/PO-I-329

Please also upvote ability for REST API to update tags:
https://steelcentral.ideas.riverbed.com/ideas/AR-I-485
