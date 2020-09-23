Script to grab and convert the JSON file of AWS IP ranges from https://ip-ranges.amazonaws.com/ip-ranges.json to AppResponse Host Groups and automatically post them to the desired appliance. The script includes an optional region filter to limit what gets updated to select AWS regions.

Command line execution is:
python awsipranges.py --hostname <hostname> --username <username> --filterfile <filename>

Not yet implemented:
* Filter for Amazon services (listed in JSON)
* Storage and comparison of dates within Amazon file to avoid merging in AppResponse if nothing has changed
* Ability to modify Host Group names in terms of capitalization or prepending of string (e.g., "AWS")
* Ability to push to more than one appliance at a time
* Optional report about change comparing before and after results
* Optional email notification after script has completed

Please upvote ability to push this through Portal to appliances:
https://steelcentral.ideas.riverbed.com/ideas/PO-I-329

Please also upvote ability for REST API to update tags:
https://steelcentral.ideas.riverbed.com/ideas/AR-I-485
