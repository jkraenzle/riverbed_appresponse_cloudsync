#!/usr/bin/env python

import os
from subprocess import call

hostname = os.environ["HOSTNAME"]
username = os.environ["USERNAME"]
password = os.environ["PASSWORD"]
regionfilter = os.environ["REGIONFILTER"]
servicefilter = os.environ["SERVICEFILTER"]
hostgroupprepend = os.environ["AWSHOSTGROUPPREPEND"]

args = ["python3",
        "/home/cloudsync/github/awsipranges.py",
        "--hostname", hostname,
        "--username", username,
        "--password", password,
        "--regionfilter", regionfilter,
        "--servicefilter", servicefilter,
        "--hostgroupprepend", hostgroupprepend,
        "--checkforupdates"]
call(args)
