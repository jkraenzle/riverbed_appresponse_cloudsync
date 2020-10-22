#!/usr/bin/env python

import os
from subprocess import call

hostname = os.environ["HOSTNAME"]
username = os.environ["USERNAME"]
password = os.environ["PASSWORD"]
instancefilter = os.environ["INSTANCEFILTER"]
serviceareafilter = os.environ["SERVICEAREAFILTER"]
hostgroupprepend = os.environ["MSFTHOSTGROUPPREPEND"]

args = ["python",
        "m365endpoints.py",
        "--hostname", hostname,
        "--username", username,
        "--password", password,
        "--serviceareafilter", serviceareafilter,
        "--instancefilter", instancefilter,
        "--hostgroupprepend", hostgroupprepend,
        "--checkforupdates"]
call(args)
