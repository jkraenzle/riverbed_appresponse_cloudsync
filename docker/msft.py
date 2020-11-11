#!/usr/bin/env python

import os
from typing import Any, IO
import yaml
from subprocess import call

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

config = yamlread ("/home/cloudsync/github/docker/config.yaml")

hostname = config["HOSTNAME"]
username = config["USERNAME"]
password = config["PASSWORD"]
instancefilter = config["INSTANCEFILTER"]
serviceareafilter = config["SERVICEAREAFILTER"] 
hostgroupprepend = config["MSFTHOSTGROUPPREPEND"]

args = ["/usr/local/bin/python3",
	"/home/cloudsync/github/m365endpoints.py",
	"--hostname", hostname,
	"--username", username,
	"--password", password,
	"--instancefilter", instancefilter,
	"--serviceareafilter", serviceareafilter,
	"--hostgroupprepend", hostgroupprepend,
	"--checkforupdates"]
call(args)
