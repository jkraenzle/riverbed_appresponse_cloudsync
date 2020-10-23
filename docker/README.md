This directory provides an example of how to use a Docker container to automate the service to run daily using cron.

After installing Docker, download the config.yaml and dockerfile to an empty directory on the Docker system. Modify the files to configure the proper settings. The dockerfile is set to download all files from this repository directly into the container (which requires an Internet connection). Those files are effectively used as the defaults, except for config.yaml. The config.yaml, which is expected to be modified specifically for the local environment, is copied over from the local file system to the container.

The config.yaml file specifies the other YAML configuration files to be used in the automation. To make a change from those defaults, duplicate those files from the parent GitHub directory, modify them appropriately, modify the dockerfile to copy the new files over the defaults that are loaded from the GitHub repository, and update the config.yaml file appropriately with the path and name of the new YAML files.

Build using the command:
docker build -t "cloudsync:1.0" .

Run using the command:
docker run -d -t "cloudsync:1.0"

The existing dockerfile has a time zone of Americas Eastern Time (New York). The cron-python file has a configuration for the AWS Host Groups to update every day at midnight ET and the Microsoft Host Groups to update every day at 12:30 AM ET.

The Python wrappers aws.py and msft.py are required since cron does not carry over environment variables that could be defined in the container during build or execution.
