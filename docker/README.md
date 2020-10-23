This directory provides an example of how to use a Docker container to automate the service to run daily using cron.

After installing Docker, download the config.yaml and dockerfile to an empty directory on the Docker system. Modify the files to configure the proper settings. 

The config.yaml file specifies the other YAML configuration files to be used in the automation. Duplicate those files from the parent GitHub directory, modify them appropriately, modify the dockerfile to copy the new files, and update the config.yaml file appropriately.

Build using the command:
docker build -t "cloudsync:1.0" .

Run using the command:
docker run -d -t "cloudsync:1.0"

The existing dockerfile has a time zone of Americas Eastern Time (New York). The cron-python file has a configuration for the AWS Host Groups to update every day at midnight ET and the Microsoft Host Groups to update every day at 12:30 AM ET.
