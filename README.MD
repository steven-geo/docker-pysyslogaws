# **pysyslog**

This is a fairly simple python script that runs as a docker container listening on UDP port 514 and will interpret the Syslog messages received and forward them to AWS CloudWatch Logs.

Each host will receive their own CloudWatch Logs stream to easily review logs per host.

NOTE: I personally use this for some core networking logs from PFSense, Uninteruptable Power Supplies and Unifi Networking equipment (using the SIEM integration). Only limited testing on different syslog message formats has been performed. If you have more examples that show up as unknown formats, please let me know and/or contribute to improving the regex statements to capture more variations.


## **Syslog Message Compatibility**

This script I beleive is mostly compatible with the below two syslog message formats. Any improvements to the interpretation are welcome.

At this stage I'm not planning on adding support for other non standard formats unless there is specific demand.

RFC5424  https://www.rfc-editor.org/rfc/rfc5424.html

RFC3164  https://www.rfc-editor.org/rfc/rfc3164.html

Adding Support: Please raise a PR with the additional regex matching, and add a syslog message to test with into the msgtest.py file.


## **Getting up and running**

What you will need to 

* An AWS Account
* Somewhere to run the docker container, this can be on premises or in AWS using ECS or EKS
* If you are running on-premises you will need AWS credentials available to this container. (Refer to the boto3 documentation on methods: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html)
* A static IP for syslog Server - a number of devices do not support DNS for setting the syslog server destination.


## **Managing Hostnames**

Some syslog formats contain the hostname as part of the syslog message, but others don't. pysyslog will automatically pull the hostname out of the message and use that if available.

To prevent IP Addresses showing up as the name for your device, you can edit the hosts.json before building your container or mount it into your container. This file is a list of hostnames and IP Address lookups that will be used only if no hostname is present in the syslog message.

Example hosts have been added to the hosts.json.


## **Testing Syslog Messages**

THe msgtest.py file performs some basic message testing, this is something I want to expand and provide more key/value matching.

Use this to provide some basic functionality testing to syslog messages.



## **Querying your Syslog Messages in AWS CloudWatch Logs**

To filter on an individual host, open the specific Log Stream for that host.

Filter for any message that haven't been formatted in one of our supported RFC Formats.
{ $.syslogtype = "unknown" }

Filter only display all Messages that are warning or above
{ $.loglevel < 5 }

