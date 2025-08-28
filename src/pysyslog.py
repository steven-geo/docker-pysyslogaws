""" A Python SYSLOG UDP Receiver that sends log to a AWS CloudWatch Log Group """
import socketserver
import socket
import json
import re
import time
import sys
import boto3
from botocore.exceptions import ClientError
import syslogmessagehandler

# TODO: Add buffer/message queue incase of transient connection issues
# TODO: Split processing into a seperate thread to scale better.
# TODO: Improve syslog decoding Regex matches
# TODO: Improve and expand testing messages and add more exchaustive testing

HOST, PORT = "0.0.0.0", 514
CWLOGGROUPNAME = '/external/pysyslog'
AWS_REGION = "ap-southeast-4"
hostlookup = {}

cwlogs = boto3.client('logs', region_name=AWS_REGION)

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """ Handle Received UDP Packets """
    def handle(self):
        global hostlookup
        ip = None
        hostname = None
        try:
            ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', format(self.client_address[0]))[0]
        except:
            print(f"ERROR: Cannot determine IP/hostname - {ip} ({hostname})")
            raise
        try:
            data = str(bytes.decode(self.request[0].strip()))
            messageobj = syslogmessagehandler.decode_syslog(data)
            if messageobj['hostname'] is None:
                messageobj['hostname'] = resolveip(ip)
            else:
                hostlookup[ip] = {}
                hostlookup[ip]['name'] = messageobj['hostname']
        except:
            print(f"ERROR: Failed to decode data '{self.request[0]}' - from {ip}")
            raise
        # WRITE LOG
        writelog(ip, messageobj['hostname'], json.dumps(messageobj))

def hostnamelookup(ip):
    """ Lookup the IP Address in our local DB """
    global hostlookup
    hostresolv = ip
    if ip in hostlookup:
        if 'name' in hostlookup[ip]:
            hostresolv = hostlookup[ip]['name']
    return hostresolv

def hostnameresolve(ip):
    """ Resolve the IP to hostname using reverse DNS """
    global hostlookup
    socket.setdefaulttimeout(0.5)  # Timeout in 500 milliseconds
    try:
        hostresolv = socket.gethostbyaddr(ip)
    except:
        hostresolv = ip
        # print("WARNING: No Host Lookup for IP: %s" % str(ip))
    return hostresolv

def resolveip(ip):
    """ Resolve IP - internal list, then DNS, thendirect ip """
    global hostlookup
    hostresolv = hostnamelookup(ip)
    if hostresolv == ip:  # If we have nothing in our DB continue
        hostlookup[ip] = {}
        hostlookup[ip]['Name'] = hostnameresolve(ip)
    else:
        hostlookup[ip]['ttl'] = 300
    if 'ttl' not in hostlookup[ip]:
        print(f"INFO: New Host {hostresolv}")
        hostlookup[ip]['ttl'] = 300
    return hostresolv

def log_group_exists(log_group_name):
    """ Returns a true/false if the log group exists """
    try:
        response = cwlogs.describe_log_groups(
            logGroupNamePrefix=log_group_name
        )
        # Iterate through the returned log groups to find an exact match
        for lg in response['logGroups']:
            if lg['logGroupName'] == log_group_name:
                return True
        return False
    except ClientError as e:
        print(f"ERROR: An error occurred: {e}")
        return False

def createloggroup(log_group_name, retentiondays=30):
    """ Create AWS CloudWatch Logs Log Group """
    if not log_group_exists(log_group_name):
        print(f"INFO: Creating Log Group {log_group_name}")
        try:
            cwlogs.create_log_group(
                logGroupName=log_group_name,
                tags={
                    'owner': 'pysyslog.py'
                },
                logGroupClass='STANDARD'
            )
        except ClientError as e:
            print(f"ERROR: Unable to Create Log Group. {e}")
        try:
            cwlogs.put_retention_policy(
                logGroupName=log_group_name,
                retentionInDays=retentiondays
            )
        except ClientError as e:
            print(f"ERROR: Unable to add retention policy to Log Group. {e}")
    else:
        print(f"INFO: Log Group {log_group_name} already exists")

def writelog(ip,hostresolv,data):
    """ Write Log to CloudWatch """
    global hostlookup
    timestamp = int(time.time()*1000)
    # If LogStream exists set streamok to True, if not create the stream
    if 'streamok' not in hostlookup[ip]:
        try:
            response = cwlogs.describe_log_streams(
                logGroupName = CWLOGGROUPNAME,
                logStreamNamePrefix = hostresolv
            )
        except ClientError as e:
            print(f"WARNING: Unable to Describe Log Stream - It may not exist (That's OK) {e}")
            response = {'LogStreams': []}
        for stream in response['logStreams']:
            if stream['logStreamName'] == hostresolv:
                hostlookup[ip]['streamok'] = True
        if 'streamok' not in hostlookup[ip]:
            print(f"INFO: Creating New Log Stream: {CWLOGGROUPNAME}:{hostresolv}")
            try:
                response = cwlogs.create_log_stream(
                    logGroupName = CWLOGGROUPNAME,
                    logStreamName = hostresolv
                )
                response = cwlogs.put_log_events(
                    logGroupName = CWLOGGROUPNAME,
                    logStreamName = hostresolv,
                    logEvents=[
                        {
                            'timestamp': timestamp,
                            'message': 'New Log Stream Created'
                        }
                    ]
                )
            except ClientError as e:
                print(f"ERROR: Unable to Create Log Stream for {ip}. {e}")
    # Write Log to Log Stream
    try:
        print(f"{timestamp}: Writing Log: {hostresolv}")
        response = cwlogs.put_log_events(
            logGroupName = CWLOGGROUPNAME,
            logStreamName = hostresolv,
            logEvents=[
                {
                    'timestamp': timestamp,
                    'message': data
                }
            ]
        )
    except ClientError as e:
        print(f"ERROR:{hostlookup[ip]}")
        print(f"ERROR Writing Log: {e}")
        if 'ttl' in hostlookup[ip]:
            del hostlookup[ip]['ttl']

def readhostinfo(filename):
    """ Read our json file with host information """
    hostfile = {}
    try:
        with open(filename,encoding='utf-8') as json_file:
            hostfile = json.load(json_file)
            print(f"INFO: Reading in Host file {filename}")
    except:
        print("WARNING: No Hostfile available or invalid")
    return hostfile

if __name__ == "__main__":
    print("INFO: Starting PySyslog")
    # Read in the Static Database (ip to hostname lookup)
    hostlookup = readhostinfo('/pysyslog/hosts.json')
    # Check and Display what creds are being used
    try:
        sts = boto3.client('sts')
        creds = sts.get_caller_identity()
        print(f"INFO: Using AWS Identity: {creds['Arn']}")
    except ClientError as e:
        print(f"CRITICAL: AWS Credentials are NOT valid. {e}")
    # Exit here if we are testing basic functionality
    if len(sys.argv) == 2:
        if str(sys.argv[1]) == "test":
            sys.exit()
    # Create Log Group if it doesn't exist
    createloggroup(CWLOGGROUPNAME, 30)
    # Setup Log connection and listen on port
    try:
        server = socketserver.UDPServer((HOST,PORT), SyslogUDPHandler)
        server.serve_forever(poll_interval=0.01)
    except IOError:
        print("CRITICAL: I/O Error Occured")
        try:
            print(f"INFO: Failure may have occured with host: {hostlookup}")
        except:
            print("ERROR: Error printing hostlookup environment")
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print ("INFO: Crtl+C Pressed. Shutting down.")
