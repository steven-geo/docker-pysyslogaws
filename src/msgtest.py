import syslogmessagehandler
import json
import sys

syslog_messages = [
    {
        "device": "pfsense 2.7.2",
        "syslogtype": "rfc5424",
        "message": "<134>1 2025-08-26T22:07:29.086608+10:00 myfirewallname filterlog 27816 - - 489,,,1531019476,lagg0.9,match,block,in,4,0x0,,1,0,0,DF,17,udp,149,192.168.31.110,224.0.2.15,30002,30003,129",
        "hostname": "myfirewallname"
    },
    {
        "device": "pfsense 2.7.2",
        "syslogtype": "rfc5424",
        "message": '<174>1 2025-08-26T22:08:15.000000+10:00 pfsense.domainname nginx - - - 192.168.1.56 - hass [26/Aug/2025:22:08:15 +1000] "POST /xmlrpc.php HTTP/1.1" 200 2949 "-" "Python-xmlrpc/3.13',
        "hostname": "pfsense.domainname"
    },
    {
        "device": "unifi controller 9.3.45",
        "syslogtype": "rfc3164_long",
        "message": "<4>Aug 26 21:26:14 UnifiDeviceName 012345678901,UAP-AC-Pro-Gen2-6.6.77+11452: kernel: [24213.573711] ath3: [90:0c:c0:00:00:00] station associated at aid 3: short preamble, short slot time, QoS, HT40 cap 0x511",
        "hostname": "WANT1AP1FamilyRm"
    },
    {
        "device": "unifi controller 9.3.45",
        "syslogtype": "rfc3164_short",
        "message": "<134>Aug 26 22:07:21 filterlog[27816]: 93,,,1000005670,lagg0,match,block,in,4,0x64,,128,4660,0,none,17,udp,284,192.168.77.140,192.168.22.255,62002,50000,264",
        "hostname": None
    },
    {
        "device": "pfsense 2.7.2",
        "syslogtype": "rfc5424",
        "message": "<13>1 2025-08-27T12:00:02.567447+10:00 firewall.domainame.com php 97909 - - '' - from 192.168.33.1",
        "hostname": "firewall.domainame.com"
    }
]

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color
FAILURES = 0

for message in syslog_messages:
    print(f"SYSLOG MESSAGE {message['syslogtype']}")
    print(message['message'])
    sysdict = syslogmessagehandler.decode_syslog(message['message'])
    # Test Hostname is Correct
    if sysdict['hostname'] == message['hostname']:
        print(f"HOSTNAME: {GREEN}PASS{NC}")
    else:
        print(f"HOSTNAME: {RED}FAIL{NC}  {sysdict['hostname']} should be {message['hostname']}")
    if sysdict['syslogtype'].upper() != message['syslogtype'].upper():
        print(json.dumps(sysdict,indent=4))
        FAILURES += 1
    else:
        print(f"TOTAL:    {GREEN}PASS{NC}")

sys.exit(FAILURES)