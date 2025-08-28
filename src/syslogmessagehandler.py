""" Syslog Message Decoder """
import re

syslog_facility = {
    "0": "kernel",
    "1": "user",
    "2": "mail system",
    "3": "system daemon",
    "4": "security/authorization",
    "5": "syslogd internal",
    "6": "line printer subsystem",
    "7": "network news subsystem",
    "8": "UUCP subsystem",
    "9": "clock daemon",
    "10": "security/authorization",
    "11": "FTP daemon",
    "12": "NTP subsystem",
    "13": "log audit",
    "14": "log alert",
    "15": "clock daemon",
    "16": "local0",
    "17": "local1",
    "18": "local2",
    "19": "local3",
    "20": "local4",
    "21": "local5",
    "22": "local6",
    "23": "local7"
}
syslog_levels = {
    "0": "EMERGENCY",
    "1": "ALERT",
    "2": "CRITICAL",
    "3": "ERROR",
    "4": "WARNING",
    "5": "NOTICE",
    "6": "INFO",
    "7": "DEBUG"
}

def facility_level(pid):
    """ Split the PID into Facility ID and Log Level ID """
    loglevel = int(pid) % 8
    facility = int((int(pid) - loglevel) / 8)
    # print(f"LOGLEVEL: {loglevel}   FACILITY:{facility}")
    return facility, loglevel


def decode_syslog(syslog_message):
    """ Decode a Syslog Message into a structured JSON Dictionary """
    msgdict = {}
    msgdict['syslogtype'] = None

    # DECODE RFC 5424
    match_rfc5424 = re.match(r"^\<?(\d+)\>?(\d+)\s(\S+)\s(\S+)\s?(\S+)\s?(\S+)\s?(\S+)\s?(-|\[.+?\])(?:\s?(.+))?$", syslog_message)
    # DECODE RFC3164
    match_rfc3164_long = re.match(r"^\<([0-9]{1,3})\>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s(\S+)\s(\S+:)\s([\S\s]+)$", syslog_message)  # Working LONG Format
    match_rfc3164_short = re.match(r"^\<([0-9]{1,3})\>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s([\S\s]+)$", syslog_message)  # Working SHORT Format
    if match_rfc5424 or match_rfc3164_long or match_rfc3164_short:
        if match_rfc5424:
            pid, version, timestamp, hostname, app_name, procid, msgid, structured_data, rawmessage = match_rfc5424.groups()
            msgdict['syslogtype'] = "RFC5424"
        elif match_rfc3164_long:
            pid, timestamp, hostname, app_name, rawmessage = match_rfc3164_long.groups()  # Working LONG Format
            msgdict['syslogtype'] = "RFC3164_long"
        elif match_rfc3164_short:
            pid, timestamp, rawmessage = match_rfc3164_short.groups()
            msgdict['syslogtype'] = "RFC3164_short"
        message = rawmessage if rawmessage is None else rawmessage.strip(':').strip(' ')
        msgdict['message'] = message
        msgdict['pid'] = pid
        fac, level = facility_level(pid)
        msgdict['facility'] = fac
        try:
            msgdict['facility_str'] = syslog_facility[str(fac)]
        except KeyError:
            msgdict['facility_str'] = "INVALID"
        msgdict['loglevel'] = level
        try:
            msgdict['loglevel_str'] = syslog_levels[str(level)]
        except KeyError:
            msgdict['loglevel_str'] = "INVALID"
        msgdict['timestamp'] = timestamp  # "Mmm dd hh:mm:ss"
        if 'hostname' in locals():
            msgdict['hostname'] = hostname
        else:
            msgdict['hostname'] = None
        if 'app_name' in locals():
            msgdict['app_name'] = app_name.strip(':').strip(' ')
        if match_rfc5424:
            msgdict['syslogversion'] = version
            msgdict['procid'] = procid
            msgdict['msgid'] = msgid
            msgdict['data'] = structured_data

    if msgdict['syslogtype'] is None:
        msgdict['syslogtype'] = "unknown"
        msgdict['message'] = syslog_message
        msgdict['hostname'] = None
        print(f"WARNING: Unknown Syslog Format Received: '{syslog_message}'")
    return msgdict

