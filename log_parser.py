import os
import re
import argparse
import sys
import requests
import json

found_ips = {}

def argument_parse(): # argument parser + --help message 
    pars = argparse.ArgumentParser(
            prog='Log Parser on REGEX basis',
            description='A small log parser for Linux logs',
            usage='log_parser.py -f [FILE_NAME] -a [ERROR_TYPE]',
            epilog='Example: log_parser.py -f auth.log -a ERROR'
            )

    pars.add_argument(
            "-f", "--filename",
            required=True,
            help="Path to the required log"
            )

    pars.add_argument(
            "-a", "--alert_type",
            required=True,
            choices=["ERROR","INFO","WARNING","DEBUG","CRITICAL","Failed","Accepted"],
            help="Choose your alert type: ERROR, INFO, WARNING, DEBUG, CRITICAL,Failed,Accepted"
            )

    return pars.parse_args()

def log_parsing(file_path,alerttype):
    try:
        with open(file_path,"r") as log:
            for line in log:
                if alerttype in line: # Alert filter in lines
                    regex_pattern = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',line) # IP regex pattern, not perfect, 999.999.999 would work as well, needs changing in further versions
                    for ip in regex_pattern:
                        if ip in found_ips:
                            found_ips[ip] += 1 # if IP exists adds value in dictionary
                        else:   
                            found_ips[ip] = 1 # if does not exist, adds key and value into the dictionary
    
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
        sys.exit(1)

    except PermissionError:
        print(f"Error: File could not be opened, No permission")
        sys.exit(1)

def print_output(ips_dict,errortype):
    for key, value in ips_dict.items():
        if value >= 5:
            print(f" IP-Address {key} has been alerted with {errortype} 5 or more times and requires further investigation")

def is_private_ip(ip):
    private_ranges = ["192.168.", "10.", "172.16.", "127."]
    return any(ip.startswith(r) for r in private_ranges)

def api_hook(ip_addr):
    api_url = "https://api.abuseipdb.com/api/v2/check"
    api_key = os.environ.get("ABUSEIPDB_KEY")
    try:
        response = requests.get(api_url, headers={"Key": api_key, "Accept": "application/json"}, params={"ipAddress": ip_addr, "maxAgeInDays":90})

        if response.status_code == 200:
            response_data = response.json()["data"]
            print(f"IP: {response_data['ipAddress']}")
            print(f"Abuse Score: {response_data['abuseConfidenceScore']}")
            print(f"Country: {response_data['countryCode']}")
            print(f"ISP: {response_data['isp']}")
            print(f"Total Reports: {response_data['totalReports']}")
        elif response.status_code == 401:
            print("Error: Invalid API key")
            sys.exit(1)
        else:
            print(f"Error: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("Error: Connection to AbuseIPDB could not be established")
    
    except requests.exceptions.Timeout:
        print("Error: Requests timed out")

if __name__ == "__main__":
    args = argument_parse()
    log_parsing(args.filename, args.alert_type)
    print_output(found_ips, args.alert_type)

    for ip in found_ips:
        if not is_private_ip(ip):
            api_hook(ip)
        else:
            print(f"Skipping on private IP-{ip}")



