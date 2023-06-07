########################################################################################################################
### Author: zp-4                                                                                                     ###
### Date: 07/06/2023                                                                                                 ###
### Description: This scripts queries MISP REST API to check if IOC is already present IN MISP DATABASE.             ###
### It may be used to know which IOC are not in MISP and search for hits in your SIEM or other tools                 ###
### Script: check.py                                                                                                 ###
### requirements: pip install requests                                                                               ###
### API Key: Must provide API key from your MISP (the script take the key as input)                                  ###
########################################################################################################################


import re
import requests
import urllib3
import ipaddress
from getpass import getpass

# Disable insecure request warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MISP_URL = 'MISP_URL'
VERIFY_SSL = False
## Don't forget to add proxy configuration if needed. Uncomment proxy conf below and add proxies= PROXY to requests 
"""
PROXY = {
  'http':'http_proxy_address',
  'https':'https_proxy_address'
"""

def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def is_domain(value):
    # Regular expression pattern to validate domain names
    domain_pattern = r"^(?:[-A-Za-z0-9]+\.)+[A-Za-z]{2,}$"
    return re.match(domain_pattern, value) is not None

def extract_ip_or_domain(url):
    # Extract IP address or domain from the URL
    pattern = r"(?:http[s]?://)?([^/:]+)"
    match = re.search(pattern, url)
    if match:
        return match.group(1)
    return None

def validate_misp_key(key):
    headers = {
        "Authorization": key,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    response = requests.get(f"{MISP_URL}/servers/getPyMISPVersion", headers=headers, verify=VERIFY_SSL)
    return response.status_code == 200

def get_misp_api_key():
    attempts = 0
    while attempts < 3:
        key = getpass("Enter MISP API key: ")
        if validate_misp_key(key):
            return key
        else:
            attempts += 1
            print("Invalid API key. Please try again.")

    print("Exceeded maximum number of attempts. Exiting program.")
    exit()

def get_iocs_not_present_in_misp(iocs, api_key):
    iocs_not_present = []
    ips_not_present = []
    domains_not_present = []
    
    headers = {
        "Authorization": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    data = {
        "returnFormat": "json",
        "value": iocs
    }
    response = requests.post(f"{MISP_URL}/attributes/restSearch",
                             headers=headers,
                             json=data,
                             verify=VERIFY_SSL)
    response.raise_for_status()
    result = response.json()['response']['Attribute']
    
    if isinstance(result, list):
        misp_iocs = [entry["value"] for entry in result]
        iocs_not_present = list(set(iocs) - set(misp_iocs))
    
    for ioc in iocs_not_present:
        if is_ip(ioc):
            ips_not_present.append(ioc)
        elif is_domain(ioc):
            domains_not_present.append(ioc)
    
    ips_not_present = ",".join(ips_not_present) if ips_not_present else ""
    domains_not_present = ",".join(domains_not_present) if domains_not_present else ""
        
    return ips_not_present, domains_not_present


# Read URLs from file
with open("urls.txt", "r") as file:
    urls = file.readlines()

# Clean and extract IPs/domains from URLs
iocs = []
for url in urls:
    url = url.strip()
    ioc = extract_ip_or_domain(url)
    if ioc:
        iocs.append(ioc)

# Prompt for MISP API key
misp_key = get_misp_api_key()

# Check if the API key is valid
if not misp_key:
    print("Exiting...")
    exit()

# Check if IOCs are not present in MISP
ips_not_present, domains_not_present = get_iocs_not_present_in_misp(iocs, misp_key)

# Print the results
print("IPs not present in MISP:")
print(ips_not_present)
print("Domains not present in MISP:")
print(domains_not_present)
