import re
import requests

def is_ip_address(input_str):
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    ipv6_pattern = re.compile(r'^[a-fA-F0-9:]+$')
    return bool(ipv4_pattern.match(input_str) or ipv6_pattern.match(input_str))

def get_virustotal_data(api_key, ip_or_domain, request_type='ip'):
    headers = {'x-apikey': api_key}
    if request_type == 'ip':
        report_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_or_domain}"
    else:
        report_url = f"https://www.virustotal.com/api/v3/domains/{ip_or_domain}"
    response = requests.get(report_url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}, Response: {response.text}")
        return None
