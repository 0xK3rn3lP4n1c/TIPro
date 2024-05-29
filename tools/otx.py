import requests
from colorama import Fore, Style

def get_otx_data(api_key, ip_or_domain, request_type='ip'):
    headers = {'X-OTX-API-KEY': api_key}
    if request_type == 'ip':
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_or_domain}/general"
    else:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ip_or_domain}/general"
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None
