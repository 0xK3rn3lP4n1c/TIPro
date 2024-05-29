import requests
from colorama import Fore

def get_abuseipdb_data(api_key, ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"{Fore.RED}Error: {response.status_code}, Response: {response.text}")
        return None
