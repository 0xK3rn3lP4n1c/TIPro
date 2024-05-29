import requests
from colorama import Fore

def get_greynoise_data(api_key, ip):
    url = f'https://api.greynoise.io/v3/community/{ip}'
    headers = {
        'key': api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"{Fore.RED}Error: {response.status_code}, Response: {response.text}")
        return None
