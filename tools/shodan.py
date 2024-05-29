import requests
from colorama import Fore

def get_shodan_data(api_key, ip):
    url = f'https://api.shodan.io/shodan/host/{ip}?key={api_key}'
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"{Fore.RED}Error: {response.status_code}, Response: {response.text}")
        return None
