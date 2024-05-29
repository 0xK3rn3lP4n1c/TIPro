import requests
from colorama import Fore

def get_urlhaus_data(domain):
    url = 'https://urlhaus-api.abuse.ch/v1/host/'
    response = requests.post(url, data={'host': domain})
    if response.status_code == 200:
        return response.json()
    else:
        print(f"{Fore.RED}Error: {response.status_code}, Response: {response.text}")
        return None
