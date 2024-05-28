import os
import argparse
import json
from colorama import Fore, Style, init
from dotenv import load_dotenv
from vt import is_ip_address, get_virustotal_data
from otx import get_otx_data
from jsonify import format_json

init(autoreset=True)
load_dotenv()

ASCII_ART = """
  _______ _____ _____           
 |__   __|_   _|  __ \          
    | |    | | | |__) | __ ___  
    | |    | | |  ___/ '__/ _ \ 
    | |   _| |_| |   | | | (_) |
    |_|  |_____|_|   |_|  \___/ 
"""

MENU = """
1. VirusTotal Query
2. OTX Query
3. Recon Mode (VT + OTX)
"""

CONFIG_FILE = "config.json"

def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w') as file:
            json.dump({"virustotal": ["last_analysis_stats", "whois"], "otx": ["sections", "whois", "alexa"]}, file)
    with open(CONFIG_FILE, 'r') as file:
        return json.load(file)

def configure():
    config = load_config()
    
    print("Configure VirusTotal fields:")
    vt_fields = input("Enter VirusTotal fields to display (comma separated): ").strip().split(',')
    config['virustotal'] = [field.strip() for field in vt_fields]
    
    print("Configure OTX fields:")
    otx_fields = input("Enter OTX fields to display (comma separated): ").strip().split(',')
    config['otx'] = [field.strip() for field in otx_fields]
    
    with open(CONFIG_FILE, 'w') as file:
        json.dump(config, file)
    print("Configuration saved.")

def check_api_keys():
    otx_api_key = os.getenv('OTX_API_KEY')
    vt_api_key = os.getenv('VT_API_KEY')
    if not otx_api_key:
        otx_api_key = input("Please enter your OTX API key: ").strip()
        os.environ['OTX_API_KEY'] = otx_api_key
        with open('.env', 'a') as env_file:
            env_file.write(f"\nOTX_API_KEY={otx_api_key}")
    if not vt_api_key:
        vt_api_key = input("Please enter your VirusTotal API key: ").strip()
        os.environ['VT_API_KEY'] = vt_api_key
        with open('.env', 'a') as env_file:
            env_file.write(f"\nVT_API_KEY={vt_api_key}")
    return otx_api_key, vt_api_key

def filter_fields(data, fields):
    return {key: data[key] for key in fields if key in data}

def vt_query(vt_api_key, ip_or_domain, config):
    request_type = 'ip' if is_ip_address(ip_or_domain) else 'domain'
    vt_data = get_virustotal_data(vt_api_key, ip_or_domain, request_type)
    if vt_data:
        filtered_data = filter_fields(vt_data['data']['attributes'], config['virustotal'])
        print(format_json(filtered_data))
    else:
        print(f"{Fore.RED}No data found in VirusTotal for {ip_or_domain}")

def otx_query(otx_api_key, ip_or_domain, config):
    request_type = 'ip' if is_ip_address(ip_or_domain) else 'domain'
    otx_data = get_otx_data(otx_api_key, ip_or_domain, request_type)
    if otx_data:
        filtered_data = filter_fields(otx_data, config['otx'])
        print(format_json(filtered_data))
    else:
        print(f"{Fore.RED}No data found in OTX for {ip_or_domain}")

def recon_mode(vt_api_key, otx_api_key, ip_or_domain, config):
    print("\nVirusTotal Data:")
    vt_query(vt_api_key, ip_or_domain, config)
    print("\nOTX Data:")
    otx_query(otx_api_key, ip_or_domain, config)

def main():
    parser = argparse.ArgumentParser(description="Unified OTX and VirusTotal CLI")
    parser.add_argument('--configure', action='store_true', help="Configure fields to display")
    parser.add_argument('--bulk', help="Path to the file containing IPs/domains for bulk scan", required=False)
    args = parser.parse_args()

    if args.configure:
        configure()
        return

    config = load_config()
    print(ASCII_ART)
    print(MENU)

    otx_api_key, vt_api_key = check_api_keys()

    choice = input("Choose an option (1/2/3): ").strip()
    ip_or_domain_input = input("Enter the IP or domain addresses separated by commas: ").strip()
    ip_or_domain_list = [item.strip() for item in ip_or_domain_input.split(',')]

    for ip_or_domain in ip_or_domain_list:
        print(f"\nProcessing {ip_or_domain}\n" + "="*50)
        if choice == '1':
            vt_query(vt_api_key, ip_or_domain, config)
        elif choice == '2':
            otx_query(otx_api_key, ip_or_domain, config)
        elif choice == '3':
            recon_mode(vt_api_key, otx_api_key, ip_or_domain, config)
        else:
            print(f"{Fore.RED}Invalid choice. Please choose 1, 2, or 3.")
        print("\n" + "="*50 + "\n")

if __name__ == "__main__":
    main()
