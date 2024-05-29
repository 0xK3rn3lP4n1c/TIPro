import os
import argparse
import json
from colorama import Fore, Style, init
from dotenv import load_dotenv
from vt import is_ip_address, get_virustotal_data
from otx import get_otx_data
from abuseipdb import get_abuseipdb_data
from greynoise import get_greynoise_data
from urlhaus import get_urlhaus_data
from shodan import get_shodan_data
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
4. AbuseIPDB Query
5. GreyNoise Query
6. URLHaus Query
7. Shodan Query
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
    abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
    greynoise_api_key = os.getenv('GREYNOISE_API_KEY')
    shodan_api_key = os.getenv('SHODAN_API_KEY')
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
    if not abuseipdb_api_key:
        abuseipdb_api_key = input("Please enter your AbuseIPDB API key: ").strip()
        os.environ['ABUSEIPDB_API_KEY'] = abuseipdb_api_key
        with open('.env', 'a') as env_file:
            env_file.write(f"\nABUSEIPDB_API_KEY={abuseipdb_api_key}")
    if not greynoise_api_key:
        greynoise_api_key = input("Please enter your GreyNoise API key: ").strip()
        os.environ['GREYNOISE_API_KEY'] = greynoise_api_key
        with open('.env', 'a') as env_file:
            env_file.write(f"\nGREYNOISE_API_KEY={greynoise_api_key}")
    if not shodan_api_key:
        shodan_api_key = input("Please enter your Shodan API key: ").strip()
        os.environ['SHODAN_API_KEY'] = shodan_api_key
        with open('.env', 'a') as env_file:
            env_file.write(f"\nSHODAN_API_KEY={shodan_api_key}")
    return otx_api_key, vt_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key

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

def abuseipdb_query(abuseipdb_api_key, ip):
    abuseipdb_data = get_abuseipdb_data(abuseipdb_api_key, ip)
    if abuseipdb_data:
        print(format_json(abuseipdb_data))
    else:
        print(f"{Fore.RED}No data found in AbuseIPDB for {ip}")

def greynoise_query(greynoise_api_key, ip):
    greynoise_data = get_greynoise_data(greynoise_api_key, ip)
    if greynoise_data:
        print(format_json(greynoise_data))
    else:
        print(f"{Fore.RED}No data found in GreyNoise for {ip}")

def urlhaus_query(domain):
    urlhaus_data = get_urlhaus_data(domain)
    if urlhaus_data:
        print(format_json(urlhaus_data))
    else:
        print(f"{Fore.RED}No data found in URLHaus for {domain}")

def shodan_query(shodan_api_key, ip):
    shodan_data = get_shodan_data(shodan_api_key, ip)
    if shodan_data:
        print(format_json(shodan_data))
    else:
        print(f"{Fore.RED}No data found in Shodan for {ip}")

def recon_mode(vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, ip_or_domain, config):
    print("\nVirusTotal Data:")
    vt_query(vt_api_key, ip_or_domain, config)
    print("\nOTX Data:")
    otx_query(otx_api_key, ip_or_domain, config)
    print("\nAbuseIPDB Data:")
    abuseipdb_query(abuseipdb_api_key, ip_or_domain)
    print("\nGreyNoise Data:")
    greynoise_query(greynoise_api_key, ip_or_domain)
    if is_ip_address(ip_or_domain):
        print("\nShodan Data:")
        shodan_query(shodan_api_key, ip_or_domain)
    else:
        print("\nURLHaus Data:")
        urlhaus_query(ip_or_domain)

def process_bulk(file_path, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, mode):
    with open(file_path, 'r') as file:
        ip_or_domain_list = [line.strip() for line in file]
    
    for ip_or_domain in ip_or_domain_list:
        print(f"\nProcessing {ip_or_domain}\n" + "="*50)
        if mode == 'vt':
            vt_query(vt_api_key, ip_or_domain, config)
        elif mode == 'otx':
            otx_query(otx_api_key, ip_or_domain, config)
        elif mode == 'combined':
            recon_mode(vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, ip_or_domain, config)
        elif mode == 'abuseipdb':
            abuseipdb_query(abuseipdb_api_key, ip_or_domain)
        elif mode == 'greynoise':
            greynoise_query(greynoise_api_key, ip_or_domain)
        elif mode == 'urlhaus':
            urlhaus_query(ip_or_domain)
        elif mode == 'shodan':
            shodan_query(shodan_api_key, ip_or_domain)
        else:
            print(f"{Fore.RED}Invalid mode. Please choose --vt, --otx, --combined, --abuseipdb, --greynoise, --urlhaus, or --shodan.")
        print("\n" + "="*50 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Unified OTX and VirusTotal CLI")
    parser.add_argument('--configure', action='store_true', help="Configure fields to display")
    parser.add_argument('--bulk', help="Path to the file containing IPs/domains for bulk scan", required=False)
    parser.add_argument('--vt', action='store_true', help="VirusTotal query mode")
    parser.add_argument('--otx', action='store_true', help="OTX query mode")
    parser.add_argument('--combined', action='store_true', help="Combined (VT + OTX) query mode")
    parser.add_argument('--abuseipdb', action='store_true', help="AbuseIPDB query mode")
    parser.add_argument('--greynoise', action='store_true', help="GreyNoise query mode")
    parser.add_argument('--urlhaus', action='store_true', help="URLHaus query mode")
    parser.add_argument('--shodan', action='store_true', help="Shodan query mode")
    args = parser.parse_args()

    if args.configure:
        configure()
        return

    config = load_config()
    print(ASCII_ART)
    print(MENU)

    otx_api_key, vt_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key = check_api_keys()

    if args.bulk:
        if args.vt:
            process_bulk(args.bulk, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'vt')
        elif args.otx:
            process_bulk(args.bulk, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'otx')
        elif args.combined:
            process_bulk(args.bulk, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'combined')
        elif args.abuseipdb:
            process_bulk(args.bulk, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'abuseipdb')
        elif args.greynoise:
            process_bulk(args.bulk, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'greynoise')
        elif args.urlhaus:
            process_bulk(args.bulk, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'urlhaus')
        elif args.shodan:
            process_bulk(args.bulk, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'shodan')
        else:
            print(f"{Fore.RED}Please specify a mode for bulk processing: --vt, --otx, --combined, --abuseipdb, --greynoise, --urlhaus, or --shodan.")
        return

    choice = input("Choose an option (1/2/3/4/5/6/7): ").strip()
    ip_or_domain_input = input("Enter the IP or domain addresses separated by commas: ").strip()
    ip_or_domain_list = [item.strip() for item in ip_or_domain_input.split(',')]

    for ip_or_domain in ip_or_domain_list:
        print(f"\nProcessing {ip_or_domain}\n" + "="*50)
        if choice == '1':
            vt_query(vt_api_key, ip_or_domain, config)
        elif choice == '2':
            otx_query(otx_api_key, ip_or_domain, config)
        elif choice == '3':
            recon_mode(vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, ip_or_domain, config)
        elif choice == '4':
            abuseipdb_query(abuseipdb_api_key, ip_or_domain)
        elif choice == '5':
            greynoise_query(greynoise_api_key, ip_or_domain)
        elif choice == '6':
            urlhaus_query(ip_or_domain)
        elif choice == '7':
            shodan_query(shodan_api_key, ip_or_domain)
        else:
            print(f"{Fore.RED}Invalid choice. Please choose 1, 2, 3, 4, 5, 6, or 7.")
        print("\n" + "="*50 + "\n")

if __name__ == "__main__":
    main()
