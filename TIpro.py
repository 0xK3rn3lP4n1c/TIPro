import os
import re
import argparse
import json
from colorama import Fore, Style, init
from dotenv import load_dotenv
from tools.vt import is_ip_address, get_virustotal_data
from tools.otx import get_otx_data
from tools.abuseipdb import get_abuseipdb_data
from tools.greynoise import get_greynoise_data
from tools.urlhaus import get_urlhaus_data
from tools.shodan import get_shodan_data
from tools.jsonify import format_json

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
8. CTI Scan (HTML Output)
"""

CONFIG_FILE = "config.json"

def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w') as file:
            json.dump({"virustotal": ["last_analysis_stats", "whois"], "otx": ["sections", "whois", "alexa"], "cti_scan": ["vt", "otx", "abuseipdb", "greynoise", "shodan", "urlhaus"]}, file)
    with open(CONFIG_FILE, 'r') as file:
        return json.load(file)

def configure_fields(config):
    print("Configure VirusTotal fields:")
    vt_fields = input("Enter VirusTotal fields to display (comma separated): ").strip().split(',')
    if vt_fields != ['']:
        config['virustotal'] = [field.strip() for field in vt_fields]

    print("Configure OTX fields:")
    otx_fields = input("Enter OTX fields to display (comma separated): ").strip().split(',')
    if otx_fields != ['']:
        config['otx'] = [field.strip() for field in otx_fields]

def configure_cti_scan(config):
    tools_menu = """
    Select tools to use in CTI Scan (comma separated numbers):
    1. VirusTotal
    2. OTX
    3. AbuseIPDB
    4. GreyNoise
    5. Shodan
    6. URLHaus
    """
    print(tools_menu)
    selected_tools = input("Enter your choices: ").strip().split(',')
    if selected_tools != ['']:
        tools_mapping = {
            '1': 'vt',
            '2': 'otx',
            '3': 'abuseipdb',
            '4': 'greynoise',
            '5': 'shodan',
            '6': 'urlhaus'
        }
        config['cti_scan'] = [tools_mapping[choice.strip()] for choice in selected_tools if choice.strip() in tools_mapping]

def save_config(config):
    with open(CONFIG_FILE, 'w') as file:
        json.dump(config, file, indent=4)
    print("Configuration saved.")

def configure(args):
    config = load_config()
    if args.fields:
        configure_fields(config)
    if args.cti_scan:
        configure_cti_scan(config)
    save_config(config)

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
        return format_json(filtered_data)
    else:
        return f"{Fore.RED}No data found in VirusTotal for {ip_or_domain}"

def otx_query(otx_api_key, ip_or_domain, config):
    request_type = 'ip' if is_ip_address(ip_or_domain) else 'domain'
    otx_data = get_otx_data(otx_api_key, ip_or_domain, request_type)
    if otx_data:
        filtered_data = filter_fields(otx_data, config['otx'])
        return format_json(filtered_data)
    else:
        return f"{Fore.RED}No data found in OTX for {ip_or_domain}"

def abuseipdb_query(abuseipdb_api_key, ip):
    abuseipdb_data = get_abuseipdb_data(abuseipdb_api_key, ip)
    if abuseipdb_data:
        return format_json(abuseipdb_data)
    else:
        return f"{Fore.RED}No data found in AbuseIPDB for {ip}"

def greynoise_query(greynoise_api_key, ip):
    greynoise_data = get_greynoise_data(greynoise_api_key, ip)
    if greynoise_data:
        return format_json(greynoise_data)
    else:
        return f"{Fore.RED}No data found in GreyNoise for {ip}"

def urlhaus_query(domain):
    urlhaus_data = get_urlhaus_data(domain)
    if urlhaus_data:
        return format_json(urlhaus_data)
    else:
        return f"{Fore.RED}No data found in URLHaus for {domain}"

def shodan_query(shodan_api_key, ip):
    shodan_data = get_shodan_data(shodan_api_key, ip)
    if shodan_data:
        return format_json(shodan_data)
    else:
        return f"{Fore.RED}No data found in Shodan for {ip}"

def recon_mode(vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, ip_or_domain, config):
    results = []
    results.append(f"\nVirusTotal Data:\n{vt_query(vt_api_key, ip_or_domain, config)}")
    results.append(f"\nOTX Data:\n{otx_query(otx_api_key, ip_or_domain, config)}")
    results.append(f"\nAbuseIPDB Data:\n{abuseipdb_query(abuseipdb_api_key, ip_or_domain)}")
    results.append(f"\nGreyNoise Data:\n{greynoise_query(greynoise_api_key, ip_or_domain)}")
    if is_ip_address(ip_or_domain):
        results.append(f"\nShodan Data:\n{shodan_query(shodan_api_key, ip_or_domain)}")
    else:
        results.append(f"\nURLHaus Data:\n{urlhaus_query(ip_or_domain)}")
    return "\n".join(results)

def process_and_collect_results(ip_or_domain_list, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, mode):
    results = []
    for ip_or_domain in ip_or_domain_list:
        result_data = {"id": ip_or_domain.replace('.', '_').replace(':', '_'), "title": f"Results for {ip_or_domain}", "data": ""}
        if mode == 'vt':
            result_data["data"] = vt_query(vt_api_key, ip_or_domain, config)
        elif mode == 'otx':
            result_data["data"] = otx_query(otx_api_key, ip_or_domain, config)
        elif mode == 'combined':
            result_data["data"] = recon_mode(vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, ip_or_domain, config)
        elif mode == 'abuseipdb':
            result_data["data"] = abuseipdb_query(abuseipdb_api_key, ip_or_domain)
        elif mode == 'greynoise':
            result_data["data"] = greynoise_query(greynoise_api_key, ip_or_domain)
        elif mode == 'urlhaus':
            result_data["data"] = urlhaus_query(ip_or_domain)
        elif mode == 'shodan':
            result_data["data"] = shodan_query(shodan_api_key, ip_or_domain)
        elif mode == 'cti_scan':
            selected_tools = config.get('cti_scan', [])
            result_data["data"] = ""
            if 'vt' in selected_tools:
                result_data["data"] += f"VirusTotal:\n{vt_query(vt_api_key, ip_or_domain, config)}\n\n"
            if 'otx' in selected_tools:
                result_data["data"] += f"OTX:\n{otx_query(otx_api_key, ip_or_domain, config)}\n\n"
            if 'abuseipdb' in selected_tools:
                result_data["data"] += f"AbuseIPDB:\n{abuseipdb_query(abuseipdb_api_key, ip_or_domain)}\n\n"
            if 'greynoise' in selected_tools:
                result_data["data"] += f"GreyNoise:\n{greynoise_query(greynoise_api_key, ip_or_domain)}\n\n"
            if 'shodan' in selected_tools and is_ip_address(ip_or_domain):
                result_data["data"] += f"Shodan:\n{shodan_query(shodan_api_key, ip_or_domain)}\n\n"
            if 'urlhaus' in selected_tools and not is_ip_address(ip_or_domain):
                result_data["data"] += f"URLHaus:\n{urlhaus_query(ip_or_domain)}\n\n"
        results.append(result_data)
    return results

def remove_color_codes(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def generate_html_report(results):
    with open('template.html', 'r') as template_file:
        template = template_file.read()

    content = ""
    for result in results:
        cleaned_data = remove_color_codes(result["data"])
        section = f"""
        <div class="container">
            <div class="toggle" onclick="toggleContent('{result["id"]}')">{result["title"]}</div>
            <div class="content" id="{result["id"]}">
                <pre>{cleaned_data}</pre>
            </div>
        </div>
        """
        content += section

    html_content = template.replace("{{content}}", content)
    with open('report.html', 'w') as report_file:
        report_file.write(html_content)

def process_bulk(file_path, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, mode):
    with open(file_path, 'r') as file:
        ip_or_domain_list = [line.strip() for line in file]
    
    results = process_and_collect_results(ip_or_domain_list, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, mode)
    if mode == 'cti_scan':
        generate_html_report(results)
    else:
        for result in results:
            print(f"\n{result['title']}\n{result['data']}\n")

def main():
    parser = argparse.ArgumentParser(description="Unified CTI Tool")
    parser.add_argument('--configure', action='store_true', help="Configure the tool")
    parser.add_argument('--fields', action='store_true', help="Configure fields to display (used with --configure)")
    parser.add_argument('--cti-scan', action='store_true', help="Configure tools for CTI Scan (used with --configure)")
    parser.add_argument('--bulk', help="Path to the file containing IPs/domains for bulk scan", required=False)
    parser.add_argument('--vt', action='store_true', help="VirusTotal query mode")
    parser.add_argument('--otx', action='store_true', help="OTX query mode")
    parser.add_argument('--combined', action='store_true', help="Combined (VT + OTX) query mode")
    parser.add_argument('--abuseipdb', action='store_true', help="AbuseIPDB query mode")
    parser.add_argument('--greynoise', action='store_true', help="GreyNoise query mode")
    parser.add_argument('--urlhaus', action='store_true', help="URLHaus query mode")
    parser.add_argument('--shodan', action='store_true', help="Shodan query mode")
    parser.add_argument('--cti-scan-mode', action='store_true', help="CTI Scan mode (all tools, HTML output)")
    parser.add_argument('ip_or_domain', nargs='?', help="IP or domain to query directly")
    args = parser.parse_args()

    if args.configure:
        configure(args)
        return

    config = load_config()

    otx_api_key, vt_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key = check_api_keys()

    if args.ip_or_domain:
        ip_or_domain_list = [args.ip_or_domain]
        if args.vt:
            results = process_and_collect_results(ip_or_domain_list, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'vt')
        elif args.otx:
            results = process_and_collect_results(ip_or_domain_list, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'otx')
        elif args.combined:
            results = process_and_collect_results(ip_or_domain_list, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'combined')
        elif args.abuseipdb:
            results = process_and_collect_results(ip_or_domain_list, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'abuseipdb')
        elif args.greynoise:
            results = process_and_collect_results(ip_or_domain_list, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'greynoise')
        elif args.urlhaus:
            results = process_and_collect_results(ip_or_domain_list, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'urlhaus')
        elif args.shodan:
            results = process_and_collect_results(ip_or_domain_list, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'shodan')
        elif args.cti_scan_mode:
            results = process_and_collect_results(ip_or_domain_list, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'cti_scan')
            generate_html_report(results)
        else:
            print(f"{Fore.RED}Please specify a mode for processing: --vt, --otx, --combined, --abuseipdb, --greynoise, --urlhaus, --shodan, or --cti-scan-mode.")
            return
        for result in results:
            print(f"\n{result['title']}\n{result['data']}\n")
        return

    print(ASCII_ART)
    print(MENU)

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
        elif args.cti_scan_mode:
            process_bulk(args.bulk, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, 'cti_scan')
        else:
            print(f"{Fore.RED}Please specify a mode for bulk processing: --vt, --otx, --combined, --abuseipdb, --greynoise, --urlhaus, --shodan, or --cti-scan-mode.")
        return

    choice = input("Choose an option (1/2/3/4/5/6/7/8): ").strip()
    ip_or_domain_input = input("Enter the IP or domain addresses separated by commas: ").strip()
    ip_or_domain_list = [item.strip() for item in ip_or_domain_input.split(',')]

    mode = ''
    if choice == '1':
        mode = 'vt'
    elif choice == '2':
        mode = 'otx'
    elif choice == '3':
        mode = 'combined'
    elif choice == '4':
        mode = 'abuseipdb'
    elif choice == '5':
        mode = 'greynoise'
    elif choice == '6':
        mode = 'urlhaus'
    elif choice == '7':
        mode = 'shodan'
    elif choice == '8':
        mode = 'cti_scan'
    else:
        print(f"{Fore.RED}Invalid choice. Please choose 1, 2, 3, 4, 5, 6, 7, or 8.")
        return

    results = process_and_collect_results(ip_or_domain_list, vt_api_key, otx_api_key, abuseipdb_api_key, greynoise_api_key, shodan_api_key, config, mode)
    if mode == 'cti_scan':
        generate_html_report(results)
    else:
        for result in results:
            print(f"\n{result['title']}\n{result['data']}\n")

if __name__ == "__main__":
    main()
