import json
from colorama import Fore, Style

def format_json(data, indent=2):
    json_str = json.dumps(data, indent=indent)
    colored_str = ""
    in_string = False
    for char in json_str:
        if char == '"':
            in_string = not in_string
            colored_str += f"{Fore.CYAN}{char}{Style.RESET_ALL}" if in_string else f"{Fore.GREEN}{char}{Style.RESET_ALL}"
        elif in_string and char != '"':
            colored_str += f"{Fore.GREEN}{char}{Style.RESET_ALL}"
        elif char == ":":
            colored_str += f"{Fore.YELLOW}{char}{Style.RESET_ALL}"
        else:
            colored_str += char
    return colored_str
