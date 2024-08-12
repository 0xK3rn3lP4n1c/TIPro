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

def format_json_pretty_html(data, indent=4):
    json_str = json.dumps(data, indent=indent)
    return f"<pre>{json_str}</pre>"

def calculate_red_shade(malicious_count, max_count=10):
    if malicious_count > max_count:
        malicious_count = max_count

    red_value = 255 - int((malicious_count / max_count) * 255)
    return f"rgb(255, {red_value}, {red_value})"

def format_json_with_toggles(data, parent_key=""):
    html_output = ""
    if isinstance(data, dict):
        for key, value in data.items():
            element_id = f"{parent_key}_{key}".replace(".", "_")
            if isinstance(value, (dict, list)):
                toggle_button = (
                    f'<div class="json-toggle" onclick="toggleJsonContent(\'{element_id}\')">'
                    f'<span id="arrow-{element_id}" class="arrow collapsed">▶</span>{key}</div>'
                )
                nested_content = format_json_with_toggles(value, element_id)
                html_output += (
                    f'<div class="json-container">{toggle_button}'
                    f'<div class="json-content" id="{element_id}">{nested_content}</div></div>'
                )
            else:  # Eğer değer basit bir türse, gösterim için bir kapsayıcıya alınabilir
                html_output += f'<div class="json-container"><strong>{key}:</strong> {json.dumps(value, indent=4)}</div>'
    elif isinstance(data, list):
        for index, item in enumerate(data):
            element_id = f"{parent_key}_{index}".replace(".", "_")
            if isinstance(item, (dict, list)):
                toggle_button = (
                    f'<div class="json-toggle" onclick="toggleJsonContent(\'{element_id}\')">'
                    f'<span id="arrow-{element_id}" class="arrow collapsed">▶</span>Item {index}</div>'
                )
                nested_content = format_json_with_toggles(item, element_id)
                html_output += (
                    f'<div class="json-container">{toggle_button}'
                    f'<div class="json-content" id="{element_id}">{nested_content}</div></div>'
                )
            else:  # Basit türler için direk gösterim
                html_output += f'<div class="json-container"><strong>Item {index}:</strong> {json.dumps(item, indent=4)}</div>'
    else:
        html_output += f"<pre>{json.dumps(data, indent=4)}</pre>"

    return html_output


def filter_fields(data, fields):
    filtered_data = {}
    for field in fields:
        keys = field.split('.')
        value = data
        for key in keys:
            value = value.get(key, None)
            if value is None:
                break
        if value is not None:
            filtered_data[keys[-1]] = value
    return filtered_data

def process_tool_output(tool_name, tool_data, malicious_key=None, max_count=10):
    formatted_data = format_json_with_toggles(tool_data)
    if malicious_key and tool_data.get(malicious_key, 0) > 0:
        malicious_count = tool_data.get(malicious_key, 0)
        background_color = calculate_red_shade(malicious_count, max_count)
        return f'<div class="{tool_name}" style="background-color: {background_color};">{formatted_data}</div>'
    else:
        return f'<div class="{tool_name}">{formatted_data}</div>'
