#!/usr/bin/env python3
"""
ColorOS Update Log Query Tool
Designed by Jerry Tse (Adapted)
"""

import sys
import re
import json
import requests

def extract_url_from_link(link_str: str) -> str:
    """Extract href attribute value from an <a> tag."""
    match = re.search(r'href\s*=\s*"([^"]+)"', link_str)
    return match.group(1) if match else link_str

def format_output(data: dict) -> None:
    """Format and print the parsed update log."""
    upg_inst_detail = data.get('upgInstDetail', [])
    if not upg_inst_detail:
        print("No update details found.")
        return

    first_printed = True  # Track if any section has been printed yet

    for item in upg_inst_detail:
        # Normal category with 'children'
        if 'children' in item:
            if not first_printed:
                print()  # blank line between sections
            for child in item['children']:
                title = child.get('title', '')
                content_list = child.get('content', [])
                if title:
                    print(title)
                for content_item in content_list:
                    if isinstance(content_item, dict):
                        text = content_item.get('data', '')
                    else:
                        text = content_item
                    if text:
                        print(f"· {text}")
            first_printed = False

        # Special item containing link and content (e.g., community link)
        elif 'link' in item and 'content' in item:
            if not first_printed:
                print()
            content_text = item.get('content', '')
            link_html = item.get('link', '')
            if content_text:
                print(content_text)
            if link_html:
                url = extract_url_from_link(link_html)
                print(url)
            first_printed = False

        # "注意事项" (Important Notes) section
        elif item.get('title') == '注意事项':
            if not first_printed:
                print()
            print("Important Notes")
            tips_content = item.get('content', '')
            if tips_content:
                print(tips_content)
            first_printed = False

def print_usage():
    """Display usage information."""
    print("\nUsage:")
    print(f"  python3 {sys.argv[0]} <OTA_Prefix>")
    print("\nConstraints:")
    print("  <OTA_Prefix> : Must contain exactly two underscores (e.g., PHN110_11.H.19_3190)")
    print("\nExample:")
    print(f"  python3 {sys.argv[0]} PHN110_11.H.19_3190")

def main():
    if len(sys.argv) != 2:
        print_usage()
        sys.exit(1)

    version_prefix = sys.argv[1]

    # Validate exactly two underscores
    if version_prefix.count('_') != 2:
        print(f"\n❌ Error: OTA_Prefix '{version_prefix}' must contain exactly two underscores.")
        print_usage()
        sys.exit(1)

    # Extract model (part before first underscore)
    model = version_prefix.split('_')[0]

    # Build full version by appending the fixed suffix
    full_version = version_prefix + "_197001010000"

    # Prepare request data
    url = "https://component-ota-cn.allawntech.com/descriptionInfo"

    headers = {
        "language": "zh-CN",
        "nvCarrier": "10010111",
        "mode": "manual",
        "osVersion": "unknown",
        "maskOtaVersion": full_version,
        "otaVersion": full_version,
        "model": model,
        "androidVersion": "unknown",
        "Content-Type": "application/json"
    }

    inner_params = {
        "mode": 0,
        "maskOtaVersion": full_version,
        "bigVersion": 0,
        "h5LinkVersion": 6
    }
    payload = {
        "params": json.dumps(inner_params, ensure_ascii=False)
    }

    print(f"\nQuerying update log for {full_version}\n")

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=15)
    except Exception as e:
        print(f"❌ Network error: {e}")
        sys.exit(1)

    if response.status_code != 200:
        print(f"❌ HTTP error: {response.status_code}")
        sys.exit(1)

    try:
        resp_json = response.json()
    except json.JSONDecodeError:
        print("❌ Response is not valid JSON.")
        sys.exit(1)

    # 专门处理 "no modify" 错误
    if resp_json.get('responseCode') == 500 and resp_json.get('errMsg') == 'no modify':
        print("No changelog in Server")
        sys.exit(0)

    if resp_json.get('responseCode') != 200:
        print(f"❌ API returned error: {resp_json}")
        sys.exit(1)

    body_str = resp_json.get('body')
    if not body_str:
        print("❌ No 'body' field in response.")
        sys.exit(1)

    try:
        inner_data = json.loads(body_str)
    except json.JSONDecodeError:
        print("❌ 'body' content is not valid JSON.")
        sys.exit(1)

    format_output(inner_data)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Script interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)