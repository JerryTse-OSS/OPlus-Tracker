#!/usr/bin/env python3
"""
ColorOS Update Log Query Tool
Designed by Jerry Tse
"""

import sys
import re
import json
import argparse
import requests

REGION_CONFIG = {
    "cn": {"host": "component-ota-cn.allawntech.com", "language": "zh-CN", "carrier_id": "10010111"},
    "cn_cmcc": {"host": "component-ota-cn.allawntech.com", "language": "zh-CN", "carrier_id": "10011000"},
    "eu": {"host": "component-ota-eu.allawnos.com", "language": "en-GB", "carrier_id": "01000100"},
    "in": {"host": "component-ota-in.allawnos.com", "language": "en-IN", "carrier_id": "00011011"},
    "sg_host": {"host": "component-ota-sg.allawnos.com"},
    "sg": {"language": "en-SG", "carrier_id": "01011010"},
    "ru": {"language": "ru-RU", "carrier_id": "00110111"},
    "tr": {"language": "tr-TR", "carrier_id": "01010001"},
    "th": {"language": "th-TH", "carrier_id": "00111001"},
    "gl": {"language": "en-US", "carrier_id": "10100111"},
    "id": {"language": "id-ID", "carrier_id": "00110011"},
    "tw": {"language": "zh-TW", "carrier_id": "00011010"},
    "my": {"language": "ms-MY", "carrier_id": "00111000"},
    "vn": {"language": "vi-VN", "carrier_id": "00111100"},
    "sa": {"language": "sa-SA", "carrier_id": "10000011"},
    "mea": {"language": "en-MEA", "carrier_id": "10100110"},
    "ph": {"language": "en-PH", "carrier_id": "001111110"},
    "roe": {"language": "en-EU", "carrier_id": "10001101"},
    "la": {"language": "en-LA", "carrier_id": "10011010"},
    "br": {"language": "en-BR", "carrier_id": "10011110"}
}

VALID_REGIONS = [r for r in REGION_CONFIG.keys() if r != "sg_host"]
CHINA_REGIONS = ["cn", "cn_cmcc"]  # Use bullet prefix for Chinese regions

def extract_url_from_link(link_str: str) -> str:
    match = re.search(r'href\s*=\s*"([^"]+)"', link_str)
    return match.group(1) if match else link_str.strip()

def format_output(data: dict, region: str) -> None:
    upg_inst_detail = data.get('upgInstDetail', [])
    if not upg_inst_detail:
        print("No update details found.")
        return

    use_bullet = region in CHINA_REGIONS
    first_printed = False

    for item in upg_inst_detail:
        # Regular update categories (with children)
        if 'children' in item:
            if first_printed:
                print()
            for child in item['children']:
                title = child.get('title', '')
                content_list = child.get('content', [])
                if title:
                    print(title)
                for content_item in content_list:
                    text = content_item.get('data', '') if isinstance(content_item, dict) else content_item
                    if text:
                        if use_bullet:
                            print(f"· {text}")
                        else:
                            print(text)
            first_printed = True

        # Link item (may have content text, or just link)
        elif 'link' in item:
            if first_printed:
                print()
            content_text = item.get('content', '')
            if content_text:
                print(content_text)
            link_html = item.get('link', '')
            if link_html:
                url = extract_url_from_link(link_html)
                print(url)
            first_printed = True

        # Important notes (multilingual)
        elif item.get('type') == 'updateTips':
            if first_printed:
                print()
            title = item.get('title', 'Important Notes')
            print(title)
            tips_content = item.get('content', '')
            if tips_content:
                print(tips_content)
            first_printed = True

def main():
    parser = argparse.ArgumentParser(
        description='ColorOS Update Log Query Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python3 %(prog)s PHN110_11.H.19_3190
"""
    )
    parser.add_argument('ota_prefix', metavar='OTA_Prefix',
                        help='OTA prefix containing exactly two underscores (e.g., PHN110_11.H.19_3190)')
    
    parser.add_argument('region', choices=sorted(VALID_REGIONS), help='Region code')
    args = parser.parse_args()

    version_prefix = args.ota_prefix
    region = args.region

    if version_prefix.count('_') != 2:
        parser.error(f"OTA_Prefix '{version_prefix}' must contain exactly two underscores.")

    if region not in VALID_REGIONS:
        available = ", ".join(sorted(VALID_REGIONS))
        print(f"\n❌ Error: Invalid region '{region}'. Available regions: {available}")
        sys.exit(1)

    model = version_prefix.split('_')[0]

    if region in ["cn", "cn_cmcc", "eu", "in"]:
        config = REGION_CONFIG[region]
    else:
        config = REGION_CONFIG["sg_host"].copy()
        config.update(REGION_CONFIG[region])

    full_version = version_prefix + "_197001010000"

    url = "https://" + config["host"] + "/descriptionInfo"
    headers = {
        "language": config["language"],
        "nvCarrier": config["carrier_id"],
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
    payload = {"params": json.dumps(inner_params, ensure_ascii=False)}

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

    if resp_json.get('responseCode') == 500 and resp_json.get('errMsg') == 'no modify':
        print("No changelog in Server")
        sys.exit(0)

    if resp_json.get('responseCode') != 200:
        print(f"❌ API returned error code: {resp_json.get('responseCode')}")
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

    format_output(inner_data, region)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Script interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)