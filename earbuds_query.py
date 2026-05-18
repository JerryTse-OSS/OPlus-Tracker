#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Earbuds OTA & Supported Devices Query Tool
Designed by Jerry Tse
"""

import sys
import time
import uuid
import hashlib
import hmac
import requests
import argparse

from config import EARBUDS_CONFIG

def generate_headers(data_str: str, host: str, secret_key: str) -> dict:
    """Generate request headers and HMAC-SHA1 signature"""
    time_stamp = str(int(time.time() * 1000))
    nonce = str(uuid.uuid4())
    
    sign = hmac.new(
        secret_key.encode('utf-8'), 
        data_str.encode('utf-8'), 
        hashlib.sha1
    ).hexdigest()
    
    return {
        'appid': 'earphone',
        'ts': time_stamp,
        'nonce': nonce,
        'sv': 'v1',
        'sign': sign,
        'Content-Type': 'application/json;charset=utf-8',
        'Host': host,
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/4.6.0'
    }

def get_cn_master_list() -> dict:
    """Internal method: Fetch the global master device list from CN region"""
    region_info = EARBUDS_CONFIG["regions"]["cn"]
    host = region_info["host"]
    secret_key = region_info["key"]
    
    url = f"https://{host}{EARBUDS_CONFIG['endpoints']['whitelist']}"
    data_str = '{"versionCode":"1001214","channel":"2","platform":"android"}'
    headers = generate_headers(data_str, host, secret_key)

    try:
        r = requests.post(url=url, headers=headers, data=data_str, timeout=10)
        r_json = r.json()
        if r_json.get('code') != 0:
            return {}
        
        whitelist = requests.get(r_json['data']['downloadUrl'], timeout=10).json()
        return {device["id"]: device["name"] for device in whitelist.get("compatWhiteList", [])}
    except:
        return {}

def get_devices(region: str):
    """Fetch and print the supported earbuds list for the specified region"""
    if region != "cn":
        print(f"[!] Note: The {region.upper()} region server does not configure a master whitelist.")
        print("[*] Fetching the CN global master list for reference...\n")
        devices = get_cn_master_list()
    else:
        devices = get_cn_master_list()
        
    if not devices:
        print("[!] Failed to fetch the whitelist.")
        sys.exit(1)
        
    print(f"=== Master Supported Devices ===")
    for dev_id, dev_name in devices.items():
        print(f"[{dev_id}] : {dev_name}")

def query_firmware(product_id: str, region: str):
    """Query firmware info for a specific productID in a specified region"""
    region_info = EARBUDS_CONFIG["regions"][region]
    host = region_info["host"]
    secret_key = region_info["key"]
    
    url = f"https://{host}{EARBUDS_CONFIG['endpoints']['firmware_info']}"
    lang = "zh_CN" if region == "cn" else "en_US"
    data_str = '{"language":"%s","productId":"%s","versionCode":"1001214","channel":"2","platform":"android"}' % (lang, product_id)
    headers = generate_headers(data_str, host, secret_key)

    try:
        print(f"Query for {product_id} Firmware\n")
        r = requests.post(url=url, headers=headers, data=data_str, timeout=10)
        r_json = r.json()
        
        if r_json.get('code') != 0 or "data" not in r_json:
            print(f"[!] Update not found or request rejected: {r_json}")
            sys.exit(1)
        
        content = r_json['data'].get('content', [])
        if not content:
            print(f"[!] No firmware available for {product_id} in the {region.upper()} region.")
            return

        size = content[0]['size']
        download_url = content[0]['url']
        version = r_json['data']['version']
        info = r_json['data']['updateInfo']
        device_name = r_json['data']['name']
        
        print(f"Device Name: {device_name}")
        print(f"Product ID : {product_id}")
        print(f"Region     : {region.upper()}")
        print(f"Version    : {version}")
        print(f"Size       : {size} Byte")
        print(f"Link       : {download_url}")
        print(f"Changelog  :{info}")
        
    except Exception as e:
        print(f"[!] Unknown error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="OPPO/OnePlus Earbuds OTA Query Tool",
        epilog="Examples:\n  python earbuds_query.py get\n  python earbuds_query.py 061410 cn",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "action", 
        help="'get' (List all devices), or 6-char Product ID"
    )
    
    # Changed region to be optional with nargs="?". Default is "cn" if omitted.
    parser.add_argument(
        "region", 
        nargs="?",
        default="cn",
        choices=["cn", "eu", "gl", "us"], 
        type=str.lower, 
        help="Region code (default: cn)"
    )
    
    args = parser.parse_args()
    action = args.action.strip().lower()
    region = args.region
    
    if action == "get":
        get_devices(region)
    elif len(action) == 6 and action.isalnum():
        query_firmware(action.upper(), region)
    else:
        print("[!] Error: Argument 1 must be a 6-character productID, 'get'.")
        sys.exit(1)

if __name__ == '__main__':
    main()
