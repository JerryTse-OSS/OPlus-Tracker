#!/usr/bin/env python3
"""
SOTA(Software OTA) Changelog Query
Designed by Jerry Tse
"""

import sys
import os
import json
import base64
import time
import re
import argparse
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Configuration ---

API_URL_QUERY = "https://component-ota-cn.allawntech.com/update/v6"
API_URL_UPDATE = "https://component-ota-cn.allawntech.com/sotaUpdate/v1"
API_URL_DESCRIPTION = "https://component-ota-cn.allawntech.com/sotaDescriptionInfo/v2"

PUBLIC_KEY_CN = """-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApXYGXQpNL7gmMzzvajHa
oZIHQQvBc2cOEhJc7/tsaO4sT0unoQnwQKfNQCuv7qC1Nu32eCLuewe9LSYhDXr9
KSBWjOcCFXVXteLO9WCaAh5hwnUoP/5/Wz0jJwBA+yqs3AaGLA9wJ0+B2lB1vLE4
FZNE7exUfwUc03fJxHG9nCLKjIZlrnAAHjRCd8mpnADwfkCEIPIGhnwq7pdkbamZ
coZfZud1+fPsELviB9u447C6bKnTU4AaMcR9Y2/uI6TJUTcgyCp+ilgU0JxemrSI
PFk3jbCbzamQ6Shkw/jDRzYoXpBRg/2QDkbq+j3ljInu0RHDfOeXf3VBfHSnQ66H
CwIDAQAB
-----END RSA PUBLIC KEY-----"""

DEFAULT_NEGOTIATION_VERSION = "1615879139745"

# --- Crypto Helpers ---

def generate_random_bytes(length: int) -> bytes:
    return os.urandom(length)

def aes_ctr_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def aes_ctr_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def generate_protected_key(aes_key: bytes, public_key_pem: str) -> str:
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(), backend=default_backend()
    )
    key_b64 = base64.b64encode(aes_key)
    ciphertext = public_key.encrypt(
        key_b64,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    )
    return base64.b64encode(ciphertext).decode()

# --- Common Functions ---

def parse_brand(brand_str: str) -> str:
    brand_lower = brand_str.strip().lower()
    if brand_lower == "oppo": return "OPPO"
    elif brand_lower == "oneplus": return "OnePlus"
    elif brand_lower == "realme": return "Realme"
    else: sys.exit(f"Error: Invalid brand '{brand_str}'. Supported: OPPO, OnePlus, Realme")

def build_headers(aes_key: bytes, public_key: str, config: Dict[str, str], is_update_request: bool = False) -> Dict[str, str]:
    protected_key_payload = generate_protected_key(aes_key, public_key)
    timestamp = str(time.time_ns() + 10**9 * 60 * 60 * 24)
    protected_key_json = json.dumps({
        "SCENE_1": {
            "protectedKey": protected_key_payload,
            "version": timestamp,
            "negotiationVersion": DEFAULT_NEGOTIATION_VERSION
        }
    })

    headers = {
        "language": "zh-CN",
        "colorOSVersion": config["coloros"],
        "androidVersion": "unknown",
        "infVersion": "1",
        "otaVersion": config["ota_version"],
        "model": config["model"],
        "mode": "taste",
        "nvCarrier": "10010111",
        "brand": config["brand"],
        "brandSota": config["brand"],
        "osType": "domestic_" + config["brand"],
        "version": "2",
        "deviceId": "0" * 64,
        "protectedKey": protected_key_json,
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "okhttp/4.12.0",
        "Accept-Encoding": "gzip"
    }
    
    if is_update_request:
        headers.update({"romVersion": config["rom_version"]})
    else:
        headers.update({"romVersion": "unknown"})
    return headers

def execute_query_request(config: Dict[str, str]) -> Tuple[Optional[Dict[str, Any]], Optional[bytes], Optional[bytes]]:
    aes_key = generate_random_bytes(32)
    iv = generate_random_bytes(16)
    headers = build_headers(aes_key, PUBLIC_KEY_CN, config, is_update_request=False)
    
    current_time = int(time.time() * 1000)
    ota_update_time = current_time - (15 * 24 * 60 * 60 * 1000)
    
    body = {
        "mode": 0,
        "time": current_time,
        "isRooted": "0",
        "isLocked": True,
        "type": "1",
        "securityPatch": "1970-01-01",
        "securityPatchVendor": "1970-01-01",
        "cota": {"cotaVersion": "", "cotaVersionName": "", "buildType": "user"},
        "opex": {"check": True},
        "sota": {
            "sotaProtocolVersion": "2",
            "sotaVersion": "V69P69",
            "otaUpdateTime": ota_update_time,
            "frameworkVer": "10",
            "supportLightH": "1",
            "updateViaReboot": 2,
            "sotaProtocolVersionNew": ["apk", "opex", "rus"]
        },
        "otaAppVersion": 16000021,
        "deviceId": "0" * 64
    }
    
    payload_str = json.dumps(body)
    cipher_text = aes_ctr_encrypt(payload_str.encode(), aes_key, iv)
    wrapped_data = {
        "params": json.dumps({
            "cipher": base64.b64encode(cipher_text).decode(),
            "iv": base64.b64encode(iv).decode()
        })
    }
    
    try:
        response = requests.post(API_URL_QUERY, headers=headers, json=wrapped_data, timeout=30)
        if response.status_code != 200:
            print(f"[!] Query failed with HTTP {response.status_code}")
            sys.exit(1)
        resp_json = response.json()
        if "body" not in resp_json:
            print("[!] Nothing in query response")
            sys.exit(1)
        encrypted_body = json.loads(resp_json["body"])
        decrypted_bytes = aes_ctr_decrypt(
            base64.b64decode(encrypted_body["cipher"]), 
            aes_key, 
            base64.b64decode(encrypted_body["iv"])
        )
        decrypted_json = json.loads(decrypted_bytes.decode())
        return decrypted_json, aes_key, iv
    except Exception:
        print("[!] Query error, something was wrong in arguments")
        sys.exit(1)

def execute_update_request(query_result: Dict[str, Any], config: Dict[str, str]) -> Optional[Dict[str, Any]]:
    if "sota" not in query_result:
        print("[!] No SOTA data found in query results")
        sys.exit(1)
    
    sota_data = query_result["sota"]
    new_sota_version = sota_data.get("sotaVersion", "")
    if not new_sota_version:
        print("[!] No SOTA version found in query results")
        sys.exit(1)
    
    apk_modules = sota_data.get("moduleMap", {}).get("apk", [])
    if not apk_modules:
        print("[!] No APK modules found in query results")
        sys.exit(1)
    
    # Generate lower version numbers for update request
    sau_modules = []
    for module in apk_modules:
        module_name = module.get("moduleName")
        latest_version = module.get("moduleVersion", 0)
        if isinstance(latest_version, int) and latest_version > 100:
            current_version = max(1, latest_version - (latest_version // 10))
        else:
            current_version = max(1, latest_version - 1)
        sau_modules.append({
            "sotaVersion": new_sota_version,
            "moduleName": module_name,
            "moduleVersion": current_version
        })
    
    body = {
        "sotaProtocolVersion": "2",
        "sotaProtocolVersionNew": ["apk", "opex", "rus"],
        "sotaVersion": "V69P69",
        "updateViaReboot": 2,
        "supportLightH": "1",
        "moduleMap": {"sau": sau_modules},
        "mode": 0,
        "deviceId": "0" * 64,
        "otaVersion": config["ota_version"]
    }
    
    update_aes_key = generate_random_bytes(32)
    update_iv = generate_random_bytes(16)
    headers = build_headers(update_aes_key, PUBLIC_KEY_CN, config, is_update_request=True)
    
    payload_str = json.dumps(body)
    cipher_text = aes_ctr_encrypt(payload_str.encode(), update_aes_key, update_iv)
    wrapped_data = {
        "params": json.dumps({
            "cipher": base64.b64encode(cipher_text).decode(),
            "iv": base64.b64encode(update_iv).decode()
        })
    }
    
    try:
        response = requests.post(API_URL_UPDATE, headers=headers, json=wrapped_data, timeout=30)
        if response.status_code != 200:
            print(f"[!] Update request failed with HTTP {response.status_code}")
            sys.exit(1)
        resp_json = response.json()
        if "body" not in resp_json:
            print("[!] Nothing in update response")
            sys.exit(1)
        encrypted_body = json.loads(resp_json["body"])
        decrypted_bytes = aes_ctr_decrypt(
            base64.b64decode(encrypted_body["cipher"]), 
            update_aes_key, 
            base64.b64decode(encrypted_body["iv"])
        )
        decrypted_json = json.loads(decrypted_bytes.decode())
        return decrypted_json
    except Exception as e:
        print(f"[!] Update error: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def fetch_sota_description(modules: List[Dict], sota_version: str, config: Dict[str, str]) -> Optional[Dict]:
    sota_list = []
    for mod in modules:
        sota_list.append({
            "sotaVersion": sota_version,
            "moduleName": mod["moduleName"],
            "moduleVersion": mod["moduleVersion"]
        })
    
    inner_params = {
        "otaVersion": config["ota_version"],
        "mode": 0,
        "deviceId": "0" * 64,
        "sota": sota_list,
        "sotaProtocolVersion": "2",
        "sotaVersion": sota_version,
        "noUpgradeModules": [],
        "h5LinkVersion": 6
    }
    params_str = json.dumps(inner_params, separators=(',', ':'), ensure_ascii=False)
    
    headers = {
        "language": "zh-CN",
        "brandSota": config["brand"].lower(),
        "sec-ch-ua-platform": "Android",
        "colorOSVersion": config["coloros"],
        "osType": "domestic_" + config["brand"],
        "romVersion": sota_version,
        "nvCarrier": "10010111",
        "mode": "manual",
        "osVersion": config["coloros"],
        "otaVersion": config["ota_version"],
        "model": config["model"],
        "uRegion": "undefined",
        "androidVersion": "unknown",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "User-Agent": "okhttp/4.12.0"
    }
    
    payload = {"params": params_str}
    try:
        response = requests.post(API_URL_DESCRIPTION, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"[!] Failed to fetch SOTA description: {str(e)}")
        return None

def extract_apk_modules(update_result: Dict[str, Any]) -> Tuple[str, List[Dict]]:
    sota_version = "Unknown"
    modules_list = []
    if "moduleMap" not in update_result:
        return sota_version, modules_list
    if "sota" in update_result and "sotaVersion" in update_result["sota"]:
        sota_version = update_result["sota"]["sotaVersion"]
    apk_modules = update_result["moduleMap"].get("apk", [])
    if not apk_modules:
        return sota_version, modules_list
    for apk in apk_modules:
        modules_list.append({
            "moduleName": apk.get("moduleName", "Unknown"),
            "moduleVersion": apk.get("moduleVersion", 0)
        })
        if sota_version == "Unknown" and "sotaVersion" in apk:
            sota_version = apk["sotaVersion"]
    return sota_version, modules_list

def print_changelog(sota_version: str, description_response: Dict):
    if not description_response:
        print("Not found sota changelog")
        return
        
    body_str = description_response.get("body")
    if body_str:
        try:
            data = json.loads(body_str)
        except Exception:
            data = description_response
    else:
        data = description_response

    module_map = data.get("moduleMap", {})
    apk_modules = module_map.get("apk", [])
    if not apk_modules:
        print("Not found apk changelog")
        return

    print(f"Get SOTA Changelog from {sota_version}\n")

    for module in apk_modules:
        desc_str = module.get("description", "{}")
        try:
            desc = json.loads(desc_str)
        except:
            continue

        title = desc.get("title")
        content_list = desc.get("content", [])
        if not content_list:
            continue

        print(title)
        for item in content_list:
            data_text = item.get("data", "")
            if data_text:
                print(data_text)
        print()

    default_desc = data.get("defaultDescription")
    if default_desc:
        desc_str = default_desc.get("description", "{}")
        try:
            desc = json.loads(desc_str)
            title = desc.get("title")
            content_list = desc.get("content", [])
            if content_list:
                print(title)
                for item in content_list:
                    data_text = item.get("data", "")
                    if data_text:
                        print(data_text)
                print()
        except:
            pass

def main(args):
    if not all([args.brand, args.ota_version, args.coloros]):
        print("❌ Error: All parameters are required")
        print("\nUsage Example:")
        print("  python3 sota_query.py --brand OnePlus \\")
        print("                       --ota-version PJX110_11.F.13_2130_202512181912 \\")
        print("                       --coloros ColorOS16.0.0 \\")
        return
    
    brand = parse_brand(args.brand)

    config = {
        "brand": brand,
        "ota_version": args.ota_version,
        "model": args.ota_version.split('_')[0],
        "coloros": args.coloros,
        "rom_version": "unknown"
    }
    
    print(f"Device: {config['model']}")
    print(f"OS: {config['coloros'].replace('ColorOS', 'ColorOS ')}")
    print()

    query_result, _, _ = execute_query_request(config)
    if query_result is None:
        return
    
    update_result = execute_update_request(query_result, config)
    if update_result is None:
        return
    
    sota_version, modules_list = extract_apk_modules(update_result)
    if not modules_list:
        print("No available SOTA Update")
        return
    
    description_response = fetch_sota_description(modules_list, sota_version, config)

    print_changelog(sota_version, description_response)

def parse_args():
    parser = argparse.ArgumentParser(
        description='SOTA APK Query Tool - Changelog only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Example:
  python3 %(prog)s --brand OnePlus \\
                   --ota-version PJX110_11.F.13_2130_202512181912 \\
                   --coloros ColorOS16.0.0 \\"
        """
    )
    parser.add_argument('--brand', required=True, help='Device brand (e.g., OnePlus, OPPO)')
    parser.add_argument('--ota-version', required=True, help='OTA version (e.g., PJX110_11.F.13_2130_202512181912)')
    parser.add_argument('--coloros', required=True, help='ColorOS version (e.g., ColorOS16.0.0)')
    
    try:
        return parser.parse_args()
    except SystemExit:
        print("\nUsage Example:")
        print("  python3 sota_query.py --brand OnePlus \\")
        print("                       --ota-version PJX110_11.F.13_2130_202512181912 \\")
        print("                       --coloros ColorOS16.0.0 \\")
        sys.exit(1)

if __name__ == "__main__":
    args = parse_args()
    try:
        main(args)
    except KeyboardInterrupt:
        print("\n\n⚠️  Script interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
