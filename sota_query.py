#!/usr/bin/env python3
"""
SOTA(Software OTA) Query
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

# API URLs
API_URL_QUERY = "https://component-ota-cn.allawntech.com/update/v6"
API_URL_UPDATE = "https://component-ota-cn.allawntech.com/sotaUpdate/v1"

# CN Region Public Key
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

def build_headers(aes_key: bytes, public_key: str, config: Dict[str, str], is_update_request: bool = False) -> Dict[str, str]:
    """Build headers for both query and update requests"""
    protected_key_payload = generate_protected_key(aes_key, public_key)
    timestamp = str(time.time_ns() + 10**9 * 60 * 60 * 24)
    
    protected_key_json = json.dumps({
        "SCENE_1": {
            "protectedKey": protected_key_payload,
            "version": timestamp,
            "negotiationVersion": DEFAULT_NEGOTIATION_VERSION
        }
    })

    # Base headers
    headers = {
        "language": "zh-CN",
        "newLanguage": "zh-CN",
        "colorOSVersion": config["coloros"],
        "androidVersion": "unknown",
        "infVersion": "1",
        "otaVersion": config["ota_version"],
        "model": config["model"],
        "mode": "taste",
        "nvCarrier": "10010111",
        "pipelineKey": "ALLNET",
        "operator": "ALLNET",
        "companyId": "",
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
    
    # Different headers for query vs update
    if is_update_request:
        headers.update({
            "romVersion": config["rom_version"]
        })
    else:
        headers.update({
            "romVersion": "unknown"
        })
    
    return headers

def execute_query_request(config: Dict[str, str]) -> Tuple[Optional[Dict[str, Any]], Optional[bytes], Optional[bytes]]:
    """Execute the query and return decrypted data, aes_key, and iv"""
    
    aes_key = generate_random_bytes(32)
    iv = generate_random_bytes(16)
    
    headers = build_headers(aes_key, PUBLIC_KEY_CN, config, is_update_request=False)
    
    # Build query body
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
        "cota": {
            "cotaVersion": "",
            "cotaVersionName": "",
            "buildType": "user"
        },
        "opex": {
            "check": True
        },
        "sota": {
            "sotaProtocolVersion": "2",
            "sotaVersion": config["current_sota"],
            "otaUpdateTime": ota_update_time,
            "frameworkVer": "10",
            "supportLightH": "1",
            "updateViaReboot": 2,
            "sotaProtocolVersionNew": ["apk", "opex", "rus"]
        },
        "otaAppVersion": 16000021,
        "deviceId": "0" * 64
    }
    
    # Encrypt and send request
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
        
        # Decrypt the response
        encrypted_body = json.loads(resp_json["body"])
        decrypted_bytes = aes_ctr_decrypt(
            base64.b64decode(encrypted_body["cipher"]), 
            aes_key, 
            base64.b64decode(encrypted_body["iv"])
        )
        decrypted_json = json.loads(decrypted_bytes.decode())
        
        return decrypted_json, aes_key, iv
        
    except Exception as e:
        print(f"[!] Query error, something was wrong in arguments")
        sys.exit(1)

def execute_update_request(query_result: Dict[str, Any], config: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """Execute the update using data from query result"""
    if "sota" not in query_result:
        print("[!] No SOTA data found in query results")
        sys.exit(1)
    
    sota_data = query_result["sota"]
    new_sota_version = sota_data.get("sotaVersion", "")
    sota_name = sota_data.get("sotaName", "")
    
    if not new_sota_version:
        print("[!] No SOTA version found in query results")
        sys.exit(1)
    
    # Get APK modules from query result
    apk_modules = sota_data.get("moduleMap", {}).get("apk", [])
    if not apk_modules:
        print("[!] No APK modules found in query results")
        sys.exit(1)
    
    # Generate lower version numbers for update request
    # In real usage, you would get current versions from device
    # Here we simulate by reducing version numbers
    sau_modules = []
    for module in apk_modules:
        module_name = module.get("moduleName")
        latest_version = module.get("moduleVersion", 0)
        
        # Create a lower version to trigger update
        # Strategy: reduce by ~5-10% of the version number
        if isinstance(latest_version, int) and latest_version > 100:
            current_version = max(1, latest_version - (latest_version // 10))
        else:
            current_version = max(1, latest_version - 1)
        
        sau_modules.append({
            "sotaVersion": new_sota_version,
            "moduleName": module_name,
            "moduleVersion": current_version
        })
    
    # Build update request body
    body = {
        "sotaProtocolVersion": "2",
        "sotaProtocolVersionNew": ["apk", "opex", "rus"],
        "sotaVersion": config["current_sota"],  # Current version on device
        "updateViaReboot": 2,
        "supportLightH": "1",
        "moduleMap": {
            "sau": sau_modules
        },
        "mode": 0,
        "deviceId": "0" * 64,
        "otaVersion": config["ota_version"]
    }
    
    # Use new aes_key and iv for update request
    update_aes_key = generate_random_bytes(32)
    update_iv = generate_random_bytes(16)
    
    headers = build_headers(update_aes_key, PUBLIC_KEY_CN, config, is_update_request=True)
    
    # Encrypt and send request
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
        
        # Decrypt the response
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

# --- Output Formatting ---

def extract_and_format_apk_info(update_result: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Extract APK information from update result and format as requested
    Returns: (sota_version, formatted_lines)
    """
    formatted_lines = []
    sota_version = "Unknown"
    
    # Check if moduleMap exists in the result
    if "moduleMap" not in update_result:
        print("[!] No moduleMap found in update result")
        return sota_version, formatted_lines
    
    # Check for sota version
    if "sota" in update_result and "sotaVersion" in update_result["sota"]:
        sota_version = update_result["sota"]["sotaVersion"]
    elif "components" in update_result and len(update_result["components"]) > 0:
        for component in update_result["components"]:
            if "sotaVersion" in component:
                sota_version = component["sotaVersion"]
                break
    
    # Check for apk modules
    apk_modules = update_result["moduleMap"].get("apk", [])
    
    if not apk_modules:
        print("[!] No APK modules found in update result")
        return sota_version, formatted_lines
    
    for apk in apk_modules:
        if "sotaVersion" in apk and sota_version == "Unknown":
            sota_version = apk["sotaVersion"]
            break
    
    # Format each APK module
    for i, apk in enumerate(apk_modules):
        # Extract fields
        apk_name = apk.get("moduleName", "Unknown")
        apk_version = apk.get("moduleVersion", "Unknown")
        apk_hash = apk.get("md5", "Unknown")
        apk_link = apk.get("manualUrl", "Unknown")
        
        # Format the output
        formatted_line = f"• Apk Name: {apk_name}\n• Apk Version: {apk_version}\n• Apk Hash: {apk_hash}\n• Link: {apk_link}"
        
        # Add separator between items (except for the last one)
        if i < len(apk_modules) - 1:
            formatted_line += "\n"
        
        formatted_lines.append(formatted_line)
    
    return sota_version, formatted_lines

def print_formatted_output(sota_version: str, formatted_lines: List[str]):
    """Print the formatted output as requested"""
    if not formatted_lines:
        print("\nNo APK information to display")
        return
    
    print("SOTA Apk Info:")
    print(f"\n· SOTA Version: {sota_version}\n")
    
    for line in formatted_lines:
        print(line)

# --- Main Execution ---

def main(args):
    """Main execution: run query, then update, then format output"""

    if not all([args.model, args.brand, args.ota_version, args.current_sota, 
                args.coloros]):
        print("❌ Error: All parameters are required")
        print("\nUsage Example:")
        print("  python3 sota_query.py --model PJX110 --brand OnePlus \\")
        print("                       --ota-version PJX110_11.F.13_2130_202512181912 \\")
        print("                       --current-sota \"V80P02(BRB1CN01)\" \\")
        print("                       --coloros ColorOS16.0.0 \\")
        return

    # Create config dictionary from args
    config = {
        "model": args.model,
        "brand": args.brand,
        "ota_version": args.ota_version,
        "current_sota": args.current_sota,
        "coloros": args.coloros,
        "rom_version": "unknown"
    }
    
    print(f"Device: {config['model']}")
    print(f"Current SOTA: {config['current_sota']}")
    print(f"OS: {config['coloros'].replace('ColorOS', 'ColorOS ')}")
    print()

    query_result, aes_key, iv = execute_query_request(config)
    
    if query_result is None:
        print("[!] Query failed. Cannot proceed with update.")
        return
    
    update_result = execute_update_request(query_result, config)
    
    if update_result is None:
        print("[!] Update failed. Cannot extract APK information.")
        return
    
    sota_version, formatted_lines = extract_and_format_apk_info(update_result)
    
    print_formatted_output(sota_version, formatted_lines)

def parse_args():
    """Parse command line arguments with validation and custom error handling"""
    parser = argparse.ArgumentParser(
        description='SOTA APK Query Tool - All parameters are required',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Example:
  python3 %(prog)s --model PJX110 --brand OnePlus \\
                   --ota-version PJX110_11.F.13_2130_202512181912 \\
                   --current-sota "V80P02(BRB1CN01)" \\
                   --coloros ColorOS16.0.0 \\"
        """
    )
    
    # All parameters are required
    parser.add_argument('--model', required=True, help='Device model (e.g., PJX110)')
    parser.add_argument('--brand', required=True, help='Device brand (e.g., OnePlus, OPPO)')
    parser.add_argument('--ota-version', required=True, help='OTA version (e.g., PJX110_11.F.13_2130_202512181912)')
    parser.add_argument('--current-sota', required=True, help='Current SOTA version on device (e.g., V80P02(BRB1CN01))')
    parser.add_argument('--coloros', required=True, help='ColorOS version (e.g., ColorOS16.0.0)')
    
    # Custom error handling to show usage example
    try:
        return parser.parse_args()
    except SystemExit:
        # Show usage example before exiting
        print("\nUsage Example:")
        print("  python3 sota_query.py --model PJX110 --brand OnePlus \\")
        print("                       --ota-version PJX110_11.F.13_2130_202512181912 \\")
        print("                       --current-sota \"V80P02(BRB1CN01)\" \\")
        print("                       --coloros ColorOS16.0.0 \\")
        sys.exit(1)

if __name__ == "__main__":
    # Parse command line arguments
    args = parse_args()
    
    # Run main automation
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
