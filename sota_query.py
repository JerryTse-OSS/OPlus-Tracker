#!/usr/bin/env python
"""
SOTA(Software OTA) Query
Designed by Jerry Tse
"""

import argparse
import base64
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from config import OTA_PUBLIC_KEYS, OTA_REGION_CONFIG, SOTA_CONFIG


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
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode()


# --- Common Functions ---

def get_public_key_for_region(region: str) -> Tuple[str, Dict]:
    key_region = "sg" if region not in ["cn", "eu", "in"] else region

    public_key = OTA_PUBLIC_KEYS[key_region]

    if region in ["cn", "eu", "in"]:
        config = OTA_REGION_CONFIG[region]
    else:
        config = OTA_REGION_CONFIG["sg_host"].copy()
        config.update(OTA_REGION_CONFIG[region])

    return public_key, config


def parse_brand(brand_str: str) -> str:
    brand_lower = brand_str.strip().lower()
    if brand_lower == "oppo":
        return "OPPO"
    elif brand_lower == "oneplus":
        return "OnePlus"
    elif brand_lower == "realme":
        return "Realme"
    else:
        raise ValueError(
            f"Error: Invalid brand '{brand_str}'. Supported: OPPO, OnePlus, Realme"
        )


def build_headers(
    aes_key: bytes,
    public_key: str,
    config: Dict[str, str],
    region_config: Dict[str, str],
    is_update_request: bool = False,
) -> Dict[str, str]:
    """Build headers for both query and update requests"""
    protected_key_payload = generate_protected_key(aes_key, public_key)
    timestamp = str(time.time_ns() + 10**9 * 60 * 60 * 24)

    protected_key_json = json.dumps(
        {
            "SCENE_1": {
                "protectedKey": protected_key_payload,
                "version": timestamp,
                "negotiationVersion": region_config["public_key_version"],
            }
        }
    )

    # Base headers dynamically injected from region config
    headers = {
        "language": region_config["language"],
        "colorOSVersion": config["coloros"],
        "androidVersion": "unknown",
        "infVersion": "1",
        "otaVersion": config["ota_version"],
        "model": config["model"],
        "mode": "taste",
        "nvCarrier": region_config["carrier_id"],
        "brand": config["brand"],
        "brandSota": config["brand"],
        "osType": "domestic_" + config["brand"] if config["region"] == "cn" else config["brand"],
        "version": "2",
        "deviceId": "0" * 64,
        "protectedKey": protected_key_json,
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "okhttp/4.12.0",
        "Accept-Encoding": "gzip",
    }

    # Different headers for query vs update
    if is_update_request:
        headers.update({"romVersion": config["rom_version"]})
    else:
        headers.update({"romVersion": "unknown"})

    return headers


def execute_query_request(
    config: Dict[str, str],
    region_config: Dict[str, str],
    public_key: str,
    url_query: str
) -> Tuple[Optional[Dict[str, Any]], Optional[bytes], Optional[bytes]]:
    """Execute the query and return decrypted data, aes_key, and iv"""

    aes_key = generate_random_bytes(32)
    iv = generate_random_bytes(16)

    headers = build_headers(aes_key, public_key, config, region_config, is_update_request=False)

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
        "cota": {"cotaVersion": "", "cotaVersionName": "", "buildType": "user"},
        "opex": {"check": True},
        "sota": {
            "sotaProtocolVersion": "2",
            "sotaVersion": "V69P69",
            "otaUpdateTime": ota_update_time,
            "frameworkVer": "10",
            "supportLightH": "1",
            "updateViaReboot": 2,
            "sotaProtocolVersionNew": ["apk", "opex", "rus"],
        },
        "otaAppVersion": 16000021,
        "deviceId": "0" * 64,
    }

    # Encrypt and send request
    payload_str = json.dumps(body)
    cipher_text = aes_ctr_encrypt(payload_str.encode(), aes_key, iv)

    wrapped_data = {
        "params": json.dumps(
            {
                "cipher": base64.b64encode(cipher_text).decode(),
                "iv": base64.b64encode(iv).decode(),
            }
        )
    }

    try:
        response = requests.post(
            url_query, headers=headers, json=wrapped_data, timeout=30
        )

        if response.status_code != 200:
            raise RuntimeError(f"[!] Query failed with HTTP {response.status_code}")

        resp_json = response.json()

        if "body" not in resp_json:
            raise RuntimeError("[!] Nothing in query response")

        # Decrypt the response
        encrypted_body = json.loads(resp_json["body"])
        decrypted_bytes = aes_ctr_decrypt(
            base64.b64decode(encrypted_body["cipher"]),
            aes_key,
            base64.b64decode(encrypted_body["iv"]),
        )
        decrypted_json = json.loads(decrypted_bytes.decode())

        return decrypted_json, aes_key, iv

    except Exception as e:
        raise RuntimeError(f"[!] Query request/decode failed: {str(e)}") from e


def execute_update_request(
    query_result: Dict[str, Any],
    config: Dict[str, str],
    region_config: Dict[str, str],
    public_key: str,
    url_update: str
) -> Optional[Dict[str, Any]]:
    """Execute the update using data from query result"""
    if "sota" not in query_result:
        raise RuntimeError("[!] No SOTA data found in query results")

    sota_data = query_result["sota"]
    new_sota_version = sota_data.get("sotaVersion", "")
    sota_name = sota_data.get("sotaName", "")

    if not new_sota_version:
        raise RuntimeError("[!] No SOTA version found in query results")

    # Get APK modules from query result
    apk_modules = sota_data.get("moduleMap", {}).get("apk", [])
    if not apk_modules:
        raise RuntimeError("[!] No APK modules found in query results")

    # Generate lower version numbers for update request
    sau_modules = []
    for module in apk_modules:
        module_name = module.get("moduleName")
        latest_version = module.get("moduleVersion", 0)

        # Create a lower version to trigger update
        if isinstance(latest_version, int) and latest_version > 100:
            current_version = max(1, latest_version - (latest_version // 10))
        else:
            current_version = max(1, latest_version - 1)

        sau_modules.append(
            {
                "sotaVersion": new_sota_version,
                "moduleName": module_name,
                "moduleVersion": current_version,
            }
        )

    # Build update request body
    body = {
        "sotaProtocolVersion": "2",
        "sotaProtocolVersionNew": ["apk", "opex", "rus"],
        "sotaVersion": "V69P69",
        "updateViaReboot": 2,
        "supportLightH": "1",
        "moduleMap": {"sau": sau_modules},
        "mode": 0,
        "deviceId": "0" * 64,
        "otaVersion": config["ota_version"],
    }

    # Use new aes_key and iv for update request
    update_aes_key = generate_random_bytes(32)
    update_iv = generate_random_bytes(16)

    headers = build_headers(
        update_aes_key, public_key, config, region_config, is_update_request=True
    )

    # Encrypt and send request
    payload_str = json.dumps(body)
    cipher_text = aes_ctr_encrypt(payload_str.encode(), update_aes_key, update_iv)

    wrapped_data = {
        "params": json.dumps(
            {
                "cipher": base64.b64encode(cipher_text).decode(),
                "iv": base64.b64encode(update_iv).decode(),
            }
        )
    }

    try:
        response = requests.post(
            url_update, headers=headers, json=wrapped_data, timeout=30
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"[!] Update request failed with HTTP {response.status_code}"
            )

        resp_json = response.json()

        if "body" not in resp_json:
            raise RuntimeError("[!] Nothing in update response")

        # Decrypt the response
        encrypted_body = json.loads(resp_json["body"])
        decrypted_bytes = aes_ctr_decrypt(
            base64.b64decode(encrypted_body["cipher"]),
            update_aes_key,
            base64.b64decode(encrypted_body["iv"]),
        )
        decrypted_json = json.loads(decrypted_bytes.decode())

        return decrypted_json

    except Exception as e:
        import traceback

        traceback.print_exc()
        raise RuntimeError(f"[!] Update error: {str(e)}") from e


# --- Output Formatting ---

def extract_and_format_apk_info(update_result: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Extract APK information from update result and format as requested"""
    formatted_lines = []
    sota_version = "Unknown"

    if "moduleMap" not in update_result:
        return sota_version, formatted_lines

    if "sota" in update_result and "sotaVersion" in update_result["sota"]:
        sota_version = update_result["sota"]["sotaVersion"]
    elif "components" in update_result and len(update_result["components"]) > 0:
        for component in update_result["components"]:
            if "sotaVersion" in component:
                sota_version = component["sotaVersion"]
                break

    apk_modules = update_result["moduleMap"].get("apk", [])

    if not apk_modules:
        return sota_version, formatted_lines

    for apk in apk_modules:
        if "sotaVersion" in apk and sota_version == "Unknown":
            sota_version = apk["sotaVersion"]
            break

    for i, apk in enumerate(apk_modules):
        apk_name = apk.get("moduleName", "Unknown")
        apk_version = apk.get("moduleVersion", "Unknown")
        apk_hash = apk.get("md5", "Unknown")
        apk_link = apk.get("manualUrl", "Unknown")

        formatted_line = f"• Apk Name: {apk_name}\n• Apk Version: {apk_version}\n• Apk Hash: {apk_hash}\n• Link: {apk_link}"

        if i < len(apk_modules) - 1:
            formatted_line += "\n"

        formatted_lines.append(formatted_line)

    return sota_version, formatted_lines


def print_formatted_output(sota_version: str, formatted_lines: List[str]):
    if not formatted_lines:
        print("\nNo APK information to display")
        return

    print("SOTA Apk Info:")
    print(f"\n· SOTA Version: {sota_version}\n")

    for line in formatted_lines:
        print(line)


# --- Main Execution ---

def run_sota_query(ota_version: str, region: str, brand: str, coloros: str):
    """Main execution: run query, then update, then format output"""
    brand = parse_brand(brand)
    region = region.lower()

    config = {
        "brand": brand,
        "ota_version": ota_version,
        "model": ota_version.split("_")[0],
        "coloros": coloros,
        "rom_version": "unknown",
        "region": region
    }

    # Retrieve Region Configurations
    public_key, region_config = get_public_key_for_region(region)
    host = region_config["host"]
    url_query = f"https://{host}{SOTA_CONFIG['endpoint_query']}"
    url_update = f"https://{host}{SOTA_CONFIG['endpoint_update']}"

    query_result, aes_key, iv = execute_query_request(config, region_config, public_key, url_query)
    update_result = execute_update_request(query_result, config, region_config, public_key, url_update)
    sota_version, formatted_lines = extract_and_format_apk_info(update_result)
    
    return {
        "config": config,
        "sota_version": sota_version,
        "formatted_lines": formatted_lines,
        "region_config": region_config
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="SOTA APK Query Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Example:
  python %(prog)s PJX110_11.F.13_2130_202512181912 cn --brand OnePlus --coloros ColorOS16.0.0
        """,
    )

    # Positional Arguments (Required parameters)
    parser.add_argument(
        "ota_version",
        help="OTA version (e.g., PJX110_11.F.13_2130_202512181912)",
    )
    
    valid_regions = [r for r in OTA_REGION_CONFIG.keys() if r not in ["sg_host", "cn_gray", "cn_cmcc"]]
    parser.add_argument(
        "region", 
        type=str.lower, 
        choices=valid_regions, 
        help="Region code (e.g., cn, eu, in, gl, etc.)"
    )

    # Named Arguments (Required params for query)
    parser.add_argument(
        "--brand", required=True, help="Device brand (e.g., OnePlus, OPPO, Realme)"
    )
    parser.add_argument(
        "--coloros", required=True, help="ColorOS version (e.g., ColorOS16.0.0)"
    )

    return parser.parse_args()


if __name__ == "__main__":
    try:
        args = parse_args()
        print(f"Querying SOTA info for {args.region.upper()} region...")
        result = run_sota_query(args.ota_version, args.region, args.brand, args.coloros)
        
        print(f"Device: {result['config']['model']}")
        print(f"OS: {result['config']['coloros'].replace('ColorOS', 'ColorOS ')}")
        print()
        print_formatted_output(result["sota_version"], result["formatted_lines"])
        sys.exit(0)
    except KeyboardInterrupt:
        print("\n\nScript interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
