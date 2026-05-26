#!/usr/bin/env python
"""
IoT Changelog Query Tool - Specialized for ColorOS iota server
Designed by Jerry Tse
"""

import argparse
import base64
import json
import random
import re
import string
import sys
import time
import hashlib
from typing import Dict, Tuple

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from config import IOT_CONFIG

OLD_KEYS = IOT_CONFIG["old_keys"]
SPECIAL_SERVERS = IOT_CONFIG["special_servers"]
DEFAULT_CHANGELOG_SUFFIX = "_197001010000"

def get_key(key_pseudo: str) -> bytes:
    return (OLD_KEYS[int(key_pseudo[0])] + key_pseudo[4:12]).encode("utf-8")

def encrypt_ctr(data: str) -> str:
    chars = string.ascii_letters + string.digits + "_!#$%&()+-="
    key_pseudo = str(random.randint(0, 9)) + "".join(
        random.choices(chars, k=14)
    )
    key_real = get_key(key_pseudo)
    iv = hashlib.md5(key_real).digest()

    cipher = Cipher(algorithms.AES(key_real), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(data.encode("utf-8")) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("utf-8") + key_pseudo

def decrypt_ctr(encrypted_data: str) -> str:
    ciphertext_b64 = encrypted_data[:-15]
    key_pseudo = encrypted_data[-15:]

    ciphertext = base64.b64decode(ciphertext_b64)
    key_real = get_key(key_pseudo)
    iv = hashlib.md5(key_real).digest()

    cipher = Cipher(algorithms.AES(key_real), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode("utf-8")


def replace_gauss_url(url: str) -> str:
    if not url or url == "N/A":
        return url
    return url.replace(IOT_CONFIG["gauss_auto_url"], IOT_CONFIG["gauss_manual_url"])


def build_special_request_data(ota_version: str, model: str, region: str) -> Tuple[Dict, Dict]:
    lang = "zh-CN" if region.lower() == "cn" else "en-EN"
    
    rom_parts = ota_version.split("_")
    rom_version = "_".join(rom_parts[:3]) if len(rom_parts) >= 3 else ota_version
    
    random_imei = "".join(random.choices(string.digits, k=15))
    random_device_id = hashlib.sha256(f"{random_imei}_{time.time()}".encode()).hexdigest()

    headers = {
        "version": "3",
        "language": lang,
        "newLanguage": lang,
        "romVersion": rom_version,
        "otaVersion": ota_version,
        "androidVersion": "unknown",
        "colorOSVersion": "unknown",
        "model": model,
        "infVersion": "1",
        "nvCarrier": "10010111",
        "deviceId": random_device_id,
        "mode": "client_auto",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    body = {
        "language": lang,
        "romVersion": rom_version,
        "otaVersion": ota_version,
        "model": model,
        "productName": model,
        "imei": random_imei,
        "mode": "0",
        "deviceId": random_device_id,
        "version": "2",
        "type": "1",
        "isRealme": "1" if "RMX" in model else "0",
        "time": str(int(time.time() * 1000)),
    }
    
    body["modules"] = [
        {
            "otaPkgType": "1",
            "version": ota_version
        }
    ]
    
    return headers, body


def query_iot_server(ota_version: str, model: str, region: str):
    headers, body = build_special_request_data(ota_version, model, region)
    encrypted_body = encrypt_ctr(json.dumps(body))
    
    server_url = SPECIAL_SERVERS.get(region.lower(), SPECIAL_SERVERS["cn"]) + "Query_Description"

    try:
        response = requests.post(
            server_url,
            headers=headers,
            json={"version": "4", "params": encrypted_body},
            timeout=30,
        )

        if response.status_code != 200:
            return None

        resp_json = response.json()
        if resp_json.get("responseCode", 200) != 200:
            return None

        encrypted_resp = resp_json.get("resps", "")
        if not encrypted_resp:
            return None

        decrypted_json = json.loads(decrypt_ctr(encrypted_resp))
        module_data = decrypted_json.get("modules", [{}])[0]
        if module_data.get("checkFailReason") or decrypted_json.get("checkFailReason"):
            return None

        return decrypted_json
    except Exception:
        return None


def build_iot_result(decrypted_json):
    module_data = decrypted_json.get("modules", [{}])[0]
    data = {**decrypted_json, **module_data}
    
    changelog = replace_gauss_url(str(data.get("description", "N/A")))

    return {
        "changelog": changelog,
        "ota_version": data.get("version_name", data.get("new_version", "N/A")),
    }


def query_iot(ota_prefix: str, region: str, model_override: str = None):
    ota_input = ota_prefix.upper()

    if not re.search(r'_\d{12}$', ota_input):
        ota_input = ota_input + DEFAULT_CHANGELOG_SUFFIX

    parts = ota_input.split("_")

    is_simple = not bool(
        re.search(r"_\d{2}\.[A-Z]", ota_input) or ota_input.count("_") >= 3
    )
    results = []

    if is_simple:
        suffixes = ["_11.A", "_11.C", "_11.F", "_11.H"]
        model = model_override if model_override else parts[0]

        for suffix in suffixes:
            base_prefix = ota_prefix.upper().split("_")[0]
            current_prefix = base_prefix + suffix
            full_version = f"{current_prefix}.01_0001_197001010000"
            
            result = query_iot_server(full_version, model, region)
            
            if result:
                results.append(
                    {
                        "query": current_prefix,
                        "found": True,
                        "result": build_iot_result(result),
                    }
                )
            else:
                results.append(
                    {"query": current_prefix, "found": False, "result": None}
                )

    else:
        model = model_override if model_override else parts[0]
        full_version = ota_input
        
        result = query_iot_server(full_version, model, region)
        
        if result:
            results.append(
                {"query": ota_input, "found": True, "result": build_iot_result(result)}
            )
        else:
            results.append({"query": ota_input, "found": False, "result": None})
    return results


def main():
    parser = argparse.ArgumentParser(description="IoT Special OTA Query Tool")
    parser.add_argument(
        "ota_prefix",
        metavar="OTA_Prefix",
        help="OTA prefix or full version name (e.g., PHN110_11.H.19_3190 or OWW221_11.A.35_2620_197001010000)",
    )
    parser.add_argument(
        "region", choices=["cn", "gl", "in", "eu"], help="Region to query (cn, gl, in, eu)"
    )
    parser.add_argument("--model", help="Custom model override")

    args = parser.parse_args()
    
    results = query_iot(args.ota_prefix, args.region, args.model)
    
    has_result = False
    for item in results:
        print(f"Querying for {item['query']}\n")
        if not item["found"]:
            print("No Result\n")
            continue
        has_result = True
        data = item["result"]
        print("Fetch Info:")
        print(f"• Changelog: {data['changelog']}")
        print(f"• Ota Version: {data['ota_version']}\n")
    return 0 if has_result else 1


if __name__ == "__main__":
    sys.exit(main())
