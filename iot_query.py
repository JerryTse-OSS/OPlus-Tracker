#!/usr/bin/env python
"""
IoT Query Tool - Specialized for ColorOS iota server
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
from typing import Dict, Tuple

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from config import IOT_CONFIG

OLD_KEYS = IOT_CONFIG["old_keys"]

SPECIAL_SERVER_CN = IOT_CONFIG["special_server_cn"]


def get_key(key_pseudo: str) -> bytes:
    return (OLD_KEYS[int(key_pseudo[0])] + key_pseudo[4:12]).encode("utf-8")


def encrypt_ecb(data: str) -> str:
    key_pseudo = str(random.randint(0, 9)) + "".join(
        random.choices(string.ascii_letters + string.digits, k=14)
    )
    key_real = get_key(key_pseudo)

    cipher = Cipher(algorithms.AES(key_real), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    block_size = 16
    padding_length = block_size - (len(data) % block_size)
    padded_data = data.encode("utf-8") + bytes([padding_length] * padding_length)

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("utf-8") + key_pseudo


def decrypt_ecb(encrypted_data: str) -> str:
    ciphertext_b64 = encrypted_data[:-15]
    key_pseudo = encrypted_data[-15:]

    ciphertext = base64.b64decode(ciphertext_b64)
    key_real = get_key(key_pseudo)

    cipher = Cipher(algorithms.AES(key_real), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = padded_plaintext[-1]
    return padded_plaintext[:-padding_length].decode("utf-8")


def replace_gauss_url(url: str) -> str:
    if not url or url == "N/A":
        return url
    return url.replace(IOT_CONFIG["gauss_auto_url"], IOT_CONFIG["gauss_manual_url"])


def build_special_request_data(ota_version: str, model: str) -> Tuple[Dict, Dict]:
    lang = "zh-CN"
    rom_parts = ota_version.split("_")
    rom_version = "_".join(rom_parts[:3]) if len(rom_parts) >= 3 else ota_version
    ota_prefix = "_".join(rom_parts[:2]) if len(rom_parts) >= 2 else ota_version

    headers = {
        "language": lang,
        "newLanguage": lang,
        "romVersion": rom_version,
        "otaVersion": ota_version,
        "androidVersion": "unknown",
        "colorOSVersion": "unknown",
        "model": model,
        "infVersion": "1",
        "nvCarrier": "10010111",
        "deviceId": "0" * 64,
        "mode": "client_auto",
        "version": "1",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    body = {
        "language": lang,
        "romVersion": rom_version,
        "otaVersion": ota_version,
        "model": model,
        "productName": model,
        "imei": "0" * 15,
        "mode": "0",
        "deviceId": "0" * 64,
        "version": "2",
        "type": "1",
        "isRealme": "1" if "RMX" in model else "0",
        "time": str(int(time.time() * 1000)),
    }
    return headers, body


def query_iot_server(ota_version: str, model: str):
    headers, body = build_special_request_data(ota_version, model)
    encrypted_body = encrypt_ecb(json.dumps(body))

    try:
        response = requests.post(
            SPECIAL_SERVER_CN,
            headers=headers,
            json={"params": encrypted_body},
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

        decrypted_json = json.loads(decrypt_ecb(encrypted_resp))
        if decrypted_json.get("checkFailReason"):
            return None

        return decrypted_json
    except Exception:
        return None


def build_iot_result(decrypted_json):
    down_url = replace_gauss_url(decrypted_json.get("down_url", "N/A"))
    changelog = replace_gauss_url(str(decrypted_json.get("description", "N/A")))
    patch_level = str(decrypted_json.get("googlePatchLevel", "N/A")).replace("0", "N/A")
    return {
        "link": down_url,
        "changelog": changelog,
        "security_patch": patch_level,
        "version": decrypted_json.get("new_version", "N/A"),
        "ota_version": decrypted_json.get("new_version", "N/A"),
    }


def query_iot(ota_prefix: str, model_override: str = None):
    ota_input = ota_prefix.upper()

    is_simple = not bool(
        re.search(r"_\d{2}\.[A-Z]", ota_input) or ota_input.count("_") >= 3
    )
    results = []

    if is_simple:
        suffixes = ["_11.A", "_11.C", "_11.F", "_11.H"]
        model = model_override if model_override else ota_input

        for suffix in suffixes:
            current_prefix = ota_input + suffix
            full_version = f"{current_prefix}.01_0001_197001010000"
            result = query_iot_server(full_version, model)
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
        parts = ota_input.split("_")
        model = model_override if model_override else parts[0]
        full_version = (
            f"{ota_input}.01_0001_197001010000" if len(parts) < 3 else ota_input
        )
        result = query_iot_server(full_version, model)
        if result:
            results.append(
                {"query": ota_input, "found": True, "result": build_iot_result(result)}
            )
        else:
            results.append({"query": ota_input, "found": False, "result": None})
    return results


def main():
    parser = argparse.ArgumentParser(description="IoT Special OTA Query Tool")
    parser.add_argument("ota_prefix", help="OTA version prefix or model name")
    parser.add_argument(
        "region", choices=["cn"], help="Region (IoT server only supports cn)"
    )
    parser.add_argument("--model", help="Custom model override")

    args = parser.parse_args()
    results = query_iot(args.ota_prefix, args.model)
    has_result = False
    for item in results:
        print(f"Querying for {item['query']}\n")
        if not item["found"]:
            print("No Result\n")
            continue
        has_result = True
        data = item["result"]
        print("Fetch Info:")
        print(f"• Link: {data['link']}")
        print(f"• Changelog: {data['changelog']}")
        print(f"• Security Patch: {data['security_patch']}")
        print(f"• Version: {data['version']}")
        print(f"• Ota Version: {data['ota_version']}\n")
    return 0 if has_result else 1


if __name__ == "__main__":
    sys.exit(main())
