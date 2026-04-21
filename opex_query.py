#!/usr/bin/env python
"""
Opex Query Tool
Designed by Jerry Tse
"""

import argparse
import base64
import json
import os
import random
import re
import string
import sys
import time
from dataclasses import dataclass
from typing import Dict

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from config import OPEX_CONFIG

# --- Configuration Constants ---

OPEX_PUBLIC_KEY_CN = OPEX_CONFIG["public_key_cn"]

OPEX_CONFIG_CN = OPEX_CONFIG["cn"]


@dataclass
class OpexInfo:
    index: int
    version_name: str
    business_code: str
    zip_hash: str
    auto_url: str


# --- Helper Functions ---


def generate_random_string(length: int = 64) -> str:
    characters = string.ascii_uppercase + string.digits
    return "".join(random.choices(characters, k=length))


def generate_random_bytes(length: int) -> bytes:
    return os.urandom(length)


def parse_os_version(os_version_str: str) -> str:
    match = re.search(r"^(\d+)(?:\.(\d+)(?:\.(\d+))?)?$", os_version_str.strip())
    if match:
        return (
            f"ColorOS{match.group(1)}.{match.group(2) or '0'}.{match.group(3) or '0'}"
        )
    match = re.search(r"V(\d+\.\d+\.\d+)", os_version_str)
    if match:
        return f"ColorOS{match.group(1)}"
    return os_version_str if os_version_str.startswith("ColorOS") else os_version_str


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
            f"\nError: Invalid brand '{brand_str}'. Supported: OPPO, OnePlus, Realme"
        )


def extract_model_from_ota_version(ota_version: str) -> str:
    if not ota_version:
        return "unknown"
    parts = ota_version.split("_")
    return parts[0] if parts else "unknown"


# --- Encryption Core Logic ---


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


def aes_ctr_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_ctr_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# --- Request Construction & Execution ---


def build_headers(
    ota_version: str,
    model: str,
    android_version: str,
    os_version: str,
    brand: str,
    device_id: str,
    protected_key: str,
) -> Dict:
    config = OPEX_CONFIG_CN
    headers = {
        "language": config["language"],
        "newLanguage": config["language"],
        "androidVersion": android_version,
        "nvCarrier": config["carrier_id"],
        "deviceId": device_id,
        "osVersion": os_version,
        "productName": model,
        "brand": brand,
        "queryMode": "0",
        "version": "1",
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "okhttp/5.3.2",
    }
    expire_time = str(time.time_ns() + 10**9 * 60 * 60 * 24)
    headers["protectedKey"] = json.dumps(
        {
            "opex": {
                "protectedKey": protected_key,
                "version": expire_time,
                "negotiationVersion": config["public_key_version"],
            }
        }
    )
    return headers


def query_opex(
    ota_version: str, os_version: str, brand: str, android_version: str
) -> Dict:
    model = extract_model_from_ota_version(ota_version)

    url = f"https://{OPEX_CONFIG_CN['host']}{OPEX_CONFIG_CN['endpoint']}"
    max_retries = 10

    for attempt in range(max_retries):
        try:
            # Regenerate Key and ID for each request to avoid server-side caching issues
            aes_key = generate_random_bytes(32)
            iv = generate_random_bytes(16)
            device_id = generate_random_string(64).lower()
            protected_key_str = generate_protected_key(aes_key, OPEX_PUBLIC_KEY_CN)

            headers = build_headers(
                ota_version,
                model,
                android_version,
                os_version,
                brand,
                device_id,
                protected_key_str,
            )
            raw_payload = {
                "mode": "0",
                "time": int(time.time() * 1000),
                "businessList": [],
                "otaVersion": ota_version,
            }

            payload_str = json.dumps(raw_payload)
            cipher_text = aes_ctr_encrypt(payload_str.encode(), aes_key, iv)
            request_data = {
                "cipher": base64.b64encode(cipher_text).decode(),
                "iv": base64.b64encode(iv).decode(),
            }

            response = requests.post(
                url, headers=headers, json=request_data, timeout=30
            )

            # 1. Check HTTP status code
            if response.status_code != 200:
                continue

            resp_json = response.json()
            code = resp_json.get("code", resp_json.get("responseCode", 200))

            # 2. Check JSON business code
            # Retry on server internal error (500)
            if code == 500:
                continue

            if code != 200 and code != 500:
                msg = (
                    resp_json.get("message")
                    or resp_json.get("error")
                    or "Unknown Error"
                )
                return {"model": model, "error": f"API Error (Code {code}): {msg}"}

            # Decrypt response
            encrypted_body = resp_json
            decrypted_bytes = aes_ctr_decrypt(
                base64.b64decode(encrypted_body["cipher"]),
                aes_key,
                base64.b64decode(encrypted_body["iv"]),
            )
            body = json.loads(decrypted_bytes.decode())

            return {"model": model, "error": None, "opex_list": process_result(body)}

        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(2 * (attempt + 1))
                continue
            return {"model": model, "error": str(e), "opex_list": []}
    return {"model": model, "error": "Max retries exceeded", "opex_list": []}


def process_result(body: Dict):
    raw_data = body.get("data")
    opex_list = []
    ver_name = "N/A"

    if isinstance(raw_data, list):
        opex_packages = raw_data
        ver_name = body.get("opexVersionName", "N/A")
    elif isinstance(raw_data, dict):
        opex_packages = raw_data.get("opexPackage", [])
        ver_name = raw_data.get("opexVersionName", "N/A")
    else:
        opex_packages = []

    for i, pkg in enumerate(opex_packages):
        if not isinstance(pkg, dict):
            continue
        if pkg.get("code") == 200 and isinstance(pkg.get("info"), dict):
            info = pkg["info"]
            opex_list.append(
                OpexInfo(
                    index=i + 1,
                    version_name=ver_name,
                    business_code=pkg.get("businessCode", "N/A"),
                    zip_hash=info.get("zipHash", "N/A"),
                    auto_url=info.get("autoUrl", "N/A"),
                )
            )

    return opex_list


def run_opex_query(ota_version: str, info: str) -> Dict:
    parts = info.split(",")
    if len(parts) != 2:
        raise ValueError("--info must be in format 'osVersion,brand'")
    os_ver_raw, brand_raw = parts
    os_version = parse_os_version(os_ver_raw)
    brand = parse_brand(brand_raw)
    android_version = "Android" + os_ver_raw
    query_result = query_opex(ota_version, os_version, brand, android_version)
    query_result.update({"brand": brand, "os_version": os_version})
    return query_result


def main():
    example_text = """Example:
  python %(prog)s PJZ110_11.C.84_1840_202601060309 --info 16,oneplus"""

    parser = argparse.ArgumentParser(
        description="Opex Query Tool - Fetch Opex/Carrier updates for ColorOS devices",
        epilog=example_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("ota_version", help="Full OTA Version String")
    parser.add_argument(
        "--info",
        required=True,
        metavar="VER,BRAND",
        help="System info: osVersion,brand (e.g. 16,oneplus)",
    )

    # Critical change: Print help doc (including Example) and exit if no args provided
    if len(sys.argv) == 1:
        parser.print_help()
        return 1

    args = parser.parse_args()

    if len(args.info.split(",")) != 2:
        print("Error: --info must be in format 'osVersion,brand'")
        print(example_text)
        return 1

    if args.ota_version.count("_") < 3:
        print("\nWarning: Opex query typically requires a complete OTA version string.")

    result = run_opex_query(args.ota_version, args.info)
    print("Querying Opex updates")
    print(f"Model: {result['model']}")
    print(f"Brand: {result['brand']}")
    print(f"OS: {result['os_version'].replace('ColorOS', 'ColorOS ')}")

    if result.get("error"):
        print(f"\n{result['error']}")
        return 1

    opex_list = result.get("opex_list", [])
    if not opex_list:
        print("\nNo Opex updates found.")
        return 1

    print("\nOpex Info:")
    for i, opex in enumerate(opex_list):
        print(f"• Link: {opex.auto_url}")
        print(f"• Zip Hash: {opex.zip_hash}")
        print(f"• Opex Codename: {opex.business_code}")
        if i < len(opex_list) - 1:
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
