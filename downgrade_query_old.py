#!/usr/bin/env python3
"""
ColorOS Downgrade Query Tool
Designed by Jerry Tse
"""

import sys
import os
import json
import base64
import time
import argparse
from datetime import datetime
from typing import Dict, Optional

import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Configuration ---

# API URL
URL = "https://downgrade.coloros.com/downgrade/query-v2"
NEGOTIATION_VERSION = 1636449646204

# Public Key (Key Index 2)
REAL_PUB_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmeQzr0TIbtwZFnDXgatg
6xP9SlNBFho1NTdFQ27SKDF+dBEEfnG9BqRw0na0DUqtpWe2CUtldbU33nnJ0KB6
z7y5f+89o9n8mJxIbh952gpskBxyrhCfpYHV5mt/n9Tkm8OcQWLRFou7/XITuZeZ
ejfUTesQjpfOeCaeKyVSoKQc6WuH7NSYq6B37RMyEn/1+vo8XuHEKD84p29KGpyG
I7ZeL85iOcwBmOD6+e4yideH2RatA1SzEv/9V8BflaFLAWDuPWUjA2WgfOvy5spY
mp/MoMOX4P0d+AkJ9Ms6PUXEUBsbOACmaMFyLCLHmd18+UeGdJR/3I15sXKbJhKe
rwIDAQAB
-----END PUBLIC KEY-----"""

# --- Crypto Helpers ---

def get_protected_key(session_key_bytes: bytes) -> str:
    """Encrypt SessionKey using RSA-OAEP-SHA1 (SessionKey must be Base64 encoded first)"""
    pub_key = serialization.load_pem_public_key(REAL_PUB_KEY.encode(), backend=default_backend())
    # Critical Step: SessionKey -> Base64 -> RSA Encrypt
    rsa_input = base64.b64encode(session_key_bytes)
    encrypted_bytes = pub_key.encrypt(
        rsa_input,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    )
    return base64.b64encode(encrypted_bytes).decode()

def encrypt_aes_gcm(plaintext: str, key: bytes, iv: bytes) -> Dict[str, str]:
    """Encrypt data using AES-256-GCM"""
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return {
        "cipher": base64.b64encode(ciphertext + encryptor.tag).decode(),
        "iv": base64.b64encode(iv).decode()
    }

def decrypt_aes_gcm(cipher_b64: str, iv_b64: str, key: bytes) -> Optional[bytes]:
    """Decrypt data using AES-256-GCM"""
    try:
        full_cipher = base64.b64decode(cipher_b64)
        iv = base64.b64decode(iv_b64)
        tag, ciphertext = full_cipher[-16:], full_cipher[:-16]
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        return None

def print_usage():
    print("\nUsage:")
    print(f"  python3 {sys.argv[0]} <OTA_Prefix> <PrjNum>")
    print("\nConstraints:")
    print("  <OTA_Prefix> : Must contain at least one '_' (e.g., PKX110_11.C)")
    print("  <PrjNum>     : Must be exactly 5 digits (e.g., 24821)")
    print("\nExample:")
    print(f"  python3 {sys.argv[0]} PKX110_11.C 24821")

# --- Main Logic ---

def main():
    # 1. Argument Validation
    if len(sys.argv) != 3:
        print_usage()
        sys.exit(1)

    ota_version = sys.argv[1].upper()
    prj_num = sys.argv[2]

    # Validate Argument 1: OTA Prefix (Must have '_')
    if "_11." not in ota_version:
        ota_version = ota_version + "_11.A"

    # Validate Argument 2: PrjNum (Must be 5 digits)
    if not prj_num.isdigit() or len(prj_num) != 5:
        print(f"\n❌ Error: Argument 2 (PrjNum) '{prj_num}' must be exactly 5 digits.")
        sys.exit(1)
    
    # Extract model from OTA prefix
    model = ota_version.split("_")[0]
    duid = "0" * 64

    # Suppress SSL warnings
    requests.packages.urllib3.disable_warnings()

    print(f"Querying downgrade for {ota_version}\n")

    # Generate session keys
    session_key = os.urandom(32)
    iv = os.urandom(12)

    # Build request payload
    payload = {
        "model": model,
        "nvCarrier": "10010111",
        "prjNum": prj_num,
        "otaVersion": ota_version
    }

    try:
        # Encrypt Header Key
        protected_key = get_protected_key(session_key)
        # Encrypt DeviceID in Body
        encrypted_device_id_obj = encrypt_aes_gcm(duid, session_key, iv)
        payload["deviceId"] = encrypted_device_id_obj
    except Exception as e:
        print(f"[!] Encryption Init Failed: {e}")
        return

    cipher_info = {
        "downgrade-server": {
            "negotiationVersion": NEGOTIATION_VERSION,
            "protectedKey": protected_key,
            "version": str(int(time.time()))
        }
    }

    headers = {
        "Host": "downgrade.coloros.com",
        "Content-Type": "application/json; charset=UTF-8",
        "cipherInfo": json.dumps(cipher_info),
        "deviceId": duid,
        "Connection": "keep-alive"
    }

    # Send Request
    try:
        resp = requests.post(URL, headers=headers, json=payload, timeout=20, verify=False)

        if resp.status_code == 200:
            resp_json = resp.json()

            # Handle Decryption
            final_data = None
            if "cipher" in resp_json:
                decrypted_bytes = decrypt_aes_gcm(resp_json["cipher"], resp_json["iv"], session_key)
                if decrypted_bytes:
                    try:
                        final_data = json.loads(decrypted_bytes)
                    except:
                        pass
            else:
                final_data = resp_json

            # Parse and Format Output
            if final_data:
                has_data = False
                if "data" in final_data and final_data["data"]:
                    pkg_list = final_data["data"].get("downgradeVoList")
                    if pkg_list:
                        has_data = True
                        for i, pkg in enumerate(pkg_list):

                            print("Fetch Info:")
                            print(f"• Link: {pkg.get('downloadUrl', 'N/A')}")
                            print(f"• Changelog: {pkg.get('versionIntroduction', 'N/A')}")
                            print(f"• Version: {pkg.get('colorosVersion', '')} ({pkg.get('androidVersion', '')})")
                            print(f"• Ota Version: {pkg.get('otaVersion', 'N/A')}")
                            print(f"• MD5: {pkg.get('fileMd5', 'N/A')}")
                            print(f"• File Size: {pkg.get('fileSize', 'N/A')} Byte ({pkg.get('fileSize')/1024/1024:.0f}M)")

                            # Add blank line between packages
                            if i < len(pkg_list) - 1:
                                print()

                if not has_data:
                    print("No Downgrade Package")
            else:
                # Decryption failed or empty response
                print("No Downgrade Package")

        else:
            print(f"[!] Server returned HTTP {resp.status_code}")

    except Exception as e:
        print(f"[!] Network Error: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Script interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        sys.exit(1)