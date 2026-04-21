#!/usr/bin/env python
"""
ColorOS Downgrade Query Tool
Designed by Jerry Tse
"""

import argparse
import base64
import json
import os
import sys
import time
from typing import Dict, Optional

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from config import DOWNGRADE_CONFIG

# --- Configuration ---

URL = DOWNGRADE_CONFIG["url"]
NEGOTIATION_VERSION = DOWNGRADE_CONFIG["negotiation_version"]
REAL_PUB_KEY = DOWNGRADE_CONFIG["public_key"]

# --- Crypto Helpers ---


def get_protected_key(session_key_bytes: bytes) -> str:
    pub_key = serialization.load_pem_public_key(
        REAL_PUB_KEY.encode(), backend=default_backend()
    )
    rsa_input = base64.b64encode(session_key_bytes)
    encrypted_bytes = pub_key.encrypt(
        rsa_input,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    return base64.b64encode(encrypted_bytes).decode()


def encrypt_aes_gcm(plaintext: str, key: bytes, iv: bytes) -> Dict[str, str]:
    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv), backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return {
        "cipher": base64.b64encode(ciphertext + encryptor.tag).decode(),
        "iv": base64.b64encode(iv).decode(),
    }


def decrypt_aes_gcm(cipher_b64: str, iv_b64: str, key: bytes) -> Optional[bytes]:
    try:
        full_cipher = base64.b64decode(cipher_b64)
        iv = base64.b64decode(iv_b64)
        tag, ciphertext = full_cipher[-16:], full_cipher[:-16]
        decryptor = Cipher(
            algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
        ).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        return None


def query_downgrade(
    ota_prefix: str, prj_num: str, sn_num: str, duid: str, debug: int = 0
):
    ota_version = ota_prefix.upper()
    if "_11." not in ota_version:
        raise ValueError(
            f"OTA_Prefix '{ota_version}' must contain '_11.' (e.g., PKX110_11.C)."
        )
    if not prj_num.isdigit() or len(prj_num) != 5:
        raise ValueError(f"PrjNum '{prj_num}' must be exactly 5 digits.")
    if len(duid) != 64:
        raise ValueError(f"DUID length is {len(duid)}, expected 64 characters.")

    model = ota_version.split("_")[0]
    requests.packages.urllib3.disable_warnings()
    carriers = ["10010111", "10011000"]
    for idx, current_carrier in enumerate(carriers):
        session_key = os.urandom(32)
        iv = os.urandom(12)
        try:
            protected_key = get_protected_key(session_key)
            encrypted_device_id_obj = encrypt_aes_gcm(duid, session_key, iv)
            payload = {
                "model": model,
                "nvCarrier": current_carrier,
                "prjNum": prj_num,
                "serialNo": sn_num,
                "otaVersion": ota_version,
                "deviceId": encrypted_device_id_obj,
            }
            cipher_info = {
                "downgrade-server": {
                    "negotiationVersion": NEGOTIATION_VERSION,
                    "protectedKey": protected_key,
                    "version": str(int(time.time())),
                }
            }
            headers = {
                "Host": "downgrade.coloros.com",
                "Content-Type": "application/json; charset=UTF-8",
                "cipherInfo": json.dumps(cipher_info),
                "deviceId": duid,
                "Connection": "close",
            }
            resp = requests.post(
                URL, headers=headers, json=payload, timeout=20, verify=False
            )
            if resp.status_code == 200:
                resp_json = resp.json()
                if isinstance(resp_json, dict) and resp_json.get("code") == 1004:
                    return {
                        "ota_version": ota_version,
                        "packages": [],
                        "error": "DUID query GUID is empty",
                    }
                final_data = None
                if "cipher" in resp_json:
                    decrypted_bytes = decrypt_aes_gcm(
                        resp_json["cipher"], resp_json["iv"], session_key
                    )
                    if decrypted_bytes:
                        try:
                            final_data = json.loads(decrypted_bytes)
                        except Exception:
                            pass
                else:
                    final_data = resp_json
                if final_data and "data" in final_data and final_data["data"]:
                    pkg_list = final_data["data"].get("downgradeVoList")
                    if pkg_list:
                        return {
                            "ota_version": ota_version,
                            "packages": pkg_list,
                            "meta_data": final_data["data"].get("metaData"),
                            "debug": debug,
                            "error": None,
                        }
                if idx == 0:
                    time.sleep(1)
                    continue
                return {
                    "ota_version": ota_version,
                    "packages": [],
                    "error": "No Downgrade Package",
                }
            if idx == 0:
                time.sleep(1)
                continue
            return {
                "ota_version": ota_version,
                "packages": [],
                "error": f"[!] Server returned HTTP {resp.status_code}",
            }
        except Exception as e:
            if idx == 0:
                time.sleep(1.5)
                continue
            return {
                "ota_version": ota_version,
                "packages": [],
                "error": f"[!] Error: {e}",
            }
    return {"ota_version": ota_version, "packages": [], "error": "No Downgrade Package"}


def main():
    parser = argparse.ArgumentParser(
        description="ColorOS Downgrade Query Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python %(prog)s PKX110_11.C 24821 a1b2c3d4 498A44DF1BEC4EB19FBCB3A870FCACB4EC7D424979CC9C517FE7B805A1937746
  python %(prog)s PKX110_11.C 24821 a1b2c3d4 498A44DF1BEC4EB19FBCB3A870FCACB4EC7D424979CC9C517FE7B805A1937746 --debug 1
""",
    )
    parser.add_argument(
        "ota_prefix",
        metavar="OTA_Prefix",
        help='OTA prefix containing "_11." (e.g., PKX110_11.C)',
    )
    parser.add_argument(
        "prj_num",
        metavar="PrjNum",
        help="Project number, exactly 5 digits (e.g., 24821)",
    )
    parser.add_argument(
        "sn_num", metavar="snNum", help="SN number from device (e.g., a1b2c3d4)"
    )
    parser.add_argument(
        "duid",
        metavar="DUID",
        help="64-character SHA256 DUID string (get from *#6776#)",
    )
    parser.add_argument(
        "--debug",
        type=int,
        choices=[0, 1],
        default=0,
        help="Enable (1) or disable (0) debug output (default: 0)",
    )
    args = parser.parse_args()

    try:
        result = query_downgrade(
            args.ota_prefix, args.prj_num, args.sn_num, args.duid, args.debug
        )
    except ValueError as e:
        parser.error(str(e))

    print(f"Querying downgrade for {result['ota_version']}\n")
    if result["packages"]:
        pkg_list = result["packages"]
        for i, pkg in enumerate(pkg_list):
            print("Fetch Info:")
            print(f"• Link: {pkg.get('downloadUrl', 'N/A')}")
            print(f"• Changelog: {pkg.get('versionIntroduction', 'N/A')}")
            print(
                f"• Version: {pkg.get('colorosVersion', '')} ({pkg.get('androidVersion', '')})"
            )
            print(f"• Ota Version: {pkg.get('otaVersion', 'N/A')}")
            print(f"• MD5: {pkg.get('fileMd5', 'N/A')}")
            file_size = pkg.get("fileSize")
            if file_size is not None:
                try:
                    size_mb = int(file_size) / 1024 / 1024
                    print(f"• File Size: {file_size} Byte ({size_mb:.0f}M)")
                except Exception:
                    print(f"• File Size: {file_size} Byte (N/A)")
            else:
                print("• File Size: N/A")
            if i < len(pkg_list) - 1 or args.debug:
                print()
        if args.debug == 1 and result.get("meta_data"):
            print(f"Metadata:\n{result['meta_data']}")
        return 0
    print(result["error"] or "No Downgrade Package")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nScript interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        sys.exit(1)
