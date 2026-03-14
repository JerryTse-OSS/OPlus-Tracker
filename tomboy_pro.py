#!/usr/bin/env python3
"""
OTA Query Tool - Query OTA update information for OPPO/OnePlus/Realme devices
Designed by: Jerry Tse
"""

import sys
import os
import json
import base64
import time
import random
import string
import argparse
import gzip
import binascii
import re
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

PUBLIC_KEYS = {
    "cn": """-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApXYGXQpNL7gmMzzvajHa
oZIHQQvBc2cOEhJc7/tsaO4sT0unoQnwQKfNQCuv7qC1Nu32eCLuewe9LSYhDXr9
KSBWjOcCFXVXteLO9WCaAh5hwnUoP/5/Wz0jJwBA+yqs3AaGLA9wJ0+B2lB1vLE4
FZNE7exUfwUc03fJxHG9nCLKjIZlrnAAHjRCd8mpnADwfkCEIPIGhnwq7pdkbamZ
coZfZud1+fPsELviB9u447C6bKnTU4AaMcR9Y2/uI6TJUTcgyCp+ilgU0JxemrSI
PFk3jbCbzamQ6Shkw/jDRzYoXpBRg/2QDkbq+j3ljInu0RHDfOeXf3VBfHSnQ66H
CwIDAQAB
-----END RSA PUBLIC KEY-----""",
    "eu": """-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh8/EThsK3f0WyyPgrtXb
/D0Xni6UZNppaQHUqHWo976cybl92VxmehE0ISObnxERaOtrlYmTPIxkVC9MMueD
vTwZ1l0KxevZVKU0sJRxNR9AFcw6D7k9fPzzpNJmhSlhpNbt3BEepdgibdRZbacF
3NWy3ejOYWHgxC+I/Vj1v7QU5gD+1OhgWeRDcwuV4nGY1ln2lvkRj8EiJYXfkSq/
wUI5AvPdNXdEqwou4FBcf6mD84G8pKDyNTQwwuk9lvFlcq4mRqgYaFg9DAgpDgqV
K4NTJWM7tQS1GZuRA6PhupfDqnQExyBFhzCefHkEhcFywNyxlPe953NWLFWwbGvF
KwIDAQAB
-----END RSA PUBLIC KEY-----""",
    "in": """-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwYtghkzeStC9YvAwOQmW
ylbp74Tj8hhi3f9IlK7A/CWrGbLgzz/BeKxNb45zBN8pgaaEOwAJ1qZQV5G4nPro
WCPOP1ro1PkemFJvw/vzOOT5uN0ADnHDzZkZXCU/knxqUSfLcwQlHXsYhNsAm7uO
KjY9YXF4zWzYN0eFPkML3Pj/zg7hl/ov9clB2VeyI1/blMHFfcNA/fvqDTENXcNB
IhgJvXiCpLcZqp+aLZPC5AwY/sCb3j5jTWer0Rk0ZjQBZE1AncwYvUx4mA65U59c
WpTyl4c47J29MsQ66hqWv6eBHlDNZSEsQpHePUqgsf7lmO5Wd7teB8ugQki2oz1Y
5QIDAQAB
-----END RSA PUBLIC KEY-----""",
    "sg": """-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkA980wxi+eTGcFDiw2I6
RrUeO4jL/Aj3Yw4dNuW7tYt+O1sRTHgrzxPD9SrOqzz7G0KgoSfdFHe3JVLPN+U1
waK+T0HfLusVJshDaMrMiQFDUiKajb+QKr+bXQhVofH74fjat+oRJ8vjXARSpFk4
/41x5j1Bt/2bHoqtdGPcUizZ4whMwzap+hzVlZgs7BNfepo24PWPRujsN3uopl+8
u4HFpQDlQl7GdqDYDj2zNOHdFQI2UpSf0aIeKCKOpSKF72KDEESpJVQsqO4nxMwE
i2jMujQeCHyTCjBZ+W35RzwT9+0pyZv8FB3c7FYY9FdF/+lvfax5mvFEBd9jO+dp
MQIDAQAB
-----END RSA PUBLIC KEY-----"""
}

REGION_CONFIG = {
    "cn": {"host": "component-ota-cn.allawntech.com", "language": "zh-CN", "carrier_id": "10010111", "public_key_version": "1615879139745"},
    "cn_cmcc": {"host": "component-ota-cn.allawntech.com", "language": "zh-CN", "carrier_id": "10011000", "public_key_version": "1615879139745"},
    "cn_gray": {"host": "component-ota-gray.coloros.com", "language": "zh-CN", "carrier_id": "10010111", "public_key_version": "1615879139745"},
    "eu": {"host": "component-ota-eu.allawnos.com", "language": "en-GB", "carrier_id": "01000100", "public_key_version": "1615897067573"},
    "in": {"host": "component-ota-in.allawnos.com", "language": "en-IN", "carrier_id": "00011011", "public_key_version": "1615896309308"},
    "sg_host": {"host": "component-ota-sg.allawnos.com", "public_key_version": "1615895993238"},
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

SUPPORTED_MODES = ["manual", "client_auto", "server_auto", "taste"]

@dataclass
class ComponentInfo:
    name: str
    version: str
    link: str
    original_link: str
    size: str
    md5: str
    auto_url: str
    expires_time: Optional[datetime] = None

@dataclass
class OpexInfo:
    index: int
    version_name: str
    business_code: str
    zip_hash: str
    auto_url: str

@dataclass
class QueryResult:
    success: bool
    response_code: int
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    components: List[ComponentInfo] = None
    opex_list: List[OpexInfo] = None
    published_time: Optional[str] = None

@dataclass
class QueryConfig:
    ota_version: str
    model: str
    region: str
    gray: int
    mode: str
    guid: str
    components_input: Optional[str] = None
    anti: int = 0
    has_custom_model: bool = False
    genshin: str = "0"
    pre: str = "0"
    custom_language: Optional[str] = None
    serial: Optional[str] = None
    imei: Optional[str] = None

def generate_imei():
    return ''.join(map(str, [random.randint(0, 9) for _ in range(15)]))

def generate_mac():
    return binascii.b2a_hex(os.urandom(6))

def generate_serial():
    return ''.join([random.choice('0123456789abcdef') for _ in range(8)])

def generate_digest():
    return '1-' + ''.join([random.choice('0123456789abcdef') for _ in range(40)])

def generate_random_string(length: int = 64) -> str:
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choices(characters, k=length))

def generate_random_bytes(length: int) -> bytes:
    return os.urandom(length)

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

def aes_ctr_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def aes_ctr_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def replace_gauss_url(url: str) -> str:
    if not url or url == "N/A":
        return url
    return url.replace(
        "https://gauss-otacostauto-cn.allawnfs.com/",
        "https://gauss-componentotacostmanual-cn.allawnfs.com/"
    )

def parse_components(components_input: Optional[str]) -> List[Dict]:
    if not components_input:
        return []
    
    components_list = []
    for pair in components_input.split(','):
        if ':' not in pair:
            print(f"Warning: Invalid component format '{pair}', should be 'name:version'")
            continue
        name, version = pair.split(':', 1)
        components_list.append({
            "componentName": name.strip(),
            "componentVersion": version.strip()
        })
    return components_list

def extract_expiration_date(url: str) -> Optional[datetime]:
    patterns = [r'Expires=(\d+)', r'x-oss-expires=(\d+)']
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            try:
                return datetime.fromtimestamp(int(match.group(1)))
            except (ValueError, TypeError):
                continue
    return None

def get_public_key_for_region(region: str, gray: int) -> Tuple[str, Dict]:
    key_region = "sg" if region not in ["cn", "eu", "in"] else region
    
    if gray == 1 and region == "cn":
        region = "cn_gray"
    
    if region == "cn_cmcc":
        key_region = "cn"
        
    public_key = PUBLIC_KEYS[key_region]
    
    if region in ["cn", "cn_cmcc", "cn_gray", "eu", "in"]:
        config = REGION_CONFIG[region]
    else:
        config = REGION_CONFIG["sg_host"].copy()
        config.update(REGION_CONFIG[region])
        
    return public_key, config

def get_redirect_url(url: str, max_retries: int = 3) -> str:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36',
        'Accept': 'application/json,text/html,*/*',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'userId': 'oplus-ota|00000001',
    }
    
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, allow_redirects=False, timeout=10)
            if response.status_code == 302:
                return response.headers.get('Location', url)
            return url
        except (requests.exceptions.Timeout, Exception):
            if attempt == max_retries - 1:
                return url
            time.sleep(2 * (attempt + 1))
    return url

def process_ota_version(ota_prefix: str, region: str, genshin: str, pre: str, custom_model: Optional[str]) -> Tuple[str, str]:
    parts = ota_prefix.split("_")
    base_model = parts[0]
    
    if custom_model:
        model = custom_model
    elif region.lower() in ["eu", "ru", "tr"]:
        model = f"{base_model}{region.upper()}"
    else:
        model = base_model

    if genshin == "1" and "YS" not in ota_prefix:
        model = base_model
        ota_prefix = ota_prefix.replace(model, model + "YS")
    elif genshin == "2" and "Ovt" not in ota_prefix:
        model = base_model
        ota_prefix = ota_prefix.replace(model, model + "Ovt")
    elif pre == "1" and "PRE" not in ota_prefix:
        model = base_model
        ota_prefix = ota_prefix.replace(model, model + "PRE")
    
    if "YS" in ota_prefix: model = base_model.replace("YS", "")
    elif "Ovt" in ota_prefix: model = base_model.replace("Ovt", "")
    elif "PRE" in ota_prefix: model = base_model.replace("PRE", "")
    
    ota_version = f"{ota_prefix}.01_0001_197001010000" if len(parts) < 3 else ota_prefix
    return ota_version, model

def build_request_headers(config: QueryConfig, region_config: Dict, device_id: str, protected_key: str) -> Dict:
    lang = config.custom_language or region_config["language"]
    return {
        "language": lang,
        "newLanguage": lang,
        "androidVersion": "unknown",
        "colorOSVersion": "unknown",
        "romVersion": "unknown",
        "infVersion": "1",
        "otaVersion": config.ota_version,
        "model": config.model,
        "mode": config.mode,
        "nvCarrier": region_config["carrier_id"],
        "pipelineKey": "ALLNET",
        "operator": "ALLNET",
        "companyId": "",
        "version": "2",
        "deviceId": device_id,
        "Content-Type": "application/json; charset=utf-8",
        "protectedKey": json.dumps({
            "SCENE_1": {
                "protectedKey": protected_key,
                "version": str(time.time_ns() + 10**9 * 60 * 60 * 24),
                "negotiationVersion": region_config["public_key_version"]
            }
        })
    }

def query_update(config: QueryConfig) -> QueryResult:
    public_key, region_config = get_public_key_for_region(config.region, config.gray)
    aes_key = generate_random_bytes(32)
    iv = generate_random_bytes(16)
    device_id = generate_random_string(64)
    
    headers = build_request_headers(config, region_config, device_id, generate_protected_key(aes_key, public_key))
    
    request_body = {
        "mode": "0",
        "time": int(time.time() * 1000),
        "isRooted": "0",
        "isLocked": True,
        "type": "0",
        "deviceId": config.guid.lower(),
        "opex": {"check": True}
    }
    if config.components_input:
        request_body["components"] = parse_components(config.components_input)
    cipher_text = aes_ctr_encrypt(json.dumps(request_body).encode(), aes_key, iv)
    endpoint_ver = "/update/v6" if (config.pre == "1") or (config.guid and config.guid != "0"*64) else "/update/v3"
    url = f"https://{region_config['host']}{endpoint_ver}"
    for attempt in range(3):
        try:
            response = requests.post(
                url, headers=headers, timeout=30,
                json={"params": json.dumps({
                    "cipher": base64.b64encode(cipher_text).decode(),
                    "iv": base64.b64encode(iv).decode()
                })}
            )
            return process_response(response, aes_key)
        except Exception as e:
            if attempt == 2:
                return QueryResult(False, 0, error=f"Connection failed: {str(e)}")
            time.sleep(5 * (attempt + 1))

    return QueryResult(False, 0, error="Max retries exceeded")

def process_response(response: requests.Response, aes_key: bytes) -> QueryResult:
    try:
        result = response.json()
    except json.JSONDecodeError:
        return QueryResult(False, 0, error="Invalid JSON response")
    
    if (status := result.get("responseCode")) != 200:
        return QueryResult(False, status, error=result.get("error", "Unknown error"))

    try:
        encrypted_body = json.loads(result["body"])
        
        decrypted = aes_ctr_decrypt(
            base64.b64decode(encrypted_body["cipher"]), 
            aes_key, 
            base64.b64decode(encrypted_body["iv"])
        )
        body = json.loads(decrypted.decode())
        
        published_time = None
        if ts := body.get("publishedTime"):
            try:
                published_time = datetime.fromtimestamp(ts / 1000).strftime("%Y-%m-%d %H:%M:%S")
            except Exception: pass

        components = []
        comp_list = body.get("components", [])
        if not isinstance(comp_list, list): comp_list = []

        for comp in comp_list:
            if not isinstance(comp, dict): continue
            
            pkts = comp.get("componentPackets")
            if not isinstance(pkts, dict): continue
            
            manual_url = replace_gauss_url(pkts.get("manualUrl", "N/A"))
            auto_url = replace_gauss_url(pkts.get("url", "N/A"))
            final_link = manual_url
            expires = None

            if "downloadCheck" in manual_url:
                final_link = replace_gauss_url(get_redirect_url(manual_url))
                expires = extract_expiration_date(final_link)
            
            components.append(ComponentInfo(
                name=comp.get("componentName", "Unknown"),
                version=comp.get("componentVersion", "Unknown"),
                link=final_link,
                original_link=manual_url,
                size=pkts.get("size", "N/A"),
                md5=pkts.get("md5", "N/A"),
                auto_url=auto_url,
                expires_time=expires
            ))
            
        opex_list = []
        opex_info = body.get("opex")
        
        if isinstance(opex_info, dict):
            opex_packages = opex_info.get("opexPackage", [])
            if isinstance(opex_packages, list):
                for i, pkg in enumerate(opex_packages):
                    if not isinstance(pkg, dict): continue
                    
                    if pkg.get("code") == 200 and isinstance(pkg.get("info"), dict):
                        info = pkg["info"]
                        opex_list.append(OpexInfo(
                            index=i + 1,
                            version_name=opex_info.get("opexVersionName", "N/A"),
                            business_code=pkg.get("businessCode", "N/A"),
                            zip_hash=info.get("zipHash", "N/A"),
                            auto_url=replace_gauss_url(info.get("autoUrl", "N/A"))
                        ))

        desc_entry = body.get("description")
        if isinstance(desc_entry, dict):
            changelog = desc_entry.get("panelUrl", "N/A")
        else:
            changelog = "N/A"

        return QueryResult(
            True, status, published_time=published_time, components=components, opex_list=opex_list,
            data={
                "changelog": replace_gauss_url(changelog),
                "security_patch": body.get("securityPatch", "N/A"),
                "version": body.get("realVersionName", body.get("versionName", "N/A")),
                "fake_ota_version": body.get("otaVersion", "N/A"),
                "ota_version": body.get("realOtaVersion", body.get("otaVersion", "N/A"))
            }
        )
    except Exception as e:
        return QueryResult(False, status, error=f"Processing failed: {str(e)}")

def display_result(result: QueryResult):
    if result.success:
        print("\nFetch Info:")
        components = result.components
        if components:
            if len(components) == 1:
                component = components[0]
                print(f"• Link: {component.link}")
            else:
                for i, component in enumerate(components, 1):
                    print(f"\nComponent {i}: {component.name}")
                    print(f"Link: {component.link}")
                    print(f"MD5: {component.md5}")
        
        data = result.data
        print(f"• Changelog: {data['changelog']}")
        if result.published_time:
            print(f"• Published Time: {result.published_time}")
        print(f"• Security Patch: {data['security_patch']}")
        print(f"• Version: {data['version']}")
        print(f"• Ota Version: {data['ota_version']}")
        
        if components and components[0].original_link != components[0].link:
            print(f"\n• Notice: Dynamic Link will expire at {components[0].expires_time}")
            
        if result.opex_list:
            print("\nOpex Info:")
            for i, opex in enumerate(result.opex_list):
                print(f"• Link: {opex.auto_url}")
                print(f"• Zip Hash: {opex.zip_hash}")
                print(f"• Opex Codename: {opex.business_code}")
                print(f"• Opex Version Name: {opex.version_name}")
                if i < len(result.opex_list) - 1:
                    print()
    else:
        if result.response_code == 2004:
            print("\nNo Result")
        elif result.response_code == 308:
            print("\nFlow Limit\nTry again later")
        elif result.response_code == 500:
            print("\nServer Error (Code 500)")
            if result.error:
                print(f"Error: {result.error}")
        elif result.response_code in [204, 2200]:
            print("\nCurrent IMEI is not in test IMEI set")
        elif result.error:
            print(f"\nError: {result.error}")
        else:
            print("\nUnknown Error")

def auto_complete_query(base_ota_prefix: str, config: QueryConfig) -> None:
    suffixes = ["_11.A", "_11.C", "_11.F", "_11.H", "_11.J"]
    last_success_fake = None
    
    if config.anti == 1: config.mode = "taste"

    for suffix in suffixes:
        display_ota = base_ota_prefix + suffix
        decor = ""
        if config.genshin == "1" and "YS" not in base_ota_prefix: decor = "YS"
        elif config.genshin == "2" and "Ovt" not in base_ota_prefix: decor = "Ovt"
        elif config.pre == "1" and "PRE" not in base_ota_prefix: decor = "PRE"
        
        display_name = display_ota.replace(base_ota_prefix, base_ota_prefix + decor) if decor else display_ota
        print(f"\nQuerying for {display_name}")

        processed_ota, processed_model = process_ota_version(
            display_ota, config.region, config.genshin, config.pre, config.model if config.has_custom_model else None
        )
        
        current_config = QueryConfig(**config.__dict__)
        current_config.ota_version = processed_ota
        current_config.model = processed_model
        
        result = query_update(current_config)

        if not result.success and result.response_code == 2004 and config.region == "in" and not config.has_custom_model:
            current_config.model = f"{processed_model}IN"
            result = query_update(current_config)

        if config.anti == 1 and not result.success and result.response_code == 2004 and last_success_fake:
            retry_ota, retry_model = process_ota_version(
                last_success_fake, config.region, config.genshin, config.pre, config.model if config.has_custom_model else None
            )
            retry_config = QueryConfig(**config.__dict__)
            retry_config.ota_version = retry_ota
            retry_config.model = retry_model
            retry_config.anti = 0 
            
            result = query_update(retry_config)
            if not result.success and result.response_code == 2004 and config.region == "in" and not config.has_custom_model:
                retry_config.model = f"{retry_model}IN"
                result = query_update(retry_config)

        if result.success and config.anti == 1:
            fake = result.data.get('fake_ota_version')
            if fake != 'N/A': last_success_fake = fake

        display_result(result)

def parse_args():
    parser = argparse.ArgumentParser(description="OTA Query Tool", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ota_prefix", nargs="?", help="OTA version prefix or device model")
    
    valid_regions = [r for r in REGION_CONFIG.keys() if r not in ["sg_host", "cn_gray"]]
    parser.add_argument("region", nargs="?", type=str.lower, choices=valid_regions, help="Region code")
    
    group_ota = parser.add_argument_group("OTA Options")
    group_ota.add_argument("--model", help="Custom model")
    group_ota.add_argument("--mode", choices=SUPPORTED_MODES, default="manual")
    group_ota.add_argument("--cl", dest="custom_language", help="Custom language (e.g. zh-CN)")
    group_ota.add_argument("--gray", type=int, choices=[0, 1], default=0, help="Gray update")
    group_ota.add_argument("--genshin", choices=["0", "1", "2"], default="0", help="Genshin edition")
    group_ota.add_argument("--pre", choices=["0", "1"], default="0", help="Preview edition")
    group_ota.add_argument("--guid", default="0"*64, help="Device GUID")
    group_ota.add_argument("--components", help="Custom components (name:version)")
    group_ota.add_argument("--anti", type=int, choices=[0, 1], default=0, help="Anti mode")
    
    args = parser.parse_args()
    
    if not args.ota_prefix or not args.region:
        parser.error("ota_prefix and region are required")
    
    if args.pre == "1" and args.guid == "0"*64:
        parser.error("GUID required for pre mode")
        
    return args

def main():
    try:
        args = parse_args()
        
        config = QueryConfig(
            ota_version=args.ota_prefix, model=args.model or "unknown", region=args.region,
            gray=args.gray, mode=args.mode, guid=args.guid, components_input=args.components,
            anti=args.anti, has_custom_model=bool(args.model), genshin=args.genshin, pre=args.pre,
            custom_language=args.custom_language
        )

        ota_upper = args.ota_prefix.upper().replace("OVT", "Ovt")
        processed_ota, processed_model = process_ota_version(
            ota_upper, args.region, args.genshin, args.pre, args.model
        )
        
        config.ota_version = processed_ota
        config.model = processed_model
        config.region = args.region.lower()

        is_simple_version = bool(re.search(r'_\d{2}\.[A-Z]', ota_upper) or ota_upper.count('_') >= 3)
        
        if not is_simple_version:
            auto_complete_query(ota_upper, config)
        else:
            print(f"Querying {config.region.upper()} update")
            
            print(f"Device Model: {config.model}")
            print(f"Full OTA Version: {config.ota_version}")
            
            if config.guid == "0"*64:
                print("Using GUID: Default device ID")
            else:
                print(f"Using GUID: {config.guid[:16]}")

            result = query_update(config)
        
            if not result.success and result.response_code == 2004 and config.region == "in" and not config.has_custom_model:
                config.model += "IN"
                result = query_update(config)

            display_result(result)

    except KeyboardInterrupt:
        sys.exit("\nInterrupted")
    except Exception as e:
        sys.exit(f"\nError: {e}")

if __name__ == "__main__":
    main()
