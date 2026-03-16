import sys
import os
import json
import base64
import time
import random
import string
from typing import List, Optional

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from opex_query import (
    OPEX_PUBLIC_KEY_CN,
    OPEX_CONFIG_CN,
    generate_protected_key,
    aes_ctr_encrypt,
    aes_ctr_decrypt,
    parse_os_version,
    parse_brand,
    replace_gauss_url,
)

router = APIRouter()


# --- Request / Response Models ---


class OPEXQueryRequest(BaseModel):
    ota_version: str = Field(
        ...,
        description="Full OTA version string (e.g. PJZ110_11.C.84_1840_202601060309). "
        "At least 3 underscore-separated segments are recommended.",
    )
    os_version: str = Field(
        ...,
        description="ColorOS major version number or full string (e.g. '16' or 'ColorOS16.0.0')",
    )
    brand: str = Field(..., description="Device brand: OPPO, OnePlus, or Realme")


class OPEXPackageResponse(BaseModel):
    business_code: str
    zip_hash: str
    auto_url: str
    version_name: str


class OPEXResponse(BaseModel):
    success: bool
    packages: Optional[List[OPEXPackageResponse]] = None
    error: Optional[str] = None


# --- Endpoint ---


@router.post(
    "/query",
    response_model=OPEXResponse,
    summary="Query OPEX (carrier/patch) packages",
)
def opex_query(request: OPEXQueryRequest):
    """
    Query OPEX carrier/patch packages for a ColorOS device (CN region only).

    `os_version` can be a bare major number (`16`), a short string (`16.0.0`),
    or the full `ColorOS16.0.0` format.
    """
    os_version = parse_os_version(request.os_version)

    # parse_brand calls sys.exit on invalid brand – convert to HTTPException
    try:
        brand = parse_brand(request.brand)
    except SystemExit as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    model = request.ota_version.split("_")[0] if request.ota_version else "unknown"
    url = f"https://{OPEX_CONFIG_CN['host']}{OPEX_CONFIG_CN['endpoint']}"

    for attempt in range(10):
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        device_id = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=64)
        ).lower()

        protected_key_str = generate_protected_key(aes_key, OPEX_PUBLIC_KEY_CN)

        expire_time = str(time.time_ns() + 10**9 * 60 * 60 * 24)
        headers = {
            "language": OPEX_CONFIG_CN["language"],
            "newLanguage": OPEX_CONFIG_CN["language"],
            "androidVersion": "unknown",
            "nvCarrier": OPEX_CONFIG_CN["carrier_id"],
            "deviceId": device_id,
            "osVersion": os_version,
            "productName": model,
            "brand": brand,
            "queryMode": "0",
            "version": "1",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "okhttp/5.3.2",
            "protectedKey": json.dumps(
                {
                    "opex": {
                        "protectedKey": protected_key_str,
                        "version": expire_time,
                        "negotiationVersion": OPEX_CONFIG_CN["public_key_version"],
                    }
                }
            ),
        }

        raw_payload = {
            "mode": "0",
            "time": int(time.time() * 1000),
            "isRooted": "0",
            "isLocked": True,
            "type": "0",
            "deviceId": device_id,
            "opex": {"check": True},
            "businessList": [],
            "otaVersion": request.ota_version,
        }

        cipher_text = aes_ctr_encrypt(json.dumps(raw_payload).encode(), aes_key, iv)
        request_data = {
            "cipher": base64.b64encode(cipher_text).decode(),
            "iv": base64.b64encode(iv).decode(),
        }

        try:
            response = requests.post(url, headers=headers, json=request_data, timeout=30)
        except requests.RequestException as exc:
            if attempt < 9:
                time.sleep(2 * (attempt + 1))
                continue
            raise HTTPException(status_code=502, detail=f"Network error: {exc}") from exc

        if response.status_code != 200:
            if attempt < 9:
                time.sleep(2 * (attempt + 1))
                continue
            raise HTTPException(
                status_code=502, detail=f"Upstream returned HTTP {response.status_code}"
            )

        resp_json = response.json()
        code = resp_json.get("code", resp_json.get("responseCode", 200))

        if code == 500:
            if attempt < 9:
                time.sleep(2 * (attempt + 1))
                continue
            raise HTTPException(status_code=502, detail="Upstream server error (code 500)")

        if code not in (200, 500):
            msg = resp_json.get("message") or resp_json.get("error") or "Unknown error"
            raise HTTPException(status_code=502, detail=f"API error (code {code}): {msg}")

        # Decrypt response
        try:
            decrypted = aes_ctr_decrypt(
                base64.b64decode(resp_json["cipher"]),
                aes_key,
                base64.b64decode(resp_json["iv"]),
            )
            body = json.loads(decrypted.decode())
        except Exception as exc:
            if attempt < 9:
                time.sleep(2 * (attempt + 1))
                continue
            raise HTTPException(status_code=502, detail="Failed to decrypt response") from exc

        # Parse packages
        raw_data = body.get("data")
        ver_name = "N/A"
        if isinstance(raw_data, list):
            opex_packages = raw_data
            ver_name = body.get("opexVersionName", "N/A")
        elif isinstance(raw_data, dict):
            opex_packages = raw_data.get("opexPackage", [])
            ver_name = raw_data.get("opexVersionName", "N/A")
        else:
            opex_packages = []

        packages: List[OPEXPackageResponse] = []
        for pkg in opex_packages:
            if not isinstance(pkg, dict):
                continue
            if pkg.get("code") == 200 and isinstance(pkg.get("info"), dict):
                info = pkg["info"]
                packages.append(
                    OPEXPackageResponse(
                        business_code=pkg.get("businessCode", "N/A"),
                        zip_hash=info.get("zipHash", "N/A"),
                        auto_url=replace_gauss_url(info.get("autoUrl", "N/A")),
                        version_name=ver_name,
                    )
                )

        return OPEXResponse(success=True, packages=packages if packages else None)

    raise HTTPException(status_code=502, detail="All retry attempts exhausted")
