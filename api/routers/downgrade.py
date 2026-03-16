import sys
import os
import json
import time
from typing import List, Optional

import requests
import urllib3
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from downgrade_query import (
    URL as DOWNGRADE_URL_V3,
    NEGOTIATION_VERSION,
    get_protected_key,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
)
from downgrade_query_old import URL as DOWNGRADE_URL_V2

router = APIRouter()

_CARRIERS = ["10010111", "10011000"]


# --- Request / Response Models ---


class DowngradeQueryRequest(BaseModel):
    ota_prefix: str = Field(
        ...,
        description="OTA prefix (must contain '_11.', e.g. PKX110_11.C)",
    )
    prj_num: str = Field(
        ...,
        description="Project number – exactly 5 digits (e.g. 24821)",
        min_length=5,
        max_length=5,
    )
    sn_num: str = Field(..., description="Serial number from the device (e.g. a1b2c3d4)")
    duid: str = Field(
        ...,
        description="64-character SHA256 device UID (from dialer code *#6776#)",
        min_length=64,
        max_length=64,
    )
    debug: bool = Field(False, description="Include metadata in response when available")


class DowngradeLegacyRequest(BaseModel):
    ota_prefix: str = Field(
        ...,
        description="OTA prefix (e.g. PKX110_11.C). '_11.A' is appended if no suffix found.",
    )
    prj_num: str = Field(
        ...,
        description="Project number – exactly 5 digits",
        min_length=5,
        max_length=5,
    )


class DowngradePackage(BaseModel):
    link: Optional[str] = None
    changelog: Optional[str] = None
    version: Optional[str] = None
    ota_version: Optional[str] = None
    md5: Optional[str] = None
    file_size: Optional[str] = None
    metadata: Optional[str] = None


class DowngradeResponse(BaseModel):
    success: bool
    packages: Optional[List[DowngradePackage]] = None
    error: Optional[str] = None


# --- Shared query helper ---


def _do_downgrade_query(
    url: str,
    ota_version: str,
    prj_num: str,
    sn_num: Optional[str],
    duid: str,
    debug: bool = False,
) -> DowngradeResponse:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    model = ota_version.split("_")[0]

    for idx, carrier in enumerate(_CARRIERS):
        session_key = os.urandom(32)
        iv = os.urandom(12)

        try:
            protected_key = get_protected_key(session_key)
            encrypted_device_id_obj = encrypt_aes_gcm(duid, session_key, iv)

            payload: dict = {
                "model": model,
                "nvCarrier": carrier,
                "prjNum": prj_num,
                "otaVersion": ota_version,
                "deviceId": encrypted_device_id_obj,
            }
            if sn_num is not None:
                payload["serialNo"] = sn_num

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

            # verify=False mirrors the original CLI script; downgrade.coloros.com
            # uses a certificate that urllib3 rejects in some environments.
            resp = requests.post(url, headers=headers, json=payload, timeout=20, verify=False)

            if resp.status_code != 200:
                if idx == 0:
                    time.sleep(1)
                    continue
                raise HTTPException(
                    status_code=502,
                    detail=f"Upstream returned HTTP {resp.status_code}",
                )

            resp_json = resp.json()

            if isinstance(resp_json, dict) and resp_json.get("code") == 1004:
                return DowngradeResponse(success=False, error="DUID/GUID is empty or invalid")

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

            if final_data:
                pkg_list = (
                    final_data.get("data", {}) or {}
                ).get("downgradeVoList")

                if pkg_list:
                    packages: List[DowngradePackage] = []
                    for pkg in pkg_list:
                        file_size = pkg.get("fileSize")
                        size_str = None
                        if file_size is not None:
                            try:
                                size_mb = int(file_size) / 1024 / 1024
                                size_str = f"{file_size} Byte ({size_mb:.0f}M)"
                            except Exception:
                                size_str = str(file_size)

                        metadata = None
                        if debug and final_data.get("data", {}).get("metaData"):
                            metadata = final_data["data"]["metaData"]

                        packages.append(
                            DowngradePackage(
                                link=pkg.get("downloadUrl"),
                                changelog=pkg.get("versionIntroduction"),
                                version=f"{pkg.get('colorosVersion', '')} ({pkg.get('androidVersion', '')})",
                                ota_version=pkg.get("otaVersion"),
                                md5=pkg.get("fileMd5"),
                                file_size=size_str,
                                metadata=metadata,
                            )
                        )
                    return DowngradeResponse(success=True, packages=packages)

            if idx == 0:
                time.sleep(1)
                continue

            return DowngradeResponse(success=False, error="No downgrade package found")

        except HTTPException:
            raise
        except Exception as exc:
            if idx == 0:
                time.sleep(1.5)
                continue
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    return DowngradeResponse(success=False, error="No downgrade package found")


# --- Endpoints ---


@router.post(
    "/query",
    response_model=DowngradeResponse,
    summary="Query downgrade packages (v3, requires DUID)",
)
def downgrade_query(request: DowngradeQueryRequest):
    """
    Query official downgrade packages from `downgrade.coloros.com` (v3 API).

    Requires the device-unique `duid` (64-char SHA256 string obtainable from `*#6776#`).
    Both standard carriers (10010111 and 10011000) are tried automatically.

    Supported region: **CN only**.
    """
    ota_version = request.ota_prefix.upper()

    if "_11." not in ota_version:
        raise HTTPException(
            status_code=422,
            detail="ota_prefix must contain '_11.' (e.g. PKX110_11.C)",
        )
    if not request.prj_num.isdigit() or len(request.prj_num) != 5:
        raise HTTPException(status_code=422, detail="prj_num must be exactly 5 digits")
    if len(request.duid) != 64:
        raise HTTPException(status_code=422, detail="duid must be exactly 64 characters")

    return _do_downgrade_query(
        DOWNGRADE_URL_V3,
        ota_version,
        request.prj_num,
        request.sn_num,
        request.duid,
        request.debug,
    )


@router.post(
    "/query-legacy",
    response_model=DowngradeResponse,
    summary="Query downgrade packages (v2 legacy, no DUID required)",
)
def downgrade_query_legacy(request: DowngradeLegacyRequest):
    """
    Query official downgrade packages using the older v2 API (no DUID needed).

    If no version suffix is found in `ota_prefix`, `_11.A` is appended automatically.

    Supported region: **CN only**.
    """
    if not request.prj_num.isdigit() or len(request.prj_num) != 5:
        raise HTTPException(status_code=422, detail="prj_num must be exactly 5 digits")

    ota_version = request.ota_prefix.upper()
    if "_11." not in ota_version:
        ota_version = ota_version + "_11.A"

    duid = "0" * 64
    return _do_downgrade_query(DOWNGRADE_URL_V2, ota_version, request.prj_num, None, duid)
