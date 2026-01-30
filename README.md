<div align="center">
<table>
  <tr>
    <td valign="center"><img src="https://github.com/twitter/twemoji/blob/master/assets/svg/1f1fa-1f1f8.svg" width="16"/> English</td>
    <td valign="center"><a href="README_zh-cn.md"><img src="https://em-content.zobj.net/thumbs/120/twitter/351/flag-china_1f1e8-1f1f3.png" width="16"/> 简体中文</a></td> 
  </tr>
</table>
</div>

# OPlus Tracker

Collection of tools for querying and resolving OTA / SOTA / OPEX update links for OPPO, OnePlus, Realme devices (ColorOS / OxygenOS).

Current scripts:

- `C16_transer.py` → resolves dynamic download link(After ColorOS 16)
- `tomboy_pro.py`  → main OTA query tool (full / delta / gray / preview / anti-query bypass)
- `opex_query.py`  → dedicated OPEX query
- `sota_query.py`  → SOTA (Software OTA) query(CN only)

## `C16_transer.py`

### Features
- Follows 302 redirects from `downloadCheck?` URLs
- Parses `Expires` or `x-oss-expires` parameters
- Displays final download link + expiration time
- Special focus on ColorOS 16 dynamic links

### Dependencies
- `requests`

Install:
```bash
pip install requests
```

### Usage
```bash
python C16_transer.py "https://gauss-componentotacostmanual-cn.allawnfs.com/.../downloadCheck?Expires=1767225599&..."
```

## `tomboy_pro.py`

Main advanced OTA query tool — supports full ROM, delta updates, gray channel, preview builds, Genshin editions, anti-query bypass (post-Oct 2025), etc.

### Main Features
- Auto suffix completion (`_11.A` / `_11.C` / `_11.F` / `_11.H` / `_11.J`)
- Modes: `manual`, `client_auto`, `server_auto`, `taste`
- `--anti 1` bypass for ColorOS 16 restricted models
- Delta OTA via `--components`
- Legacy special server fallback (`--special 1`)
- Google Server Firmware Query (`--fingerprint`)

### Dependencies
```text
requests
cryptography
protobuf   (optional — only for --fingerprint mode)
```

```bash
pip install -r requirements.txt
```

### Usage
```bash
python tomboy_pro.py <OTA_PREFIX> <REGION> [options]
```

**Positional**
- `<OTA_PREFIX>`     `PJX110` / `PJX110_11.A` / `PJX110_11.C.36_...`
- `<REGION>`         `cn` `eu` `in` `sg` `ru` `tr` `th` `gl` `tw` `my` `vn` `id`

**Popular flags**

| Flag                  | Meaning                                          | Example / Note                       |
|-----------------------|--------------------------------------------------|--------------------------------------|
| `--model`             | Force model                                      | `--model PJX110`                     |
| `--gray 1`            | Test channel for Realme(Also few OPlus)          |                                      |
| `--mode taste`        | Often used with `--anti 1`                       |                                      |
| `--genshin 1` / `2`   | Genshin edition (YS / Ovt suffix)                |                                      |
| `--pre 1`             | Preview build (needs `--guid`)                   |                                      |
| `--guid 64hex`        | 64-char device GUID                              | Required for pre/taste               |
| `--components`        | Delta query (name:fullversion,...)               | `--components System:PJX110_11...`   |
| `--anti 1`            | Bypass ColorOS 16 query restriction (~Oct 2025)  | Usually + `--mode taste`             |
| `--fingerprint`       | Use Google OTA Server instead                    | OxygenOS / US variant useful         |

**Examples**
```bash
# Basic CN query
python tomboy_pro.py PJX110_11.A cn

# Anti-query bypass for ColorOS 16
python tomboy_pro.py PLA110_11.A cn --anti 1

# Delta OTA
python tomboy_pro.py PJX110_11.C.36_1360_20250814 cn --components System:PJX110_11.C.35_...

# Preview with GUID
python tomboy_pro.py PJX110_11.A cn --pre 1 --guid 0123456789abcdef... (64 chars)
```

## `opex_query.py`

Dedicated tool to query **OPEX** packages (mainly ColorOS 15/16 CN variants).

### Usage
```bash
python opex_query.py <FULL_OTA_VERSION> --info <OS_VERSION>,<BRAND>

# Examples
python opex_query.py PJZ110_11.C.84_1840_202601060309 --info 16,oneplus
python opex_query.py PJZ110_11.C.85_...               --info 16,oppo
python opex_query.py RMX5200_11.A.63_...               --info 16,realme
```

**Note**: Requires **complete** OTA version string (at least 3 `_` segments).

## `sota_query.py`

Queries **SOTA** (Software OTA / modular APK updates) — mainly used for CN ColorOS 16 modular component updates.

### Features
- Simulates device query → gets latest SOTA version & module list
- Simulates update request → extracts APK module download links
- Strict parameter validation

### Usage
All 7 parameters are **required**:

```bash
python sota_query.py \
  --model PJX110 \
  --brand OnePlus \
  --ota-version PJX110_11.F.13_2130_202512181912 \
  --current-sota "V80P02" \
  --coloros ColorOS16.0.0 \
  --security-patch 2025-12-01 \
  --rom-version "PJX110_16.0.2.400(CN01)"
```

### Important Notes (2025–2026)
- ColorOS 16 introduced strong anti-query restrictions (~Oct 2025). Use `--anti 1` + `taste` mode + base version (e.g. `11.A`) to bypass on many models.
- Dynamic links from `downloadCheck?` usually expire in **10–30 minutes** — use `C16_transer.py` immediately after getting them.
- OPEX and SOTA queries are **CN-only** at the moment.
- All tools regenerate encryption keys / device IDs per request to reduce server-side blocking.
