<div align="center">
<br>
<table>
<tr>
<td valign="center"><img src="https://github.com/twitter/twemoji/blob/master/assets/svg/1f1fa-1f1f8.svg" width="16"/> English</td>
<td valign="center"><a href="README_zh-cn.md"><img src="https://em-content.zobj.net/thumbs/120/twitter/351/flag-china_1f1e8-1f1f3.png" width="16"/> 简体中文</a></td>
</tr>
</table>
<br>
</div>

# OPlus Tracker

Collection of tools for querying and resolving OTA / SOTA / OPEX / IOT / Downgrade update links for OPPO, OnePlus, Realme devices (ColorOS / OxygenOS).

Current scripts:

- `C16_transer.py`     → resolves dynamic download links (ColorOS 16+)
- `tomboy_pro.py`      → main OTA query tool (full / delta / gray / preview / anti-query bypass)
- `opex_query.py`      → dedicated OPEX query (CN only)
- `sota_query.py`      → SOTA (Software OTA / modular APK) query (CN only)
- `iot_query.py`       → legacy & IoT server query (CN only)
- `downgrade_query.py` → query official downgrade packages (CN only)
- `realme_edl_query.py` → query official EDL packages for Realme
- `changelog_query.py` → query specific version changelog

## `C16_transer.py`

### Features
- Resolve dynamic links with `downloadCheck?`
- Displays final download link + expiration time

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

### Dependencies
```text
requests
cryptography
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
- `<REGION>`         `cn` `cn_cmcc` `eu` `in` `sg` `ru` `tr` `th` `gl` `tw` `my` `vn` `id` `sa` `mea` `ph` `la` `br` `roe`

**Popular flags**
| Flag              | Meaning                                          | Example / Note                       |
|-------------------|--------------------------------------------------|--------------------------------------|
| `--model`         | Force model                                      | `--model PJX110`                     |
| `--gray 1`        | Test channel (mainly Realme, few OPlus)          |                                      |
| `--mode taste`    | Often used with `--anti 1`                       |                                      |
| `--genshin 1/2`   | Genshin edition (YS / Ovt suffix)                |                                      |
| `--pre 1`         | Preview build (needs `--guid`)                   |                                      |
| `--guid 64hex`    | 64-char device GUID                              | Required for pre/taste               |
| `--components`    | Delta query (name:fullversion,...)               | `--components System:PJX110_11...`   |
| `--anti 1`        | Bypass ColorOS 16 query restriction (~Oct 2025)  | Usually + `--mode taste`             |
| `--nvid 8digit`    | Use custom NV Carrier ID to query                |                                      |

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

# Custom NVID
python tomboy_pro.py RMX3301_11.H sg --nvid 00011011
```

**Note**: Get Delta OTA is pretty special, you may get the components info by run `getprop | grep ro.oplus.version | sed -E 's/\[ro\.oplus\.version\.([^]]+)\]: \[([^]]+)\]/\1:\2/g' | tr '\n' ',' | sed 's/,$//' | sed 's/base/system_vendor/g'` in your device, and make sure using the full OTA version and the same version as your component

## `opex_query.py`

Dedicated tool to query **OPEX** (mainly ColorOS CN variants).

### Usage
```bash
python opex_query.py <FULL_OTA_VERSION> --info <OS_VERSION>,<BRAND>

# Examples
python opex_query.py PJZ110_11.C.84_1840_202601060309 --info 16,oneplus
python opex_query.py RMX5200_11.A.63_... --info 16,realme
```

**Note**: Requires complete OTA version string (at least 3 `_` segments).

## `sota_query.py`

Queries **SOTA** (Software OTA) — mainly for CN ColorOS System APPs updates.

### Usage
All 5 parameters are **required** (see previous version for full example)

## `iot_query.py`

Query tool using the old **iota.coloros.com** special server (CN only).  
Often returns older or special builds no longer available through normal channels.

### Usage
```bash
python iot_query.py <OTA_PREFIX> cn [options]

# Examples
python iot_query.py OWW221 cn
python iot_query.py OWW221_11.A cn --model OWW221
```

**Note**: Only supports region `cn`. Results may be outdated.

## `downgrade_query.py` & `downgrade_query_old.py`

Query official **downgrade packages** from `downgrade.coloros.com` (CN only).  
Useful when you need older official firmware versions that are still signed and allowed for downgrade.

### Features
- Uses AES-256-GCM + RSA-OAEP encryption (matches official downgrade server)
- Requires real **DUID** (64-char SHA256 string from *#6776#)
- Needs **PrjNum** (5-digit project number)
- Returns download URL, changelog, version info, MD5, publish time

### Dependencies
- `requests`
- `cryptography`

Install:
```bash
pip install requests cryptography
```

### Usage of `downgrade_query.py`
```bash
python downgrade_query.py <OTA_PREFIX> <PrjNum> <snNum> <DUID> [--debug 0/1]

# Example
python downgrade_query.py PKX110_11.C 24821 a1b2c3e4 498A44DF1BEC4EB19FBCB3A870FCACB4EC7D424979CC9C517FE7B805A1937746
```

**Constraints**
- `<OTA_PREFIX>` : Must contain at least one `_` (e.g. `PKX110_11.C`)
- `<PrjNum>`     : Exactly 5 digits (e.g. `24821`)
- `<snNum>`     : SN Number from phone
- `<DUID>`       : 64-character SHA256 string (get from dialer code *#6776#)
- `[--debug 0/1]` : Get metadata for official downgrade process

**Output example**
```
Fetch Info:
• Link: https://...
• Changelog: ...
• Version: ColorOS 15.0 (Android 15)
• Ota Version: PKX110_11.C.12_...
• MD5: abcdef123456...
```

### Usage of `downgrade_query_old.py` 
```bash
python downgrade_query.py <OTA_PREFIX> <PrjNum>

# Example
python downgrade_query.py PKX110_11.C 24821
```

**Constraints**
- `<OTA_PREFIX>` : Must contain at least one `_` (e.g. `PKX110_11.C`)
- `<PrjNum>`     : Exactly 5 digits (e.g. `24821`)

**Output example**
```
Fetch Info:
• Link: https://...
• Changelog: ...
• Version: ColorOS 15.0 (Android 15)
• Ota Version: PKX110_11.C.12_...
• MD5: abcdef123456...
```

**Note**: Only works for models/regions that support official downgrade. Server may reject invalid DUID or project number.

## `realme_edl_query.py`

Query tool using REALME Server to query for EDL ROM.

### Usage
```bash
python realme_edl_query.py <VERSION_NAME> <REGION> <DATE>

# Examples
python3 realme_edl_query.py "RMX3888_16.0.3.500(CN01)" CN 202601241320
```

**Output example**
```
Querying for RMX8899_16.0.3.532(CN01)

Fetch Info:
• Link: https://rms11.realme.net/sw/RMX8899domestic_11_16.0.3.532CN01_2026013016580190.zip
```

**Note**: You may get the date from full OTA Version, the third part in `_`

## `changelog_query.py`

Query for specific version changelog

**Positional**  
- `<OTA_PREFIX>`     `PJD110_11.F.39_2390`  
- `<REGION>`         `cn` `cn_cmcc` `eu` `in` `sg` `ru` `tr` `th` `gl` `tw` `my` `vn` `id` `sa` `mea` `ph` `la` `br` `roe`

### Usage
```bash
python3 changelog_query.py <OTA_VERSION> <REGION>

# Examples
python3 changelog_query.py PJD110_11.F.39_2390 CN
```

**Note**: You are allow not to use full OTA Version, but needed two `_` at least(include Version & Version Code)

### Important Notes (2025–2026)
- ColorOS 16 introduced strong anti-query restrictions (~Oct 2025). Use `--anti 1` + `taste` mode + base version (e.g. `11.A`) in `tomboy_pro.py` to bypass on many models.
- Dynamic links from `downloadCheck?` usually expire in **10–30 minutes** — use `C16_transer.py` immediately after getting them.
- `opex_query.py`, `sota_query.py`, `iot_query.py` and `downgrade_query.py` are **CN-only** at the moment.
- All tools regenerate encryption keys / device IDs per request to reduce server-side blocking.
