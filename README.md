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

**Popular flags** (see table in previous version)

**Examples** (see previous examples)

## `opex_query.py`

Dedicated tool to query **OPEX** (mainly ColorOS CN variants).

### Usage
```bash
python opex_query.py <FULL_OTA_VERSION> --info <OS_VERSION>,<BRAND>

# Examples
python opex_query.py PJZ110_11.C.84_1840_202601060309 --info 16,oneplus
python opex_query.py RMX5200_11.A.63_...               --info 16,realme
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

## `downgrade_query.py`

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

### Usage
```bash
python downgrade_query.py <OTA_PREFIX> <PrjNum> <DUID>

# Example
python downgrade_query.py PKX110_11.C 24821 498A44DF1BEC4EB19FBCB3A870FCACB4EC7D424979CC9C517FE7B805A1937746
```

**Constraints**
- `<OTA_PREFIX>` : Must contain at least one `_` (e.g. `PKX110_11.C`)
- `<PrjNum>`     : Exactly 5 digits (e.g. `24821`)
- `<DUID>`       : 64-character SHA256 string (get from dialer code *#6776#)

**Output example**
```
Fetch Info:
• Link: https://...
• Changelog: ...
• Published Time: 2025-08-12 14:30:00
• Version: ColorOS 15.0 (Android 15)
• Ota Version: PKX110_11.C.12_...
• MD5: abcdef123456...
```

**Note**: Only works for models/regions that support official downgrade. Server may reject invalid DUID or project number.

### Important Notes (2025–2026)
- ColorOS 16 introduced strong anti-query restrictions (~Oct 2025). Use `--anti 1` + `taste` mode + base version (e.g. `11.A`) in `tomboy_pro.py` to bypass on many models.
- Dynamic links from `downloadCheck?` usually expire in **10–30 minutes** — use `C16_transer.py` immediately after getting them.
- `opex_query.py`, `sota_query.py`, `iot_query.py` and `downgrade_query.py` are **CN-only** at the moment.
- All tools regenerate encryption keys / device IDs per request to reduce server-side blocking.
