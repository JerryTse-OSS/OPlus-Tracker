# OPlus Tracker

## `C16_transer.py`

### Features:
- Parses `Expires` or `x-oss-expires` parameters from URLs to determine link validity.
- Prints ColorOS 16 Dynamic Decrypt Link information.

### Dependencies

Required Python packages:
- [`requests`](https://pypi.org/project/requests/)

Standard library modules used:
- `urllib.parse`
- `datetime`
- `time`
- `sys`

Install via:
```bash
pip install requests
```

### Usage

```bash
python C16_transer.py "YOUR_DOWNLOAD_CHECK_URL_HERE"
```

The script expects a URL containing `downloadCheck?` (usually returned by OTA query tools).

**Example:**
```bash
python C16_transer.py "https://gauss-componentotacostmanual-cn.allawnfs.com/ota/xxx/downloadCheck?Expires=1767225599&..."
```

It will follow the redirect (302) and show the final download link + expiration time.

## `tomboy_pro.py`

Advanced OTA update query tool for OPPO / OnePlus / Realme devices (ColorOS / OxygenOS).

Supports querying full OTA, incremental (delta) OTA, preview builds, Genshin Impact special editions, gray mode, OPEX packages, and bypass anti-query mode (introduced ~Oct 2025).

### Main Features
- Region-specific OTA servers & RSA public keys
- RSA-OAEP protected AES key negotiation
- AES-CTR request/response encryption
- Automatic suffix completion for partial version input
- Supports `manual`, `client_auto`, `server_auto`, `taste` modes
- Delta/incremental OTA query via `--components`
- OPEX update query support
- Google check-in simulation (fingerprint mode)
- Anti-query bypass logic (`--anti 1`) for post-2025 restrictions

### Dependencies

Required packages:
- [`requests`](https://pypi.org/project/requests/)
- [`cryptography`](https://pypi.org/project/cryptography/)
- [`protobuf`](https://pypi.org/project/protobuf/) *(optional — only needed for Google check-in / fingerprint mode)*

Standard library:
- `json`, `base64`, `hashlib`, `os`, `sys`, `time`, `random`, `argparse`, `gzip`, `binascii`, `re`, `datetime`

Install:
```bash
pip install -r requirements.txt
```

### Usage

```bash
python tomboy_pro.py <OTA_VERSION_PREFIX> <REGION> [options]
```

**Positional arguments:**
- `OTA_VERSION_PREFIX`  
  Examples:  
  - `PJX110`  
  - `PJX110_11.A`  
  - `PJX110_11.C.36_1360_202508141954`  
  - or just model name `PJX110` (will try common suffixes)

- `REGION`  
  Supported: `cn`, `eu`, `in`, `sg`, `ru`, `tr`, `th`, `gl`, `tw`, `my`, `vn`, `id`

**Important Options:**

| Flag                        | Description                                                                                 | Default    |
|-----------------------------|---------------------------------------------------------------------------------------------|------------|
| `--model MODEL`             | Force specific model (overrides auto-detection)                                             | auto       |
| `--gray 0/1`                | Query gray (test) channel                                                                   | 0          |
| `--mode MODE`               | Query mode: `manual`, `client_auto`, `server_auto`, `taste`                                 | `manual`   |
| `--genshin 0/1/2`           | Genshin Impact edition (1=YS, 2=Ovt)                                                        | 0          |
| `--pre 0/1`                 | Preview / early access build (requires `--guid`)                                            | 0          |
| `--guid 64hexchars`         | 64-character device GUID (required for pre/taste/guid-specific queries)                     | 000…0      |
| `--components comp:ver,...` | Query delta/incremental OTA (full version required in value)                                | —          |
| `--anti 0/1`                | Anti-anti-query mode (helps get ColorOS 16 on some models after Oct 2025 restriction)      | 0          |
| `--special 0/1`             | Use legacy special CN server (sometimes gets early/old builds)                              | 0          |
| `--opex 0/1`                | Query OPEX (carrier/business) packages — only CN supported                                  | 0          |
| `--info "15,oneplus"`       | Required when `--opex 1` — format: `osVersion,brand` (oppo/oneplus/realme)                  | —          |
| `--fingerprint "..."`       | Use Google check-in API instead of OPlus server (OxygenOS or US Varient)                       | —          |

### Examples

1. Basic query (China)
```bash
python tomboy_pro.py PJX110_11.A cn
```

2. Gray mode (China)
```bash
python tomboy_pro.py PJX110_11.A cn --gray 1
```

3. Genshin Impact edition
```bash
python tomboy_pro.py PJE110_11.C cn --genshin 1
```

4. Preview build (requires GUID)
```bash
python tomboy_pro.py PJX110_11.A cn --pre 1 --guid 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

5. Delta / incremental OTA
```bash
python tomboy_pro.py PJX110_11.C.36_1360_202508141954 cn --components System:PJX110_11.C.35_1350_202507201122,OtherComp:1.0.0
```

6. Anti-query bypass for ColorOS 16 (late 2025+)
```bash
python tomboy_pro.py PLA110_11.A cn --anti 1
```

7. OPEX / carrier package query (CN only)
```bash
python tomboy_pro.py PJZ110_11.C.84_1840_202601060309 cn --opex 1 --info "16,oneplus"
```

8. Specific query mode
```bash
python tomboy_pro.py PJX110 CN --mode taste
```

### Important Notes (2025–2026)

- Since ~October 2025, OPlus added server-side anti-query restrictions for ColorOS 16 on many models.
- Using `--anti 1` + base version like `11.A` + `taste` mode can often bypass this.
- `--opex 1` is currently only supported in China region.
- Google check-in mode (`--fingerprint`) is useful for OxygenOS global(US Varient) updates.
- Many dynamic download links expire quickly (usually 10min & 30min). Use `C16_transer.py` to resolve `downloadCheck` URLs.
