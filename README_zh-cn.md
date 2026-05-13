<div align="center">
    <br>
    <table>
        <tr>
            <td valign="center"><a href="README.md"><img src="https://github.com/twitter/twemoji/blob/master/assets/svg/1f1fa-1f1f8.svg" width="16"/>English</a></td>
            <td valign="center"><a href="README_zh-cn.md"><img src="https://em-content.zobj.net/thumbs/120/twitter/351/flag-china_1f1e8-1f1f3.png" width="16"/>简体中文</a></td>
        </tr>
    </table>
    <br>
</div>

# OPlus Tracker

## 项目简介

**OPlus Tracker** 是一个用于查询和解析 OPPO、OnePlus、Realme 设备（ColorOS / OxygenOS）的 OTA / SOTA / OPEX / IOT / 降级更新链接的工具集合。

## 现有脚本

- `C16_transer.py` → 解析动态下载链接（ColorOS 16+）
- `tomboy_pro.py` → 主要 OTA 查询工具（完整版 / 增量 / 灰度 / 预览 / 反查询绕过）
- `opex_query.py` → 专用 OPEX 查询（仅限国内）
- `opex_analyzer.py` → 分析 OPEX 修复的内容
- `sota_query.py` → SOTA（软件 OTA / 模块化 APK）查询（仅限国内）
- `sota_changelog_query.py` → SOTA（软件 OTA / 模块化 APK）更新日志查询（仅限国内）
- `iot_query.py` → 旧版 & IoT 服务器查询（仅限国内）
- `downgrade_query.py` → 查询官方降级包（仅限国内）
- `realme_edl_query.py` → 查询 Realme 官方 EDL 包
- `changelog_query.py` → 查询特定版本的更新日志
- `desc_query.py` → 查询特定版本的更新日志 URL
- `config.py` → 公钥、服务器地址和 API 端点的配置

---

## `C16_transer.py`

### 功能

- 使用 `downloadCheck?` 解析动态链接
- 显示最终下载链接 + 过期时间

### 依赖项

- `requests`

安装方式：

```bash
pip install requests
```

### 使用方法

```bash
python C16_transer.py "https://gauss-componentotacostmanual-cn.allawnfs.com/.../downloadCheck?Expires=1767225599&..."
```

---

## `tomboy_pro.py`

主要的高级 OTA 查询工具 — 支持完整 ROM、增量更新、灰度频道、预览版本、原神版本、反查询绕过（2025年10月后）等。

### 主要功能

- 自动后缀完成（`_11.A` / `_11.C` / `_11.F` / `_11.H` / `_11.J`）
- 模式：`manual`（手动）、`client_auto`（客户端自动）、`server_auto`（服务器自动）、`taste`（尝鲜）
- `--anti 1` 绕过 ColorOS 16 受限机型
- 通过 `--components` 进行增量 OTA

### 依赖项

```text
requests
cryptography
```

```bash
pip install -r requirements.txt
```

### 使用方法

```bash
python tomboy_pro.py <OTA_PREFIX> <REGION> [options]
```

#### 位置参数

- `<OTA_PREFIX>` `PJX110` / `PJX110_11.A` / `PJX110_11.C.36_...`
- `<REGION>` `cn` `cn_cmcc` `eu` `in` `sg` `ru` `tr` `th` `gl` `tw` `my` `vn` `id` `sa` `mea` `ph` `la` `br` `roe`

#### 常用标志

| 标志            | 含义                                     | 示例 / 说明                   |
| --------------- | ---------------------------------------- | ----------------------------- |
| `--model`       | 强制指定型号                             | `--model PJX110`              |
| `--gray 1`      | 测试频道（主要用于 Realme，少数 OPlus）  |                               |
| `--mode taste`  | 常与 `--anti 1` 配合使用                 |                               |
| `--genshin 1/2` | 原神版本（YS / Ovt 后缀）                |                               |
| `--pre 1`       | 预览版本（需要 `--guid`）                |                               |
| `--guid 64hex`  | 64 字符设备 GUID                         | 预览版/品尝模式必需           |
| `--components`  | 增量查询（name:fullversion,...）         | `--components System:PJX110_11...` |
| `--anti 1`      | 绕过 ColorOS 16 查询限制（~2025年10月）  | 通常 + `--mode taste`         |
| `--nvid 8digit` | 使用自定义 NV 运营商 ID 查询             |                               |
| `--graynew 1`   | 查询不在品尝模式但在灰度服务器中的固件   |                               |

#### 使用示例

```bash
# 基本中国区查询
python tomboy_pro.py PJX110_11.A cn

# ColorOS 16 反查询绕过
python tomboy_pro.py PLA110_11.A cn --anti 1

# 增量 OTA
python tomboy_pro.py PJX110_11.C.36_1360_20250814 cn --components System:PJX110_11.C.35_...

# 带 GUID 的预览版本
python tomboy_pro.py PJX110_11.A cn --pre 1 --guid 0123456789abcdef... (64 个字符)

# 自定义 NVID
python tomboy_pro.py RMX3301_11.H sg --nvid 00011011
```

**注意**：获取增量 OTA 比较特殊，你可以通过运行 `getprop | grep ro.oplus.version | sed -E 's/\[ro\.oplus\.version\.([^]]+)\]: \[([^]]+)\]/\1:\2/g' | tr '\n' ',' [...]` 来获取组件信息

---

## `opex_query.py`

专用工具，用于查询 **OPEX**（主要是用于国内的ColorOS补丁更新）。

### 使用方法

```bash
python opex_query.py <FULL_OTA_VERSION> --info <OS_VERSION>,<BRAND>

# 示例
python opex_query.py PLG110_11.A.98_0980_202604281448 --info 16,oneplus
python opex_query.py RMX5200_11.A.63_... --info 16,realme
```

PLG110_11.A.98_0980_202604281448
**注意**：需要完整的 OTA 版本字符串（至少 3 个 `_` 分隔符）。

---

## `opex_analyzer.py`

用于分析 OPEX 修复内容的工具

### 使用方法

```bash
python opex_analyzer.py <URL>
```

---

## `sota_query.py`

查询 **SOTA**（软件 OTA）— 主要用于国内ColorOS 系统应用更新。

### 使用方法

```bash
python sota_query.py --brand BRAND --ota-version OTA_VERSION --coloros COLOROS

# 示例
python sota_query.py --brand OnePlus --ota-version PJX110_11.F.15_2150_202602051458 --coloros ColorOS16.0.0
```

**注意**：所有 3 个参数都是**必需的**（参考示例）

---

## `sota_changelog_query.py`

查询 **SOTA**（软件 OTA）更新日志 — 主要用于国内ColorOS 系统应用更新。

### 使用方法

```bash
python sota_changelog_query.py --brand BRAND --ota-version OTA_VERSION --coloros COLOROS

# 示例
python sota_changelog_query.py --brand OnePlus --ota-version PJX110_11.F.15_2150_202602051458 --coloros ColorOS16.0.0
```

**注意**：与 `sota_query.py` 相同，但只查询更新日志

---

## `iot_query.py`

使用旧的 **iota.coloros.com** 特殊服务器的查询工具（仅限国内）。  
通常返回通过正常渠道不再可用的更早或特殊版本。

### 使用方法

```bash
python iot_query.py <OTA_PREFIX> cn [options]

# 示例
python iot_query.py OWW221 cn
python iot_query.py OWW221_11.A cn --model OWW221
```

**注意**：仅支持 `cn` 地区。结果可能已过时。

---

## `downgrade_query.py` & `downgrade_query_old.py`

从 `downgrade.coloros.com` 查询官方**降级包**（仅限国内）。  
当你需要仍然签名并允许降级的较旧官方固件版本时很有用。

### 功能

- 使用 AES-256-GCM + RSA-OAEP 加密（与官方降级服务器匹配）
- 需要真实的 **DUID**（来自 \*#6776# 的 64 字符 SHA256 字符串）
- 需要 **PrjNum**（5 位项目编号）
- 返回下载 URL、更新日志、版本信息、MD5、发布时间

### 依赖项

- `requests`
- `cryptography`

安装方式：

```bash
pip install requests cryptography
```

### `downgrade_query.py` 使用方法

```bash
python downgrade_query.py <OTA_PREFIX> <PrjNum> <snNum> <DUID> [--debug 0/1]

# 示例
python downgrade_query.py PKX110_11.C 24821 a1b2c3e4 498A44DF1BEC4EB19FBCB3A870FCACB4EC7D424979CC9C517FE7B805A1937746
```

#### 约束条件

- `<OTA_PREFIX>` : 必须至少包含一个 `_`（例如 `PKX110_11.C`）
- `<PrjNum>` : 恰好 5 位数字（例如 `24821`）
- `<snNum>` : 手机的 SN 号码
- `<DUID>` : 64 字符 SHA256 字符串（从拨号代码 \*#6776# 获取）
- `[--debug 0/1]` : 获取官方降级过程的元数据

#### 输出示例

```text
Fetch Info:
• Link: https://...
• Changelog: ...
• Version: ColorOS 15.0 (Android 15)
• Ota Version: PKX110_11.C.12_...
• MD5: abcdef123456...
```

### `downgrade_query_old.py` 使用方法

```bash
python downgrade_query_old.py <OTA_PREFIX> <PrjNum>

# 示例
python downgrade_query_old.py PKX110_11.C 24821
```

#### 约束条件

- `<OTA_PREFIX>` : 必须至少包含一个 `_`（例如 `PKX110_11.C`）
- `<PrjNum>` : 恰好 5 位数字（例如 `24821`）

#### 输出示例

```text
Fetch Info:
• Link: https://...
• Changelog: ...
• Version: ColorOS 15.0 (Android 15)
• Ota Version: PKX110_11.C.12_...
• MD5: abcdef123456...
```

**注意**：仅适用于支持官方降级的型号/地区。服务器可能会拒绝无效的 DUID 或项目编号。

---

## `realme_edl_query.py`

使用realme服务器查询 EDL ROM 的查询工具。

### 使用方法

```bash
python realme_edl_query.py <VERSION_NAME> <REGION> <DATE>

# 示例
python realme_edl_query.py "RMX3888_16.0.3.500(CN01)" CN 202601241320
```

#### 输出示例

```text
Querying for RMX8899_16.0.3.532(CN01)

Fetch Info:
• Link: https://rms11.realme.net/sw/RMX8899domestic_11_16.0.3.532CN01_2026013016580190.zip
```

**注意**：你可以从完整 OTA 版本的 `_` 分隔的第三部分获取日期

---

## `changelog_query.py`

查询特定版本的更新日志

#### 约束条件

- `<OTA_PREFIX>` `PJD110_11.F.39_2390`
- `<REGION>` `cn` `cn_cmcc` `eu` `in` `sg` `ru` `tr` `th` `gl` `tw` `my` `vn` `id` `sa` `mea` `ph` `la` `br` `roe`
- `[--pre 0/1]` : 获取测试版本 / 测试设备的更新日志

### 使用方法

```bash
python changelog_query.py <OTA_VERSION> <REGION>

# 示例
python changelog_query.py PJD110_11.F.39_2390 cn

python changelog_query.py PLP110_11.A.40_0400 cn --pre 1
```

**注意**：你不需要使用完整的 OTA 版本，但至少需要两个 `_`（包括版本 & 版本代码）

---

## `desc_query.py`

查询特定版本的更新日志 URL

#### 约束条件

- `<OTA_PREFIX>` `PJD110_11.F.39_2390`
- `<REGION>` `cn` `cn_cmcc` `eu` `in` `sg` `ru` `tr` `th` `gl` `tw` `my` `vn` `id` `sa` `mea` `ph` `la` `br` `roe`

### 使用方法

```bash
python desc_query.py <OTA_VERSION> <REGION>

# 示例
python desc_query.py PJD110_11.F.39_2390 cn

python desc_query.py PLP110PRE_11.A.40_0400 cn
```

**注意**：你可以使用完整的 OTA 版本，但也支持至少两个 `_`（包括版本 & 版本代码）

---

## 重要说明（2025–2026）

- **ColorOS 16** 引入了强大的反查询限制（~2025年10月）。在许多型号上，使用 `tomboy_pro.py` 中的 `--anti 1` + `taste` 模式 + 基础版本（例如 `11.A`）来绕过。
- 来自 `downloadCheck?` 的动态链接通常在 **10–30 分钟内过期** — 获取后立即使用 `C16_transer.py`