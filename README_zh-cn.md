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

用于查询和解析 OPPO、一加、真我 设备（ColorOS / OxygenOS）的 OTA / SOTA / OPEX / IOT / 降级更新链接的工具集合.

现有脚本：

- `C16_transer.py` → 解析动态链接（ColorOS 16+）
- `tomboy_pro.py` → 主要 OTA 查询工具（全量包 / 增量包 / 灰度版本 / 预览版本 / 反查询绕过）
- `opex_query.py` → 专用 OPEX 查询工具
- `opex_analyzer.py` → 分析 OPEX 修复的内容
- `sota_query.py` → SOTA（软件 OTA / 模块化 APK）查询工具
- `sota_changelog_query.py` → SOTA（软件 OTA / 模块化 APK）更新日志查询工具
- `iot_query.py` → 旧版及 IoT 服务器查询工具
- `downgrade_query.py` → 查询官方降级包（仅限中国）
- `realme_edl_query.py` → 查询真我官方售后包
- `changelog_query.py` → 查询指定版本的更新日志
- `desc_query.py` → 查询指定版本的更新日志链接
- `config.py` → 公钥、服务器地址及 API 端点配置

## `C16_transer.py`

### 功能

- 解析包含 `downloadCheck?` 的动态链接
- 显示最终下载链接和过期时间

### 依赖

- `requests`

安装命令：

```bash
pip install requests
```

### 使用方法

```bash
python C16_transer.py "https://gauss-componentotacostmanual-cn.allawnfs.com/.../downloadCheck?Expires=1767225599&..."
```

## `tomboy_pro.py`

主要的高级 OTA 查询工具，支持完整包、增量更新、灰度通道、预览版本、原神定制版、反查询绕过（2025 年 10 月之后）等OTA查询工具。

### 主要功能

- 自动补全后缀如（`_11.A` / `_11.C` / `_11.F` / `_11.H` / `_11.J`）
- 模式：`manual`(手动查询)、`client_auto`(客户端查询)、`server_auto`(服务器查询)、`taste`(尝鲜版查询)
- 使用 `--anti 1` 绕过 ColorOS 16 受限机型的查询限制
- 使用 `--components` 查询增量 OTA

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

#### 常用选项

| 选项            | 含义                                            | 示例 / 说明                        |
| --------------- | ----------------------------------------------- | ---------------------------------- |
| `--model`       | 强制指定机型                                    | `--model PJX110`                   |
| `--gray 1`      | 测试通道（主要用于真我和少数一加机型）    |                                    |
| `--mode taste`  | 通常与 `--anti 1` 一同使用                      |                                    |
| `--genshin 1/2` | 原神定制版（YS / Ovt 后缀）                     |                                    |
| `--pre 1`       | 预览版本（需要 `--guid`）                       |                                    |
| `--guid 64hex`  | 64 字符的设备 GUID                              | pre/taste 模式必需                 |
| `--components`  | 增量查询（name:fullversion,...）                | `--components System:PJX110_11...` |
| `--anti 1`      | 绕过 ColorOS 16 查询限制（约 2025 年 10 月）    | 通常搭配 `--mode taste`            |
| `--nvid 8digit` | 使用自定义 NV 运营商 ID 查询                    |                                    |
| `--graynew 1`   | 查询不在尝鲜模式、但存在于灰度服务器的固件   |                                    |
| `--recruit 1`   | 查询需要申请资格的 Beta 阶段固件                |                                    |
| `--orginal_link 1` | 同时打印原始链接和解析后的链接               |                                    |
| `--pki 1`       | 修复 OS17 无法查询内部（测试）版本的问题         |                                    |

#### 示例

```bash
# 基础中国区查询
python tomboy_pro.py PJX110_11.A cn

# 绕过 ColorOS 16 反查询限制
python tomboy_pro.py PLA110_11.A cn --anti 1

# 增量 OTA
python tomboy_pro.py PJX110_11.C.36_1360_20250814 cn --components System:PJX110_11.C.35_...

# 使用 GUID 查询预览版本
python tomboy_pro.py PJX110_11.A cn --pre 1 --guid 0123456789abcdef... (64 chars)

# 自定义 NVID
python tomboy_pro.py RMX3301_11.H sg --nvid 00011011
```

**注意**：增量 OTA 查询较为特殊。你可以在设备上运行 `getprop | grep ro.oplus.version | sed -E 's/\[ro\.oplus\.version\.([^]]+)\]: \[([^]]+)\]/\1:\2/g' | tr '\n' ',' | sed 's/,$//' | sed 's/base/system_vendor/g'` 获取组件信息。请确保使用完整的 OTA 版本，并保证 OTA 版本与组件版本一致。

## `opex_query.py`

用于查询 **OPEX** 的专用工具。

### 使用方法

```bash
python opex_query.py <FULL_OTA_VERSION> <REGION> --info <OS_VERSION>,<BRAND>

# 示例
python opex_query.py PJZ110_11.C.84_1840_202601060309 cn --info 16,oneplus
python opex_query.py RMX5200_11.A.63_... --info 16,realme
```

**注意**：需要完整的 OTA 版本字符串（至少包含 3 个由 `_` 分隔的部分）。

## `opex_analyzer.py`

用于分析 OPEX 包所修复内容的工具。

### 使用方法

```bash
python opex_analyzer.py <URL>
```

## `sota_query.py`

查询 **SOTA**（软件 OTA），主要用于 ColorOS 系统应用更新。

### 使用方法

```bash
python sota_query.py OTA_VERSION REGION --brand BRAND --coloros COLOROS

# 示例
python sota_query.py PJD110_11.F.43_2430_202603192242 cn --brand OnePlus --coloros ColorOS16.0.0

python sota_query.py CPH2573_11.F.43_2430_202603192142 in --brand OnePlus --coloros ColorOS16.0.0
```

**注意**：所有参数均为**必填项**（请参考示例）。

## `sota_changelog_query.py`

查询 **SOTA**（软件 OTA）更新日志，主要用于 ColorOS 系统应用的更新日志。

### 使用方法

```bash
python sota_changelog_query.py OTA_VERSION REGION --brand BRAND --coloros COLOROS

# 示例
python sota_changelog_query.py PJD110_11.F.43_2430_202603192242 cn --brand OnePlus --coloros ColorOS16.0.0

python sota_changelog_query.py CPH2573_11.F.43_2430_202603192142 in --brand OnePlus --coloros ColorOS16.0.0
```

**注意**：用法与 `sota_query.py` 相同，但此脚本仅查询更新日志。

## `iot_query.py`

使用旧版专用服务器 **iota.coloros.com** 的查询工具。<br>
通常可查询到常规渠道已不再提供的旧版本或特殊版本。

### 使用方法

```bash
python iot_query.py <OTA_PREFIX> cn [options]

# 示例
python iot_query.py OWW221 cn
python iot_query.py OWW221_11.A cn --model OWW221
```

**注意**：仅支持 `cn` 地区，查询结果可能已经过时。

## `downgrade_query.py` & `downgrade_query_old.py`

从 `downgrade.coloros.com` 查询官方**降级包**（仅限中国）。<br>
适用于获取仍有签名且允许降级的旧版官方固件。

### 功能

- 使用 AES-256-GCM + RSA-OAEP 加密（与官方降级服务器一致）
- 需要真实的 **DUID**（通过 \*#6776# 获取的 64 字符 SHA256 字符串）
- 需要 **PrjNum**（5 位项目编号）
- 返回下载 URL、更新日志、版本信息、MD5 和发布时间

### 依赖项

- `requests`
- `cryptography`

安装：

```bash
pip install requests cryptography
```

### `downgrade_query.py` 使用方法

```bash
python downgrade_query.py <OTA_PREFIX> <PrjNum> <snNum> <DUID> [--debug 0/1]

# 示例
python downgrade_query.py PKX110_11.C 24821 a1b2c3e4 498A44DF1BEC4EB19FBCB3A870FCACB4EC7D424979CC9C517FE7B805A1937746
```

#### 参数

- `<OTA_PREFIX>`：必须至少包含一个 `_`（例如 `PKX110_11.C`）
- `<PrjNum>`：必须是 5 位数字（例如 `24821`）
- `<snNum>`：手机的 SN 序列号
- `<DUID>`：64 字符的 SHA256 字符串（通过拨号盘代码 \*#6776# 获取）
- `[--debug 0/1]`：获取官方降级流程的元数据

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

#### 参数约束

- `<OTA_PREFIX>`：必须至少包含一个 `_`（例如 `PKX110_11.C`）
- `<PrjNum>`：必须是 5 位数字（例如 `24821`）

#### 输出示例

```text
Fetch Info:
• Link: https://...
• Changelog: ...
• Version: ColorOS 15.0 (Android 15)
• Ota Version: PKX110_11.C.12_...
• MD5: abcdef123456...
```

**注意**：仅适用于支持官方降级的机型和地区。服务器可能拒绝无效的 DUID 或项目编号。

## `realme_edl_query.py`

使用真我服务器查询EDL(9008)刷机包工具。

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

**注意**：日期可从完整 OTA 版本中获取，即由 `_` 分隔的第三部分。

## `changelog_query.py`

查询指定版本的更新日志。

#### 参数约束

- `<OTA_PREFIX>` `PJD110_11.F.39_2390`
- `<REGION>` `cn` `cn_cmcc` `eu` `in` `sg` `ru` `tr` `th` `gl` `tw` `my` `vn` `id` `sa` `mea` `ph` `la` `br` `roe`
- `[--pre 0/1]`：获取测试版本 / 测试设备的更新日志

### 使用方法

```bash
python changelog_query.py <OTA_VERSION> <REGION>

# 示例
python changelog_query.py PJD110_11.F.39_2390 cn

python changelog_query.py PLP110_11.A.40_0400 cn --pre 1
```

**注意**：无需使用完整的 OTA 版本，但必须至少包含两个 `_`（即包含版本和版本代码）。

## `desc_query.py`

查询指定版本的更新日志链接。

#### 参数约束

- `<OTA_PREFIX>` `PJD110_11.F.39_2390`
- `<REGION>` `cn` `cn_cmcc` `eu` `in` `sg` `ru` `tr` `th` `gl` `tw` `my` `vn` `id` `sa` `mea` `ph` `la` `br` `roe`

### 使用方法

```bash
python desc_query.py <OTA_VERSION> <REGION>

# 示例
python desc_query.py PJD110_11.F.39_2390 cn

python desc_query.py PLP110PRE_11.A.40_0400 cn
```

**注意**：可以使用完整的 OTA 版本，也支持只提供至少包含两个 `_` 的版本（即包含版本和版本代码）。

### 重要说明（2025–2026）

- ColorOS 16 引入了严格的反查询限制（约 2025 年 10 月）。对于许多机型，可以在 `tomboy_pro.py` 中使用 `--anti 1` + `taste` 模式 + 基础版本（例如 `11.A`）进行绕过。
- 来自 `downloadCheck?` 的动态链接通常会在 **10–30 分钟**内过期，请在链接过期后立即使用 `C16_transer.py`重新获取链接。
- `downgrade_query.py` 目前**仅支持中国**。
- 所有工具都会为每次请求重新生成加密密钥 / 设备 ID，以减少服务器端封锁。
