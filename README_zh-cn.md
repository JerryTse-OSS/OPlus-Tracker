<div align="center">
<table>
  <tr>
    <td valign="center"><a href="README.md"><img src="https://github.com/twitter/twemoji/blob/master/assets/svg/1f1fa-1f1f8.svg" width="16"/> English</td>
    <td valign="center"><img src="https://em-content.zobj.net/thumbs/120/twitter/351/flag-china_1f1e8-1f1f3.png" width="16"/> 简体中文</a></td> 
  </tr>
</table>
</div>

# OPlus 固件查询工具

可查询并解析OPPO、一加（OnePlus）、真我（Realme）设备的 OTA/SOTA/OPEX 升级包下载链接，适配 ColorOS、OxygenOS系统

当前包含脚本:

- `C16_transer.py` → 解析动态链接（处理链接过期问题）
- `tomboy_pro.py`  → OTA 查询工具（支持完整全量包/增量包/灰度包/预览包，可绕过反查询限制）
- `opex_query.py`  → OPEX补丁包 / 运营商定制包查询（适配ColorOS 15/16 商务版）
- `sota_query.py`  → SOTA（软件级OTA/APK）查询与模拟（主要适用于国内版）
## `C16_transer.py`

### 功能
- 自动处理 `downloadCheck` 格式链接的 302 重定向
- 解析链接中的 `Expires` 与 `x-oss-expires` 过期参数
- 输出可用的最终下载链接及对应的过期时间
- 专门针对 ColorOS 16 系统的动态链接做优化处理

### 依赖
- `requests`

安装:
```bash
pip install requests
```

### 用法
```bash
python C16_transer.py "https://gauss-componentotacostmanual-cn.allawnfs.com/.../downloadCheck?Expires=1767225599&..."
```

## `tomboy_pro.py`

这款是高阶OTA 查询工具，支持完整全量包、增量升级、灰度通道、预览版、原神定制版，还能绕过2025年10月后上线的反查询限制。

### 主要功能
- 适配各地区专属服务器及对应的 RSA 加密密钥
- 支持 RSA-OAEP + AES-CTR 双重加密方式
- 自动补全版本号后缀 (`_11.A` / `_11.C` / `_11.F` / `_11.H` / `_11.J`)
- 提供四种查询模式: `manual`, `client_auto`, `server_auto`, `taste`
- 支持`--anti 1` 参数，绕过 ColorOS 16 机型的查询限制
- 可通过 `--components` 参数查询增量 OTA 包 
- 旧版特殊服务器回退 (`--special 1`)
- 模拟 Google 设备校验 (`--fingerprint`)

### 依赖
```text
requests
cryptography
protobuf   (可选，仅--fingerprint模式需要)
```

```bash
pip install -r requirement.txt
```

### 用法
```bash
python tomboy_pro.py <OTA版本前缀> <地区> [参数]
```

**必选参数**
- `<OTA 版本前缀>`     `PJX110` / `PJX110_11.A` / `PJX110_11.C.36_...`
- `<地区>`         `cn` `eu` `in` `sg` `ru` `tr` `th` `gl` `tw` `my` `vn` `id`

**常用可选参数**

| 参数                  | 说明                                          | 示例 / 备注                       |
|-----------------------|--------------------------------------------------|--------------------------------------|
| `--model`             | 强制指定设备型号                                    | `--model PJX110`                     |
| `--gray 1`            | 开启灰度 / 测试通道（仅国内）                      |                                      |
| `--mode taste`        | 尝鲜模式 `--anti 1`                       |                                      |
| `--genshin 1` / `2`   | 原神定制版 (YS / Ovt suffix)                |                                      |
| `--pre 1`             | 预览版 (needs `--guid`)                   |                                      |
| `--guid 64hex`        | 设备 64 位 GUID                              | 预览版 / 尝鲜模式必填               |
| `--components`        | 增量包查询（组件名：完整版本号...）               | `--components System:PJX110_11...`   |
| `--anti 1`            | 绕过 ColorOS 16 反查询限制（2025.10上线）  | 通常搭配 + `--mode taste` 使用             |
| `--fingerprint`       | 改用 Google 设备校验                    | 对氧 OS / 美版机型适用         |

**使用示例**
```bash
# 国内OTA查询
python tomboy_pro.py PJX110_11.A cn

# 绕过ColorOS 16反查询限制
python tomboy_pro.py PLA110_11.A cn --anti 1

# 增量OTA包查询
python tomboy_pro.py PJX110_11.C.36_1360_20250814 cn --components System:PJX110_11.C.35_...

# 传入GUID查询预览版
python tomboy_pro.py PJX110_11.A cn --pre 1 --guid 0123456789abcdef... (64 chars)
```

## `opex_query.py`

专属 OPEX包查询工具（主要适配 ColorOS 15/16 国内版设备）。

### 用法
```bash
python opex_query.py <完整OTA版本号> --info <系统版本>,<品牌>

# 示例
python opex_query.py PJZ110_11.C.84_1840_202601060309 --info 16,oneplus
python opex_query.py PJZ110_11.C.85_...               --info 16,oppo
python opex_query.py RMX5200_11.A.63_...               --info 16,realme
```

**注意**: 需输入 **完整** OTA 版本号，且版本号至少包含3个`_`分段。

## `sota_query.py`

查询 **SOTA**（软件级OTA/APK）升级包，主要用于国内ColorOS 16

### 功能
- 模拟设备端查询，获取最新 SOTA 版本号及APK列表
- 模拟升级请求，提取各APK的直接下载链接
- 具备严格的入参校验，确保符合官方接口要求

### 用法
7个**参数**均为必填：

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

重要说明（2025-2026）
- ColorOS 16 系统新增严格的反查询限制（2025 年 10 月左右上线），多数机型可通过 `--anti `1 + `taste` 模式 + 基础版本号（如 `11.A`）绕过该限制。
- `downloadCheck?` 格式的动态链接有效期通常为**10-30分钟**，获取后请立即使用- `C16_transer.py` 解析并保存最终下载链接。
- 目前 OPEX 和 SOTA 查询功能仅支持**国内版**设备。
- 所有工具每次请求都会重新生成加密密钥与设备 ID，以降低被官方服务器封禁的概率。
