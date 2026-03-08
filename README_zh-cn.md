<div align="center"> 
 <table> 
   <tr> 
     <td valign="center"><a href="README.md"><img src="https://github.com/twitter/twemoji/blob/master/assets/svg/1f1fa-1f1f8.svg" width="16"/> English</td> 
     <td valign="center"><img src="https://em-content.zobj.net/thumbs/120/twitter/351/flag-china_1f1e8-1f1f3.png" width="16"/> 简体中文</a></td>  
   </tr> 
 </table> 
 </div> 
  
 # OPlus 固件查询工具 
  
 可查询并解析OPPO、一加（OnePlus）、真我（Realme）设备的 OTA/SOTA/OPEX/IOT/ 降级，升级包下载链接，适用于ColorOS、OxygenOS系统 
  
 当前包含脚本: 
  
 - `C16_transer.py` → 解决动态下载链接问题（ColorOS 16） 
 - `tomboy_pro.py`  → OTA 查询工具（支持完整全量包/增量包/灰度包/预览包，可绕过反查询限制） 
 - `opex_query.py`  → OPEX补丁包查询 
 - `sota_query.py`  → SOTA（软件级OTA）主要适用于国内版 
 - `iot_query.py` → 查询旧版及服务器（仅限中国）
 - `downgrade_query.py` → 查询官方降级包（仅限中国）
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
  
 ### 使用方法 
 ```bash 
 python C16_transer.py "https://gauss-componentotacostmanual-cn.allawnfs.com/.../downloadCheck?Expires=1767225599&..." 
 ``` 
  
 ## `tomboy_pro.py` 
  
 这款是高阶OTA 查询工具，支持完整全量包、增量升级、灰度通道、预览版、原神定制版，还能绕过2025年10月后上线的反查询限制。 
  
 ### 主要功能 
 - 自动补全版本号后缀 (`_11.A` / `_11.C` / `_11.F` / `_11.H` / `_11.J`) 
 - 提供四种查询模式: `manual`, `client_auto`, `server_auto`, `taste` 
 - 支持`--anti 1` 参数，绕过 ColorOS 16 机型的查询限制 
 - 可通过 `--components` 参数查询增量 OTA 包  
 - 旧版特殊服务器回退 (`--special 1`) 
 - Google 服务器固件查询 (`--fingerprint`) 
  
 ### 依赖 
 ```text 
 requests 
 cryptography 
 protobuf   (可选，仅--fingerprint模式需要) 
 ``` 
  
 ```bash 
 pip install -r requirements.txt 
 ``` 
  
 ### 使用方法 
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
 | `--gray 1`            | Realme（以及部分 OPlus）的测试频道                      |                                      | 
 | `--mode taste`        | 尝鲜模式 `--anti 1`                       |                                      | 
 | `--genshin 1` / `2`   | 原神定制版 (YS / Ovt suffix)                |                                      | 
 | `--pre 1`             | 预览版 (needs `--guid`)                   |                                      | 
 | `--guid 64hex`        | 设备 64 位 GUID                              | 预览版 / 尝鲜模式必填               | 
 | `--components`        | 增量包查询（组件名：完整版本号...）               | `--components System:PJX110_11...`   | 
 | `--anti 1`            | 绕过 ColorOS 16 反查询限制（2025.10上线）  | 通常搭配 + `--mode taste` 使用             | 
 | `--fingerprint`       | 请改用 Google OTA 服务器                    | 对氧 OS / 美版机型适用         | 
  
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
  
 ### 使用方法 
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
  
 ### 使用方法 
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
 ## `iot_query.py`

使用旧版 **iota.coloros.com** 特殊服务器（仅限中国大陆）的查询工具。
通常会返回一些已不再通过常规渠道提供的旧版本或特殊版本。

### 使用方法
```bash
python iot_query.py <OTA_PREFIX> cn [options]

# 示例
python iot_query.py OWW221 cn
python iot_query.py OWW221_11.A cn --model OWW221
```

**注意**: 仅支持`中国`地区。结果可能存在时效性问题。

## `downgrade_query.py` & `downgrade_query_old.py`

从 `downgrade.coloros.com`（仅限中国大陆地区）查询官方**降级包**。
当您需要仍然经过签名且允许降级的旧版官方固件时，此功能非常有用。

### 功能
- 使用 AES-256-GCM + RSA-OAEP 加密（与官方降级服务器匹配）
- 需要真实的 **DUID**（来自 *#6776# 的 64 字符 SHA256 字符串）
- 需要 **PrjNum**（5 位项目编号）
- 返回下载 URL、更新日志、版本信息、MD5 值和发布时间

### 依赖
- `requests`
- `cryptography`

Install:
```bash
pip install requests cryptography
```
### 使用`downgrade_query.py`的方法
```bash
python downgrade_query.py <OTA_PREFIX> <PrjNum> <snNum> <DUID> [--debug 0/1]

# 示例
python downgrade_query.py PKX110_11.C 24821 a1b2c3e4 498A44DF1BEC4EB19FBCB3A870FCACB4EC7D424979CC9C517FE7B805A1937746
```

**限制条件**

- `<OTA_PREFIX>`：必须至少包含一个下划线（例如 `PKX110_11.C`）
- `<PrjNum>`：必须是 5 位数字（例如 `24821`）
- `<snNum>`：手机序列号
- `<DUID>`：64 个字符的 SHA256 字符串（通过拨号代码 *#6776# 获取）
- `[--debug 0/1]`：获取官方降级包的数据

**输出示例**
```
Fetch Info:
• Link: https://...
• Changelog: ...
• Published Time: 2025-08-12 14:30:00
• Version: ColorOS 15.0 (Android 15)
• Ota Version: PKX110_11.C.12_...
• MD5: abcdef123456...
```

### 使用 `downgrade_query_old.py`的方法
```bash
python downgrade_query.py <OTA_PREFIX> <PrjNum>

# 示例
python downgrade_query.py PKX110_11.C 24821
```

**限制条件**

- `<OTA_PREFIX>`：必须至少包含一个下划线（例如 `PKX110_11.C`）
- `<PrjNum>`：必须是 5 位数字（例如 `24821`）

**输出示例**
```
Fetch Info:
• Link: https://...
• Changelog: ...
• Published Time: 2025-08-12 14:30:00
• Version: ColorOS 15.0 (Android 15)
• Ota Version: PKX110_11.C.12_...
• MD5: abcdef123456...
```

**注意**：仅适用于支持官方降级的型号/地区。服务器可能会拒绝无效的DUID或项目编号。

## `realme_edl_query.py`

使用realme服务器查询EDL(9008)rom的工具。

 ### 用法

```bash
python realme_edl_query.py <版本号> <区域> <日期>

# 示例
python3 realme_edl_query.py "RMX3888_16.0.3.500(CN01)" CN 202601241320
```

**输出示例**
```
查询 RMX8899_16.0.3.532(CN01)

获取信息：

• 链接：https://rms11.realme.net/sw/RMX8899domestic_11_16.0.3.532CN01_2026013016580190.zip
```

**注意**：您可以从完整的 OTA 版本号中获取日期，即下划线中的第三部分。

 ### 重要说明（2025-2026） 
 - ColorOS16 系统新增严格的反查询限制（2025年10月左右上线），多数机型可通过 `--anti `1 + `taste` 模式 + 基础版本号（如 `11.A`）绕过该限制。 
 - `downloadCheck?` 格式的动态链接有效期通常为**10-30分钟**，获取后请立即使用- `C16_transer.py` 解析并保存最终下载链接。 
 - `opex_query.py`、`sota_query.py`、`iot_query.py` 和 `downgrade_query.py` 目前仅`支持中国地区`。
 - 所有工具每次请求都会重新生成加密密钥与设备 ID，以降低被官方服务器封禁的概率。