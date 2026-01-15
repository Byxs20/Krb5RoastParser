# PCAP Kerberos Roasting Extractor

这是一个用于从 PCAP 数据包文件中提取 Kerberos 哈希的 Python 工具。它基于 `tshark` 进行底层解析，能够智能处理字段分隔，并支持从 **AS-REQ**、**AS-REP** 和 **TGS-REP** 数据包中提取用于 Hashcat 破解的哈希值。

## 🔥 主要特性 (Supported Hash Formats)

本工具专为红队和渗透测试人员设计，支持提取以下 Hashcat 兼容格式：

### 1. AS-REQ (Pre-Auth)
用于离线破解用户密码（针对启用预认证的账户）。
- **`$krb5pa$23`** (RC4)
- **`$krb5pa$17`** (AES128-CTS-HMAC-SHA1-96)
- **`$krb5pa$18`** (AES256-CTS-HMAC-SHA1-96)

### 2. AS-REP (AS-REP Roasting)
用于攻击未开启 Kerberos 预认证的用户 (UF_DONT_REQUIRE_PREAUTH)。
- **`$krb5asrep$23`** (RC4)

### 3. TGS-REP (Kerberoasting)
用于请求服务票据并离线破解服务账户密码。
- **`$krb5tgs$23`** (RC4)
- **`$krb5tgs$17`** (AES128)
- **`$krb5tgs$18`** (AES256)

---

## 🛠️ 依赖环境

- Python 3.x
- **Wireshark / Tshark**: 必须安装并添加到系统环境变量 PATH 中。

```bash
# Ubuntu/Debian
sudo apt-get install tshark

# Windows
# 安装 Wireshark 后并确保其路径在 PATH 中
```

## 🚀 使用方法

```bash
python krb5_roasting.py <pcap_file> <mode>
```

### 参数说明
- `<pcap_file>`: 包含 Kerberos 流量的数据包文件路径。
- `<mode>`: 提取模式，支持以下三种：
  - `as_req`: 提取 AS-REQ 预认证哈希。
  - `as_rep`: 提取 AS-REP Roasting 哈希。
  - `tgs_rep`: 提取 TGS-REP (Kerberoasting) 哈希。

### 示例

**1. 提取 Kerberoasting 哈希 (TGS-REP):**
```bash
python krb5_roasting.py capture.pcap tgs_rep > hashes.txt
```

**2. 提取 AS-REP Roasting 哈希 (AS-REP):**
```bash
python krb5_roasting.py capture.pcap as_rep > asrep_hashes.txt
```

**3. 提取预认证数据 (AS-REQ):**
```bash
python krb5_roasting.py capture.pcap as_req > pa_hashes.txt
```

---

## ⚡ Hashcat 模式对照表

提取出的哈希可直接用于 Hashcat，对应模式如下：

| Hash Format Type | Encryption | Hashcat Mode | Attack Type |
| :--- | :--- | :--- | :--- |
| **`$krb5pa$23`** | RC4 | 7500 | AS-REQ Pre-Auth |
| **`$krb5pa$17/18`** | AES128/256 | 19900 / 20000 | AS-REQ Pre-Auth |
| **`$krb5asrep$23`** | RC4 | 18200 | AS-REP Roasting |
| **`$krb5tgs$23`** | RC4 | 13100 | Kerberoasting |
| **`$krb5tgs$17/18`** | AES128/256 | 19600 / 19700 | Kerberoasting (AES) |

## ⚠️ 注意事项

1. **Tshark 版本兼容性**: 脚本内置了“智能回退”机制。如果在较新版本的 Tshark 中字段名称发生变化（例如 `encryptedKDCREPData_cipher` vs `cipher`），脚本会自动尝试旧版字段名。
2. **SPN 格式**: 针对 MSSQL 等服务，脚本会自动处理 SPN 格式，将 `MSSQL,domain.com` 转换为标准的 `MSSQL/domain.com` 格式。
3. **AES AS-REP**: 目前工具会有意跳过非 RC4 (Etype 23) 的 AS-REP 数据包，因为标准的 AS-REP Roasting 通常针对 RC4，且 AES 格式在无预认证攻击场景下的利用较为复杂且 Hashcat 支持有限。
