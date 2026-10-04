"""Windows 密钥提取 — 扫描 Weixin.exe 进程内存

两层扫描策略：
1. Config.Cipher 运行时扫描（微信 4.1.10+）：
   在内存中定位 WCDB Config.Cipher 名称字符串，回溯引用它的
   (ptr, len) pair 与上层节点，解出 XOR 加密的配置 blob，从中提取
   ``x'<enc_key_hex><salt_hex>'`` 字面量并用 HMAC 校验。
   算法思路来自社区工具 TANGandXUE/wcdb-key-tool（独立重写，非逐字拷贝）。
   ⚠ 实验性：本层仅在 macOS 上完成纯逻辑单元测试，未在真实 Windows
   4.1.10+ 环境实机验证。
2. Legacy 明文 ``x'<hex>'`` 内存扫描（4.0.x ~ 4.1.9.x），作为回退保留。

注意：``ctypes.windll`` 延迟到函数内获取，保证模块可在非 Windows
环境 import（用于跨平台单元测试）。
"""

import ctypes
import ctypes.wintypes as wt
import functools
import re
import struct
import subprocess
import time

from .common import (
    collect_db_files,
    cross_verify_keys,
    save_results,
    scan_memory_for_keys,
    verify_enc_key,
)

print = functools.partial(print, flush=True)

MEM_COMMIT = 0x1000
READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}

# ---- Config.Cipher 扫描常量（4.1.10+） ----
WINDOWS_CONFIG_CIPHER_NAME = b"com.Tencent.WCDB.Config.Cipher"  # 长度 30
WINDOWS_CONFIG_XOR_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b450048844c2448488944254048584c24"
)  # 32 字节
WINDOWS_MAX_USER_ADDRESS = 0x0000_8000_0000_0000
WINDOWS_CONFIG_BLOB_MAX = 1024
WINDOWS_CONFIG_LITERAL_RE = re.compile(rb"[xX]'([0-9a-fA-F]{64,192})'")


def _kernel32():
    """延迟获取 kernel32，避免模块 import 时触达 ctypes.windll。"""
    # windll 仅在 Windows 存在；非 Windows 环境 import 本模块时不会执行到此处
    return ctypes.windll.kernel32  # type: ignore[attr-defined]


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


# ---------------------------------------------------------------------------
# 纯逻辑函数（不依赖 Windows API，可跨平台单测）
# ---------------------------------------------------------------------------

def _xor_repeat(data, mask):
    """逐字节 data[i] ^ mask[i % len(mask)]。"""
    mlen = len(mask)
    return bytes(b ^ mask[i % mlen] for i, b in enumerate(data))


def _u64_from(data, offset):
    """小端解析 u64；越界返回 0。"""
    if offset < 0 or offset + 8 > len(data):
        return 0
    return struct.unpack_from("<Q", data, offset)[0]


def _probable_32_byte_key(data):
    """启发式判断 32 字节数据是否像一个随机密钥。"""
    if len(data) != 32:
        return False
    if all(b == 0x00 for b in data) or all(b == 0xFF for b in data):
        return False
    return len(set(data)) >= 15


def _windows_v411_config_key_candidates(blob):
    """从 XOR 加密的 Config.Cipher blob 中提取 (enc_key_hex, embedded_salt) 候选。

    Args:
        blob: 读自内存的加密 blob（<= 1024 字节）

    Returns:
        list[tuple[str, str | None]]: (64 字符 enc_key_hex, 32 字符 salt_hex 或 None)
    """
    if not blob or len(blob) > WINDOWS_CONFIG_BLOB_MAX:
        return []
    decoded = _xor_repeat(blob, WINDOWS_CONFIG_XOR_MASK)
    results = []
    seen = set()
    for m in WINDOWS_CONFIG_LITERAL_RE.finditer(decoded):
        run = m.group(1).decode("ascii")
        starts = [0]
        if len(run) > 96:
            starts.extend(range(0, len(run) - 63, 32))
            starts.append(len(run) - 64)
        for start in dict.fromkeys(starts):
            enc_key_hex = run[start:start + 64]
            try:
                key_bytes = bytes.fromhex(enc_key_hex)
            except ValueError:
                continue
            if not _probable_32_byte_key(key_bytes):
                continue
            embedded_salt = run[start + 64:start + 96]
            if len(embedded_salt) < 32:
                embedded_salt = None
            cand = (enc_key_hex, embedded_salt)
            if cand not in seen:
                seen.add(cand)
                results.append(cand)
    return results


def _iter_windows_region_chunks(regions, read_region, overlap=0):
    """按区域读取内存并拼接上一区域尾部 overlap 字节（处理跨界匹配）。

    Args:
        regions: [(base, size), ...]
        read_region: (base, size) -> bytes | None
        overlap: 拼接到下一区域前缀的字节数

    Yields:
        (chunk_base, chunk_bytes)：chunk_base 为 chunk 起始的绝对地址
    """
    tail = b""
    tail_base = 0
    for base, size in regions:
        data = read_region(base, size)
        if not data:
            tail = b""
            continue
        if tail:
            chunk = tail + data
            chunk_base = tail_base
        else:
            chunk = data
            chunk_base = base
        yield chunk_base, chunk
        if overlap > 0:
            tail = data[-overlap:]
            tail_base = base + size - len(tail)
        else:
            tail = b""


def _find_bytes_in_regions(regions, read_region, needle):
    """在内存区域中搜索 needle，返回所有命中的绝对地址集合。"""
    hits = set()
    if not needle:
        return hits
    for base, chunk in _iter_windows_region_chunks(
            regions, read_region, overlap=len(needle) - 1):
        pos = 0
        while True:
            idx = chunk.find(needle, pos)
            if idx < 0:
                break
            hits.add(base + idx)
            pos = idx + 1
    return hits


# ---------------------------------------------------------------------------
# Config.Cipher 扫描主流程（微信 4.1.10+，实验性，未实机验证）
# ---------------------------------------------------------------------------

def _scan_windows_v411_config_cipher(pid, regions, read_region, read_mem,
                                     db_files, salt_to_dbs, key_map,
                                     remaining_salts, print_fn):
    """运行时 Config.Cipher 扫描层（4.1.10+）。

    思路：定位 "com.Tencent.WCDB.Config.Cipher" 名称字符串 → 找引用它的
    (ptr, 29) pair → 回溯节点取出 config 对象指针 → 解出 XOR 加密 blob →
    提取 x'<hex>' 字面量候选 → HMAC 校验。

    Returns:
        dict: 扫描统计信息
    """
    stats = {
        "needle_occurrences": 0,
        "string_object_refs": 0,
        "node_candidates": 0,
        "config_ptr_candidates": 0,
        "blob_count": 0,
        "candidate_count": 0,
        "verified_candidates": 0,
        "matched_salts": set(),
    }
    print_fn(f"\n[*] PID={pid} 第 1 层: Config.Cipher 运行时扫描 (4.1.10+, 实验性)")

    needle_addresses = _find_bytes_in_regions(
        regions, read_region, WINDOWS_CONFIG_CIPHER_NAME)
    stats["needle_occurrences"] = len(needle_addresses)
    if not needle_addresses:
        print_fn("  [Config.Cipher] 未找到名称字符串，跳过本层")
        return stats
    print_fn(f"  [Config.Cipher] 名称字符串命中 {len(needle_addresses)} 处")

    pair_patterns = [
        struct.pack("<Q", addr) + struct.pack("<Q", len(WINDOWS_CONFIG_CIPHER_NAME))
        for addr in sorted(needle_addresses)
    ]
    pair_re = re.compile(b"|".join(re.escape(p) for p in pair_patterns))
    seen_candidates = set()

    def _try_verify(enc_key_hex, embedded_salt):
        enc_key = bytes.fromhex(enc_key_hex)
        if embedded_salt is not None:
            # 字面量内嵌 salt：只对同 salt 的库验证
            targets = [embedded_salt] if embedded_salt in remaining_salts else []
        else:
            # 无内嵌 salt：对所有剩余 salt 尝试
            targets = list(remaining_salts)
        for salt_hex in targets:
            for rel, path, sz, s, page1 in db_files:
                if s != salt_hex:
                    continue
                if verify_enc_key(enc_key, page1):
                    key_map[salt_hex] = enc_key_hex
                    remaining_salts.discard(salt_hex)
                    stats["verified_candidates"] += 1
                    stats["matched_salts"].add(salt_hex)
                    print_fn(f"\n  [FOUND][Config.Cipher] salt={salt_hex}")
                    print_fn(f"    enc_key={enc_key_hex}")
                    print_fn(f"    PID={pid}")
                    print_fn(f"    数据库: {', '.join(salt_to_dbs[salt_hex])}")
                    return True
                break  # 每个 salt 只需用其第一个库的 page1 校验
        return False

    for chunk_base, chunk in _iter_windows_region_chunks(
            regions, read_region, overlap=0x80):
        for m in pair_re.finditer(chunk):
            stats["string_object_refs"] += 1
            qaddr = chunk_base + m.start()

            node = read_mem(qaddr - 0x10, 0x50)
            if not node or len(node) < 0x40:
                continue
            if _u64_from(node, 0x10) not in needle_addresses:
                continue
            if _u64_from(node, 0x18) != len(WINDOWS_CONFIG_CIPHER_NAME):
                continue
            stats["node_candidates"] += 1

            config_ptr = _u64_from(node, 0x28)
            if not (0x10000 <= config_ptr < WINDOWS_MAX_USER_ADDRESS):
                continue
            stats["config_ptr_candidates"] += 1

            obj = read_mem(config_ptr + 0x88, 0x28)
            if not obj or len(obj) < 0x18:
                continue
            data_ptr = _u64_from(obj, 0x8)
            data_len = _u64_from(obj, 0x10)
            if not (0 < data_len <= WINDOWS_CONFIG_BLOB_MAX):
                continue
            if not (0x10000 <= data_ptr < WINDOWS_MAX_USER_ADDRESS):
                continue
            stats["blob_count"] += 1

            blob = read_mem(data_ptr, data_len)
            if not blob or len(blob) < data_len:
                continue

            for enc_key_hex, embedded_salt in \
                    _windows_v411_config_key_candidates(blob):
                cand = (enc_key_hex, embedded_salt)
                if cand in seen_candidates:
                    continue
                seen_candidates.add(cand)
                stats["candidate_count"] += 1
                _try_verify(enc_key_hex, embedded_salt)

            if not remaining_salts:
                break
        if not remaining_salts:
            break

    print_fn(
        f"  [Config.Cipher] needle={stats['needle_occurrences']} "
        f"pair引用={stats['string_object_refs']} "
        f"节点候选={stats['node_candidates']} "
        f"config对象={stats['config_ptr_candidates']} "
        f"blob={stats['blob_count']} "
        f"密钥候选={stats['candidate_count']} "
        f"验证通过={stats['verified_candidates']} "
        f"匹配salt={len(stats['matched_salts'])}"
    )
    return stats


# ---------------------------------------------------------------------------
# Windows 进程内存访问（仅 Windows 可调用）
# ---------------------------------------------------------------------------

def _get_pids():
    """返回所有 Weixin.exe 进程的 (pid, mem_kb) 列表，按内存降序"""
    r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                       capture_output=True, text=True)
    pids = []
    for line in r.stdout.strip().split('\n'):
        if not line.strip():
            continue
        p = line.strip('"').split('","')
        if len(p) >= 5:
            pid = int(p[1])
            mem = int(p[4].replace(',', '').replace(' K', '').strip() or '0')
            pids.append((pid, mem))
    if not pids:
        raise RuntimeError("Weixin.exe 未运行")
    pids.sort(key=lambda x: x[1], reverse=True)
    for pid, mem in pids:
        print(f"[+] Weixin.exe PID={pid} ({mem // 1024}MB)")
    return pids


def _read_mem(h, addr, sz):
    buf = ctypes.create_string_buffer(sz)
    n = ctypes.c_size_t(0)
    if _kernel32().ReadProcessMemory(h, ctypes.c_uint64(addr), buf, sz, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def _enum_regions(h):
    k32 = _kernel32()
    regs = []
    addr = 0
    mbi = MBI()
    while addr < 0x7FFFFFFFFFFF:
        if k32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        if mbi.State == MEM_COMMIT and mbi.Protect in READABLE and 0 < mbi.RegionSize < 500 * 1024 * 1024:
            regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return regs


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------

def extract_keys(db_dir, output_path, pid=None):
    """提取 Windows 微信数据库密钥。

    Args:
        db_dir: 微信数据库目录
        output_path: all_keys.json 输出路径
        pid: 可选，指定 PID（默认自动检测所有 Weixin.exe）

    Returns:
        dict: salt_hex -> enc_key_hex 映射
    """
    print("=" * 60)
    print("  提取所有微信数据库密钥")
    print("=" * 60)

    db_files, salt_to_dbs = collect_db_files(db_dir)

    print(f"\n找到 {len(db_files)} 个数据库, {len(salt_to_dbs)} 个不同的salt")
    for salt_hex, dbs in sorted(salt_to_dbs.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  salt {salt_hex}: {', '.join(dbs)}")

    pids = _get_pids() if pid is None else [(pid, 0)]

    k32 = _kernel32()
    hex_re = re.compile(b"x'([0-9a-fA-F]{64,192})'")
    key_map = {}
    remaining_salts = set(salt_to_dbs.keys())
    all_hex_matches = 0
    t0 = time.time()

    for pid_val, mem_kb in pids:
        h = k32.OpenProcess(0x0010 | 0x0400, False, pid_val)
        if not h:
            print(f"[WARN] 无法打开进程 PID={pid_val}，跳过")
            continue

        try:
            regions = _enum_regions(h)
            total_bytes = sum(s for _, s in regions)
            total_mb = total_bytes / 1024 / 1024
            print(f"\n[*] 扫描 PID={pid_val} ({total_mb:.0f}MB, {len(regions)} 区域)")

            def read_region(base, size, _h=h):
                return _read_mem(_h, base, size)

            # 第 1 层：Config.Cipher 运行时扫描（4.1.10+）
            _scan_windows_v411_config_cipher(
                pid_val, regions, read_region, _read_mem_bound(h),
                db_files, salt_to_dbs, key_map, remaining_salts, print,
            )

            # 第 2 层：legacy 明文 x'<hex>' 扫描（4.0.x ~ 4.1.9.x）
            if remaining_salts:
                print(f"\n[*] PID={pid_val} 第 2 层: legacy 明文扫描 (4.0.x~4.1.9.x)")
                scanned_bytes = 0
                for reg_idx, (base, size) in enumerate(regions):
                    data = _read_mem(h, base, size)
                    scanned_bytes += size
                    if not data:
                        continue

                    all_hex_matches += scan_memory_for_keys(
                        data, hex_re, db_files, salt_to_dbs,
                        key_map, remaining_salts, base, pid_val, print,
                    )

                    if (reg_idx + 1) % 200 == 0:
                        elapsed = time.time() - t0
                        progress = scanned_bytes / total_bytes * 100 if total_bytes else 100
                        print(
                            f"  [{progress:.1f}%] {len(key_map)}/{len(salt_to_dbs)} salts matched, "
                            f"{all_hex_matches} hex patterns, {elapsed:.1f}s"
                        )

                    if not remaining_salts:
                        break
        finally:
            k32.CloseHandle(h)

        if not remaining_salts:
            print(f"\n[+] 所有密钥已找到，跳过剩余进程")
            break

    elapsed = time.time() - t0
    print(f"\n扫描完成: {elapsed:.1f}s, {len(pids)} 个进程, {all_hex_matches} hex模式")

    cross_verify_keys(db_files, salt_to_dbs, key_map, print)
    return save_results(db_files, salt_to_dbs, key_map, output_path, print)


def _read_mem_bound(h):
    """返回绑定进程句柄的 read_mem(addr, size) 闭包。"""
    def _read(addr, size):
        return _read_mem(h, addr, size)
    return _read
