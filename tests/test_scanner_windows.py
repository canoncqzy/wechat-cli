"""scanner_windows 纯逻辑单元测试（不依赖 Windows API，macOS/Linux 可运行）。

运行：
    .venv/bin/python -m pytest tests/ -q
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wechat_cli.keys import scanner_windows as sw  # noqa: E402


def _make_blob(plaintext: bytes) -> bytes:
    """用 XOR MASK 把明文构造成加密 blob（模拟内存中的 Config.Cipher 数据）。"""
    return sw._xor_repeat(plaintext, sw.WINDOWS_CONFIG_XOR_MASK)


# 32 字节、>=15 个不同字节值的合法密钥
KEY_BYTES = bytes(range(32))
KEY_HEX = KEY_BYTES.hex()
SALT_HEX = (b"\x3a" * 16).hex()


def test_xor_repeat_known_vector():
    assert sw._xor_repeat(b"\x01\x02\x03", b"\x10\x20") == b"\x11\x22\x13"
    # 与 MASK 对拍：异或两次还原
    data = b"hello wcdb cipher blob"
    assert sw._xor_repeat(sw._xor_repeat(data, sw.WINDOWS_CONFIG_XOR_MASK),
                          sw.WINDOWS_CONFIG_XOR_MASK) == data


def test_u64_from():
    data = struct.pack("<Q", 0x1122334455667788) + b"xx"
    assert sw._u64_from(data, 0) == 0x1122334455667788
    # 越界返回 0
    assert sw._u64_from(data, 3) == 0
    assert sw._u64_from(b"", 0) == 0
    assert sw._u64_from(data, -1) == 0


def test_probable_32_byte_key():
    assert sw._probable_32_byte_key(KEY_BYTES)
    assert not sw._probable_32_byte_key(b"\x00" * 32)  # 全 0
    assert not sw._probable_32_byte_key(b"\xff" * 32)  # 全 ff
    assert not sw._probable_32_byte_key(b"\xab" * 32)  # 低熵
    assert not sw._probable_32_byte_key(KEY_BYTES[:31])  # 长度不足


def test_config_key_candidates_basic():
    plaintext = b"x'" + KEY_HEX.encode() + SALT_HEX.encode() + b"'"
    blob = _make_blob(plaintext)
    candidates = sw._windows_v411_config_key_candidates(blob)
    assert (KEY_HEX, SALT_HEX) in candidates


def test_config_key_candidates_uppercase_x():
    plaintext = b"X'" + KEY_HEX.encode() + SALT_HEX.encode() + b"'"
    blob = _make_blob(plaintext)
    candidates = sw._windows_v411_config_key_candidates(blob)
    assert (KEY_HEX, SALT_HEX) in candidates


def test_config_key_candidates_key_only():
    # 仅 64 hex（无 salt）→ embedded_salt 为 None
    plaintext = b"x'" + KEY_HEX.encode() + b"'"
    blob = _make_blob(plaintext)
    candidates = sw._windows_v411_config_key_candidates(blob)
    assert (KEY_HEX, None) in candidates


def test_config_key_candidates_rejects_low_entropy():
    zero_key = "00" * 32
    plaintext = b"x'" + zero_key.encode() + SALT_HEX.encode() + b"'"
    blob = _make_blob(plaintext)
    candidates = sw._windows_v411_config_key_candidates(blob)
    assert all(c[0] != zero_key for c in candidates)


def test_config_key_candidates_long_hex_window():
    # 长 hex 串（前缀 64 hex 噪声 + key + salt），走滑动窗口路径
    noise = "cd" * 32  # 64 hex 噪声（低熵，会被拒绝）
    run = noise + KEY_HEX + SALT_HEX
    plaintext = b"x'" + run.encode() + b"'"
    blob = _make_blob(plaintext)
    candidates = sw._windows_v411_config_key_candidates(blob)
    assert (KEY_HEX, SALT_HEX) in candidates


def test_config_key_candidates_blob_limits():
    assert sw._windows_v411_config_key_candidates(b"") == []
    assert sw._windows_v411_config_key_candidates(b"\x00" * 1025) == []


def test_find_bytes_in_regions_cross_chunk():
    backing = bytearray(4096)
    needle = sw.WINDOWS_CONFIG_CIPHER_NAME
    # needle 跨越两个区域的边界（区域在 128 处切分）
    offset = 100
    backing[offset:offset + len(needle)] = needle

    regions = [(0, 128), (128, len(backing) - 128)]

    def read_region(base, size):
        return bytes(backing[base:base + size])

    hits = sw._find_bytes_in_regions(regions, read_region, needle)
    assert hits == {offset}


def test_find_bytes_in_regions_multiple_hits():
    backing = bytearray(2048)
    needle = b"NEEDLE!"
    backing[10:17] = needle
    backing[1000:1007] = needle

    regions = [(0, 2048)]

    def read_region(base, size):
        return bytes(backing[base:base + size])

    hits = sw._find_bytes_in_regions(regions, read_region, needle)
    assert hits == {10, 1000}


def test_module_import_without_windll():
    # 在非 Windows 上 import 成功且模块级未触达 windll
    assert not hasattr(sw, "kernel32")
    assert sw.WINDOWS_CONFIG_CIPHER_NAME == b"com.Tencent.WCDB.Config.Cipher"
    assert len(sw.WINDOWS_CONFIG_XOR_MASK) == 32
