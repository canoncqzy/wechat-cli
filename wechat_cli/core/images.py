r"""微信 4.x 图片 .dat 解码 — V1/V2 容器格式

V2 容器结构（已实证验证）:
  [0:6]   魔数 V2 = 07 08 56 32 08 07（V1 = 07 08 56 31 08 07）
  [6:10]  aes_size（小端 u32，通常 1024）
  [10:14] xor_size（小端 u32，上限 1048576）
  [14]    flag
  之后依次为:
    1. AES 段 data[15 : 15+aligned]，aligned = ceil(aes_size/16)*16，AES-128-ECB 解密
    2. 分隔 16 字节（跳过）
    3. 明文中段 rem[:len(rem)-x]（原样）
    4. XOR 尾段 rem[len(rem)-x:]，每字节 XOR xor_key
  输出 = AES 明文[:aes_size] + 明文中段 + XOR 尾段

密钥派生（离线）:
  code 来自 kvcomm 目录下 *.statistic 文件名（正则 (?:key_)?(\d+)_）
  aes_key = md5(f"{code}{clean_wxid}").hexdigest()[:16] 的 ASCII 字节
  xor_key = code & 0xFF

kvcomm 目录位置（平台相关）:
  macOS  : ~/Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data/**/kvcomm/
  Windows: %APPDATA%\\Tencent\\xwechat\\net\\kvcomm\\
           %APPDATA%\\Tencent\\xwechat\\ilink\\kvcomm\\
           %APPDATA%\\Tencent\\WeChat\\kvcomm\\（旧版）
  注：Windows 路径来自社区资料，未经实机验证，可能随微信版本变化。
  显式覆盖（优先级从高到低）:
    1. 环境变量 WECHAT_CLI_KVCOMM_DIR（可用 os.pathsep 分隔多个路径，设置后完全覆盖默认）
    2. config.json 中的 kvcomm_dir 项
    3. 平台默认路径
"""

import glob as glob_mod
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from Crypto.Cipher import AES

from .config import STATE_DIR, load_config

V2_MAGIC = b"\x07\x08V2\x08\x07"
V1_MAGIC = b"\x07\x08V1\x08\x07"

_KVCOMM_ROOT = os.path.expanduser(
    "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data"
)
_CODE_RE = re.compile(r"(?:key_)?(\d+)_")
_KEY_CACHE_FILE = os.path.join(STATE_DIR, "image_key.json")


def _platform_kvcomm_roots() -> "list[str]":
    """平台默认的 kvcomm 候选根（按优先级顺序）。"""
    if sys.platform == "darwin":
        return [_KVCOMM_ROOT]
    if sys.platform == "win32":
        # 社区资料路径，未实机验证，可能随版本变化
        appdata = os.environ.get("APPDATA") or os.path.expanduser("~/AppData/Roaming")
        return [
            os.path.join(appdata, "Tencent", "xwechat", "net", "kvcomm"),
            os.path.join(appdata, "Tencent", "xwechat", "ilink", "kvcomm"),
            os.path.join(appdata, "Tencent", "WeChat", "kvcomm"),
        ]
    return []


def _config_kvcomm_dir() -> "str | None":
    """config.json 中的 kvcomm_dir 配置项；读取失败返回 None。"""
    try:
        cfg = load_config()
    except Exception:
        return None
    d = cfg.get("kvcomm_dir")
    return d if isinstance(d, str) and d else None


def _kvcomm_roots() -> "list[str]":
    """解析全部 kvcomm 候选根。

    环境变量 WECHAT_CLI_KVCOMM_DIR（os.pathsep 分隔多个）设置时完全覆盖默认；
    否则依次取 config kvcomm_dir + 平台默认路径，去重保序。
    """
    env = os.environ.get("WECHAT_CLI_KVCOMM_DIR", "").strip()
    if env:
        return [p for p in env.split(os.pathsep) if p]
    roots = []
    cfg_dir = _config_kvcomm_dir()
    if cfg_dir:
        roots.append(cfg_dir)
    roots.extend(_platform_kvcomm_roots())
    seen = set()
    return [r for r in roots if not (r in seen or seen.add(r))]

# 图片魔数 → 扩展名
_JPG_MAGIC = b"\xff\xd8\xff"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
WXGF_MAGIC = b"wxgf"
_HEVC_START_CODE = b"\x00\x00\x00\x01"

# ffmpeg 路径（模块级可配置，测试可覆盖；也可用环境变量 WECHAT_CLI_FFMPEG 指定）
FFMPEG = os.environ.get("WECHAT_CLI_FFMPEG") or shutil.which("ffmpeg")


def clean_wxid(wxid: str) -> str:
    """去掉 wxid 目录名的实例后缀。

    wxid_vpq9sk7xsqvf21_6625 -> wxid_vpq9sk7xsqvf21
    """
    if wxid.startswith("wxid_"):
        parts = wxid.split("_")
        if len(parts) >= 3:
            return "_".join(parts[:2])
    return wxid


def derive_keys(code: int, wxid: str) -> "tuple[bytes, int]":
    """由候选 code 与 wxid（已 clean）派生 (aes_key, xor_key)。"""
    aes_key = hashlib.md5(f"{code}{wxid}".encode()).hexdigest()[:16].encode()
    xor_key = code & 0xFF
    return aes_key, xor_key


def find_candidate_codes() -> "list[int]":
    """扫描各候选根下的 *.statistic 文件名，提取候选 code。

    根目录本身名为 kvcomm 时直接取其中 *.statistic；
    否则递归搜索并仅保留路径中含 kvcomm 的项。
    """
    codes = set()
    for root in _kvcomm_roots():
        if not os.path.isdir(root):
            continue
        if os.path.basename(os.path.normpath(root)) == "kvcomm":
            names = [os.path.basename(p)
                     for p in glob_mod.glob(os.path.join(root, "*.statistic"))]
        else:
            names = [p.name for p in Path(root).rglob("*.statistic")
                     if "kvcomm" in p.parts]
        for name in names:
            m = _CODE_RE.search(name)
            if m:
                codes.add(int(m.group(1)))
    return sorted(codes)


def detect_image_ext(data: bytes) -> "str | None":
    """按魔数判定图片类型，返回扩展名；无法识别返回 None。"""
    if data[:3] == _JPG_MAGIC:
        return "jpg"
    if data[:8] == _PNG_MAGIC:
        return "png"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:4] == WXGF_MAGIC:
        return "wxgf"
    return None


def decode_dat(data: bytes, aes_key: bytes, xor_key: int) -> "bytes | None":
    """解码 V1/V2 .dat 内容，返回图片明文；失败返回 None。

    xor_size == 0 的文件是未下载完的残片，返回 None。
    """
    if len(data) < 15 or data[:6] not in (V2_MAGIC, V1_MAGIC):
        return None
    aes_size = int.from_bytes(data[6:10], "little")
    xor_size = int.from_bytes(data[10:14], "little")
    if xor_size == 0:
        return None
    aligned = ((aes_size + 15) // 16) * 16
    aes_seg = data[15:15 + aligned]
    if len(aes_seg) < aligned:
        return None
    plain_aes = AES.new(aes_key, AES.MODE_ECB).decrypt(aes_seg)[:aes_size]
    rem = data[15 + aligned + 16:]
    x = min(xor_size, len(rem))
    mid = rem[:len(rem) - x]
    tail = bytes(b ^ xor_key for b in rem[len(rem) - x:])
    return plain_aes + mid + tail


def _wxid_dir_name(db_dir: str) -> str:
    return os.path.basename(os.path.dirname(os.path.normpath(db_dir)))


def _attach_root(db_dir: str) -> str:
    return os.path.join(os.path.dirname(os.path.normpath(db_dir)), "msg", "attach")


def _find_probe_dat(db_dir: str) -> "str | None":
    """在 attach 目录下找一个已完成（xor_size>0）的 .dat 用于试解码。"""
    root = _attach_root(db_dir)
    if not os.path.isdir(root):
        return None
    for sub in sorted(os.listdir(root)):
        pattern = os.path.join(root, sub, "*", "Img", "*.dat")
        for dat in sorted(glob_mod.glob(pattern)):
            if dat.endswith("_h.dat"):
                continue
            try:
                with open(dat, "rb") as f:
                    header = f.read(15)
            except OSError:
                continue
            if len(header) == 15 and header[:6] in (V2_MAGIC, V1_MAGIC):
                if int.from_bytes(header[10:14], "little") > 0:
                    return dat
    return None


def _try_keys_on(dat_path: str, aes_key: bytes, xor_key: int) -> bool:
    """用候选密钥试解码并检查是否得到图片魔数。"""
    try:
        with open(dat_path, "rb") as f:
            data = f.read()
    except OSError:
        return False
    plain = decode_dat(data, aes_key, xor_key)
    return plain is not None and detect_image_ext(plain) is not None


def _load_key_cache() -> dict:
    try:
        with open(_KEY_CACHE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_key_cache(cache: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(_KEY_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)


def resolve_image_keys(db_dir: str) -> "tuple[bytes, int] | None":
    """解析当前账号的图片解密密钥。

    优先读 ~/.wechat-cli/image_key.json 缓存并验证；失效则遍历候选 code
    试解码一个已完成 .dat，命中后写缓存。全部失败返回 None。
    """
    wxid_dir = _wxid_dir_name(db_dir)
    wxid = clean_wxid(wxid_dir)
    probe = _find_probe_dat(db_dir)
    if not probe:
        return None

    cache = _load_key_cache()
    entry = cache.get(wxid_dir)
    if entry:
        try:
            aes_key = bytes.fromhex(entry["aes_key"])
            xor_key = int(entry["xor_key"])
        except (KeyError, ValueError):
            aes_key, xor_key = b"", -1
        if aes_key and xor_key >= 0 and _try_keys_on(probe, aes_key, xor_key):
            return aes_key, xor_key

    for code in find_candidate_codes():
        aes_key, xor_key = derive_keys(code, wxid)
        if _try_keys_on(probe, aes_key, xor_key):
            cache[wxid_dir] = {
                "code": code,
                "aes_key": aes_key.hex(),
                "xor_key": xor_key,
            }
            _save_key_cache(cache)
            return aes_key, xor_key
    return None


def iter_chat_dat_files(db_dir: str, chat_username: str) -> "list[str]":
    """列出指定聊天 attach 目录下所有图片 .dat（保留 _t.dat 缩略图，排除 _h.dat）。"""
    h = hashlib.md5(chat_username.encode()).hexdigest()
    chat_attach = os.path.join(_attach_root(db_dir), h)
    if not os.path.isdir(chat_attach):
        return []
    files = glob_mod.glob(os.path.join(chat_attach, "*", "Img", "*.dat"))
    return sorted(f for f in files if not f.endswith("_h.dat"))


def wxgf_hevc_offset(data: bytes) -> "int | None":
    """返回 wxgf 中 HEVC 裸流的起始下标（magic 之后第一个 00 00 00 01 起始码）。

    实测本机样本均为 32。找不到或不是 wxgf 返回 None。
    """
    if not data.startswith(WXGF_MAGIC):
        return None
    idx = data.find(_HEVC_START_CODE, len(WXGF_MAGIC))
    return idx if idx != -1 else None


def decode_wxgf(data: bytes) -> "bytes | None":
    """把 wxgf（微信私有格式，内嵌 HEVC 单帧）转成 PNG 字节。

    通过管道调用 ffmpeg：stdin 喂裸 HEVC 流，stdout 取 PNG。
    ffmpeg 不存在或转换失败返回 None。
    """
    off = wxgf_hevc_offset(data)
    if off is None or not FFMPEG:
        return None
    try:
        proc = subprocess.run(
            [FFMPEG, "-hide_banner", "-loglevel", "error",
             "-f", "hevc", "-i", "pipe:0",
             "-frames:v", "1", "-f", "image2pipe", "-vcodec", "png", "pipe:1"],
            input=data[off:], capture_output=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not proc.stdout.startswith(_PNG_MAGIC):
        return None
    return proc.stdout


def decode_dat_file(dat_path: str, out_dir: str, aes_key: bytes, xor_key: int,
                    keep_wxgf: bool = False) -> "tuple[str, str, str | None] | None":
    """解码单个 .dat 到 out_dir。

    wxgf 结果默认自动经 ffmpeg 转成 PNG（keep_wxgf=True 时保留原样）。
    返回 (输出路径, 最终类型, converted_from)；converted_from 非 None 表示
    由该格式转换而来（如 "wxgf"）。失败返回 None。
    """
    try:
        with open(dat_path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    plain = decode_dat(data, aes_key, xor_key)
    if plain is None:
        return None
    ext = detect_image_ext(plain) or "bin"
    converted_from = None
    payload = plain
    if ext == "wxgf" and not keep_wxgf:
        png = decode_wxgf(plain)
        if png is not None:
            payload, ext, converted_from = png, "png", "wxgf"
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(dat_path))[0]
    out_path = os.path.join(out_dir, f"{stem}.{ext}")
    with open(out_path, "wb") as f:
        f.write(payload)
    return out_path, ext, converted_from


def dat_xor_size(dat_path: str) -> "int | None":
    """读取 .dat 头部的 xor_size；无法解析返回 None。"""
    try:
        with open(dat_path, "rb") as f:
            header = f.read(15)
    except OSError:
        return None
    if len(header) == 15 and header[:6] in (V2_MAGIC, V1_MAGIC):
        return int.from_bytes(header[10:14], "little")
    return None
