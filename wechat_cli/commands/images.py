"""images 命令 — 解码微信 4.x 加密图片 .dat 为可查看的 jpg/png"""

import os
import re
import subprocess
import sys

import click

from ..core import images as images_core
from ..core.images import (
    dat_xor_size,
    decode_dat_file,
    iter_chat_dat_files,
    resolve_image_keys,
)
from ..core.messages import resolve_chat_context
from ..output.formatter import output

_SAFE_NAME_RE = re.compile(r'[\\/:*?"<>|\s]+')


def _safe_dir_name(name: str) -> str:
    """把显示名转成安全的目录名。"""
    safe = _SAFE_NAME_RE.sub("_", name).strip("._")
    return safe or "unknown"


@click.command("images")
@click.argument("chat_name")
@click.option("--limit", default=None, type=int, help="最多解码的图片数量（默认全部）")
@click.option("--out", "out_dir", default=None, help="输出目录（默认 ~/.wechat-cli/decoded_images）")
@click.option("--open", "open_dir", is_flag=True, help="完成后用 Finder 打开输出目录 (macOS)")
@click.option("--keep-wxgf", is_flag=True, help="保留原始 .wxgf，不转换为 PNG")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "text"]), help="输出格式")
@click.pass_context
def images(ctx, chat_name, limit, out_dir, open_dir, keep_wxgf, fmt):
    """解码指定聊天的加密图片 .dat 为可查看的图片

    \b
    示例:
      wechat-cli images "文件传输助手"                 # 解码全部图片
      wechat-cli images "AI交流群" --limit 20         # 只解码前 20 张
      wechat-cli images "张三" --open                 # 解码并打开目录
      wechat-cli images "张三" --keep-wxgf            # 保留原始 .wxgf 不转换
      wechat-cli images "张三" --format text          # 纯文本输出
    """
    app = ctx.obj

    if limit is not None and limit <= 0:
        click.echo("错误: limit 必须大于 0", err=True)
        ctx.exit(2)

    chat_ctx = resolve_chat_context(chat_name, app.msg_db_keys, app.cache, app.decrypted_dir)
    if not chat_ctx:
        click.echo(f"找不到聊天对象: {chat_name}", err=True)
        ctx.exit(1)

    keys = resolve_image_keys(app.db_dir)
    if not keys:
        click.echo("无法解析图片解密密钥（未找到可用 code 或无已完成图片可试解码）", err=True)
        ctx.exit(1)
    aes_key, xor_key = keys

    base_out = out_dir or app.cfg.get("decoded_image_dir")
    chat_out_dir = os.path.join(base_out, _safe_dir_name(chat_ctx["display_name"]))

    dat_files = iter_chat_dat_files(app.db_dir, chat_ctx["username"])
    if not dat_files:
        click.echo(f"{chat_ctx['display_name']} 没有找到图片 .dat 文件", err=True)
        ctx.exit(1)

    total = len(dat_files)
    targets = dat_files[:limit] if limit else dat_files

    if not keep_wxgf and not images_core.FFMPEG:
        click.echo("提示: 未找到 ffmpeg，wxgf 全尺寸图将保留原始格式。"
                   "安装后可自动转 PNG: brew install ffmpeg", err=True)
    if limit is None and total > 50:
        click.echo(f"提示: 共 {total} 个文件，wxgf 转换每张需启动一次 ffmpeg，"
                   "可用 --limit 控制数量", err=True)

    decoded = []
    skipped = 0
    failed = 0
    wxgf_fallback = 0  # 转换失败保留 .wxgf 的数量
    for dat_path in targets:
        xs = dat_xor_size(dat_path)
        if xs == 0:
            skipped += 1  # 未下载完的残片
            continue
        result = decode_dat_file(dat_path, chat_out_dir, aes_key, xor_key,
                                 keep_wxgf=keep_wxgf)
        if not result:
            failed += 1
            continue
        out_path, img_type, converted_from = result
        if converted_from is None and img_type == "wxgf" and not keep_wxgf:
            wxgf_fallback += 1
        decoded.append({
            "src": dat_path,
            "path": out_path,
            "type": img_type,
            "converted_from": converted_from,
            "ok": True,
        })

    if open_dir and sys.platform == "darwin":
        os.makedirs(chat_out_dir, exist_ok=True)
        subprocess.Popen(["open", chat_out_dir])

    result = {
        "chat": chat_ctx["display_name"],
        "username": chat_ctx["username"],
        "out_dir": chat_out_dir,
        "total": total,
        "decoded": len(decoded),
        "skipped": skipped,
        "failed": failed or None,
        "wxgf_fallback": wxgf_fallback or None,
        "images": decoded,
    }

    if fmt == "json":
        output(result, "json")
    else:
        lines = [
            f"{result['chat']} 的图片解码结果:",
            f"输出目录: {chat_out_dir}",
            f"共找到 {total} 个 .dat，成功解码 {len(decoded)} 张，"
            f"跳过未完成 {skipped} 个" + (f"，失败 {failed} 个" if failed else "")
            + (f"，{wxgf_fallback} 张 wxgf 转换失败已保留原格式" if wxgf_fallback else ""),
            "",
        ]
        for img in decoded:
            line = img["path"]
            if img["converted_from"]:
                line += f"  (由 {img['converted_from']} 转换)"
            lines.append(line)
        output("\n".join(lines), "text")
