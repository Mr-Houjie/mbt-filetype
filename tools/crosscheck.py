#!/usr/bin/env python3
"""跨库一致性对拍：mbt-filetype vs libmagic / python-magic。

用法：
    python tools/crosscheck.py corpus/ [--limit N] [--json report.json]

语料目录里放真实文件（每种格式 1~3 个即可）。脚本会：
1. 批量调用 `moon run cmd/main -- --json <files...>` 拿到本库结果；
2. 用 python-magic（或系统 `file --mime-type`）拿到参照结果；
3. 输出一致率与全部分歧清单。

分歧不是失败，而是下一轮规则修正的输入；把归因写进报告即可。
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

# libmagic 与 IANA 注册表在少数类型上的命名差异，同一组内视为等价
MIME_GROUPS = [
    {"image/x-icon", "image/vnd.microsoft.icon"},
    {"audio/wav", "audio/x-wav", "audio/vnd.wave"},
    {"application/zip", "application/x-zip-compressed"},
    {"application/vnd.rar", "application/x-rar"},
    {"application/gzip", "application/x-gzip"},
    {"application/vnd.sqlite3", "application/x-sqlite3"},
    {"application/xml", "text/xml"},
    {"application/rtf", "text/rtf"},
    {"audio/midi", "audio/x-midi"},
    {"application/x-bzip2", "application/bzip2"},
    {"application/vnd.ms-cab-compressed", "application/x-cab"},
]

MIME_EQUIV = {}
for _group in MIME_GROUPS:
    for _mime in _group:
        MIME_EQUIV[_mime] = _group - {_mime}


def collect(root, limit):
    paths = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in sorted(filenames):
            paths.append(os.path.join(dirpath, name))
            if limit and len(paths) >= limit:
                return paths
    return paths


def our_results(paths, chunk=100):
    """调用本库 CLI，返回 {path: detection}。"""
    results = {}
    for start in range(0, len(paths), chunk):
        batch = paths[start : start + chunk]
        cmd = ["moon", "run", "cmd/main", "--", "--json"] + batch
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode not in (0, 1):
            sys.exit("moon run 失败：\n" + proc.stderr[-2000:])
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            results[item.get("path", "")] = item
    return results


def reference_mime():
    """返回 f(path) -> mime，优先 python-magic，其次系统 file。"""
    try:
        import magic  # type: ignore

        return lambda path: magic.from_file(path, mime=True), "python-magic"
    except Exception:
        pass
    if shutil.which("file"):
        def via_file(path):
            out = subprocess.run(
                ["file", "--mime-type", "-b", path], capture_output=True, text=True
            )
            return out.stdout.strip()
        return via_file, "file --mime-type"
    sys.exit(
        "未找到参照实现。请安装其一的任意一个：\n"
        "  pip install python-magic-bin   (Windows)\n"
        "  pip install python-magic       (Linux/macOS)\n"
        "或安装系统 `file` 命令。"
    )


def equivalent(ours, theirs):
    if ours == theirs:
        return True
    return theirs in MIME_EQUIV.get(ours, set()) or ours in MIME_EQUIV.get(theirs, set())


def relation(item, their_mime):
    """判断本库结果与参照结果的关系。

    - exact / alias：判定一致
    - finer：参照只能给出 text/plain 或 application/octet-stream，
             而本库给出了更具体的类型（不算分歧，但要列出来复核）
    - conflict：两边都给出了具体类型且不一致
    """
    ours = item.get("mime", "")
    if ours == their_mime:
        return "exact"
    if equivalent(ours, their_mime):
        return "alias"
    if their_mime == "text/plain" and item.get("category") == "text":
        return "finer"
    if their_mime == "application/octet-stream" and ours:
        return "finer"
    return "conflict"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--json", default="")
    args = parser.parse_args()

    if not os.path.isdir(args.corpus):
        sys.exit(f"目录不存在：{args.corpus}")

    paths = collect(args.corpus, args.limit)
    if not paths:
        sys.exit("语料目录为空")

    ref, ref_name = reference_mime()
    ours = our_results(paths)

    agree, finer, disagree, missing = [], [], [], []
    for path in paths:
        item = ours.get(path)
        if item is None:
            missing.append(path)
            continue
        their_mime = ref(path) or ""
        kind = relation(item, their_mime)
        if kind in ("exact", "alias"):
            agree.append(path)
        elif kind == "finer":
            finer.append(
                {
                    "path": path,
                    "ours": item.get("mime", ""),
                    "ours_type": item.get("type", ""),
                    "confidence": item.get("confidence", ""),
                    "reference": their_mime,
                }
            )
        else:
            disagree.append(
                {
                    "path": path,
                    "ours": item.get("mime", ""),
                    "ours_type": item.get("type", ""),
                    "confidence": item.get("confidence", ""),
                    "score": item.get("score", 0),
                    "reference": their_mime,
                }
            )

    total = len(paths)
    rate = 100.0 * len(agree) / total if total else 0.0
    covered = 100.0 * (len(agree) + len(finer)) / total if total else 0.0

    print(f"参照实现：{ref_name}")
    print(f"语料文件：{total}")
    print(
        f"完全一致：{len(agree)}  本库更具体：{len(finer)}  "
        f"真分歧：{len(disagree)}  未取到本库结果：{len(missing)}"
    )
    print(f"一致率：{rate:.2f}%   一致 + 更具体：{covered:.2f}%\n")

    if finer:
        print("本库更具体（参照只给出 text/plain 或 octet-stream）：")
        for row in finer:
            print(f"  {row['path']}  本库: {row['ours']}  参照: {row['reference']}")
        print("")

    if disagree:
        print("真分歧（逐条归因后再决定是否改规则）：")
        for row in disagree:
            print(
                f"  {row['path']}\n"
                f"    本库: {row['ours']} ({row['ours_type']}, {row['confidence']}, {row['score']}/100)\n"
                f"    参照: {row['reference']}"
            )
    if missing:
        print("未取到本库结果：")
        for path in missing:
            print(f"  {path}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "reference": ref_name,
                    "total": total,
                    "agreement_rate": round(rate, 2),
                    "covered_rate": round(covered, 2),
                    "finer": finer,
                    "disagreements": disagree,
                    "missing": missing,
                },
                handle,
                ensure_ascii=False,
                indent=2,
            )
        print(f"\n报告已写入 {args.json}")

    return 0 if not disagree else 1


if __name__ == "__main__":
    sys.exit(main())
