#!/usr/bin/env python3
"""生成真实编码器产出的语料（不手写魔数）。

用法：
    python tools/make_corpus.py [corpus/]

生成物来自 zlib / bz2 / lzma / tarfile / wave / sqlite3 等真实编码器，
用于 `tools/crosscheck.py` 做跨库一致性对拍。
"""

import bz2
import gzip
import io
import json
import lzma
import os
import sqlite3
import sys
import tarfile
import wave
import zipfile
import zlib


def write(root, name, data):
    path = os.path.join(root, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def png_chunk(kind, payload):
    chunk = kind + payload
    return (
        len(payload).to_bytes(4, "big")
        + chunk
        + zlib.crc32(chunk).to_bytes(4, "big")
    )


def make_png():
    raw = b"\x00" + b"\xff\x00\x00" * 8
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", (8).to_bytes(4, "big") + (8).to_bytes(4, "big") + bytes([8, 2, 0, 0, 0]))
        + png_chunk(b"IDAT", zlib.compress(raw))
        + png_chunk(b"IEND", b"")
    )


def make_wav():
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(8000)
        handle.writeframes(b"\x00\x00" * 800)
    return buffer.getvalue()


def make_zipdocx():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        archive.writestr("_rels/.rels", "<Relationships/>")
        archive.writestr("word/document.xml", "<w:document/>")
    return buffer.getvalue()


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "corpus"
    os.makedirs(root, exist_ok=True)

    text = "id,name,score\n1,alpha,90\n2,beta,85\n"
    write(root, "table.csv", text.encode())
    write(root, "table.tsv", text.replace(",", "\t").encode())
    write(root, "data.json", json.dumps({"a": [1, 2, 3], "b": None}).encode())
    write(root, "page.html", b"<!DOCTYPE html><html><body>hi</body></html>\n")
    write(root, "feed.xml", b'<?xml version="1.0"?><rss/>\n')
    write(root, "notes.md", b"# title\n\nhello\n")
    write(root, "plain.txt", b"just some text\n")

    write(root, "image.png", make_png())
    write(root, "audio.wav", make_wav())
    write(root, "bundle.zip", make_zipdocx())

    write(root, "archive.tar", b"")
    with tarfile.open(os.path.join(root, "archive.tar"), "w") as archive:
        payload = b"hello tar\n"
        info = tarfile.TarInfo("hello.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))

    write(root, "blob.gz", gzip.compress(text.encode()))
    write(root, "blob.bz2", bz2.compress(text.encode()))
    write(root, "blob.xz", lzma.compress(text.encode()))

    db_path = os.path.join(root, "store.sqlite")
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute("create table t(id integer primary key, name text)")
    conn.execute("insert into t(name) values ('alpha')")
    conn.commit()
    conn.close()

    print(f"语料已生成：{root}")
    for name in sorted(os.listdir(root)):
        print(f"  {name:16s} {os.path.getsize(os.path.join(root, name)):>8d} bytes")


if __name__ == "__main__":
    main()
