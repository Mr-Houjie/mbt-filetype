# mbt-filetype

零依赖的 MoonBit 文件类型识别与内容嗅探库：魔数签名、容器消歧、MIME 归一化，附命令行工具。

`mbt-filetype` 回答一个很具体的问题：**这段字节到底是什么文件？** 它不根据扩展名猜测，只读取内容头部，并给出可解释的证据。

## 特性

- **104 条魔数签名，96 种类型**：图片、文档、归档、音视频、可执行、字体、数据库、科学数据、WASM、数据列存
- **容器消歧**：ZIP → docx / xlsx / pptx / epub / apk / jar / odt / ods / odp / xps；RIFF → wav / avi / webp；ftyp → mp4 / mov / heic / avif / m4a / 3gp；EBML → mkv / webm；IFF → aiff；Ogg → opus；OLE2 → doc / xls / ppt 候选；ASF → wma / wmv 候选
- **不猜原则**：证据不足时返回 `unknown`，歧义时返回候选列表，绝不返回一个错误答案
- **可解释**：输出命中的签名、偏移、字节数与判定理由
- **确定性**：纯函数识别，不访问网络、不依赖时区与 locale
- **边界安全**：所有字节访问都做边界检查，任意输入都不会越界；附带固定种子 fuzz 测试
- **CI 友好**：`--expect` 断言类型，`--scan` 报告扩展名与内容不符的文件

## 安装

```bash
moon add Mr-Houjie/mbt-filetype
```

## 库 API

```moonbit
let detection = @Mr-Houjie/mbt-filetype.detect(bytes)
match detection.file_type {
  Some(file_type) => {
    println(file_type.id)       // "png"
    println(file_type.mime)     // "image/png"
    println(file_type.ext)      // "png"
    println(file_type.category) // Image
    println(detection.reason)   // "PNG signature"
  }
  None => println("unknown")
}
```

## CLI

```bash
# 识别单个文件
moon run cmd/main -- examples/sample.png

# 以 JSON 输出
moon run cmd/main -- --json examples/sample.json

# 显示签名偏移与字节数
moon run cmd/main -- --explain examples/sample.png

# 断言类型：不匹配时退出码为 1
moon run cmd/main -- --expect image/png examples/sample.png

# 递归扫描目录，报告扩展名与内容不符的文件
moon run cmd/main -- --scan examples

# 列出全部已知类型
moon run cmd/main -- --list-types
```

输出示例：

```text
examples/sample.png
  type:       png
  mime:       image/png
  extension:  .png
  category:   image
  confidence: certain
  evidence:   PNG signature
```

```json
{"path":"examples/sample.json","type":"json","mime":"application/json","ext":"json","category":"text","confidence":"probable","offset":0,"bytes":1,"reason":"首个非空白字节是 { 或 [","candidates":[]}
```

## 支持的格式

| 大类 | 类型 |
|---|---|
| 图片 | png, jpeg, gif, bmp, tiff, ico, cur, psd, xcf, webp, avif, heic, jp2, jxl, icns, dds, ktx, ktx2, exr, hdr, pnm |
| 文档 | pdf, postscript, pfa, rtf, djvu, ole2, doc, xls, ppt, epub, docx, xlsx, pptx, odt, ods, odp, xps, pem, pgp, mobi, chm |
| 归档 | zip, apk, jar, gzip, bzip2, xz, zstd, 7z, rar, tar, cab, lz4, cpio, rpm, ar, deb, xar, squashfs, crx, iso, compress |
| 音频 | mp3, flac, ogg, opus, wav, aiff, au, midi, aac, wavpack, ape, amr, m4a, wma |
| 视频 | mp4, mov, mkv, webm, avi, flv, mpeg, ts, 3gp, wmv, asf |
| 可执行 | elf, pe, macho, class, dex, luac, wasm |
| 字体 | ttf, otf, woff, woff2, ttc, pcf, bdf |
| 数据库 | sqlite, parquet, arrow, avro, orc |
| 科学数据 | hdf4, hdf5, netcdf, fits, grib, mat, npy |
| 文本 | json, xml, html, csv, tsv, text |

## 设计原则

1. **不猜**：弱签名只给 `probable`；容器无法消歧时返回 `unknown` 或候选列表
2. **可解释**：每个结果都带 `reason`、`offset`、`matched_len`
3. **确定性**：同一份字节在任何后端得到同一结果，不依赖扩展名、网络或系统状态
4. **边界安全**：先检查长度再做字节比较；`detect` 对任意输入都是全函数

## 一致性语料与测试

识别行为由 `conformance.mbt` 中的 **128 条**「输入 → 期望类型」用例定义，测试与自检共用同一份数据。

```bash
# 标准测试（Linux / macOS）
moon test

# 独立自检入口（Windows 下 moon test 可能受嵌套进程限制）
moon run cmd/verify
```

## CI 集成

```yaml
- name: Check asset types
  run: |
    moon run cmd/main -- --expect image/png public/logo.png
    moon run cmd/main -- --scan public
```

`--scan` 只比较「有扩展名且类型已知」的文件；纯文本类型会跳过，避免把 `.md`、`.txt` 误报为不一致。

## 边界与不做的事

- 只读文件头部（ZIP 衍生格式最多检查前 64 KiB 的条目名），不做深度解析
- OLE2 只返回统一类型与 doc / xls / ppt 候选，不解析复合文档目录
- 不解压压缩包，不递归检查归档内部
- 文本判定是保守启发式，一律标记为 `probable`
- 这不是安全扫描器：不检测恶意构造、不校验文件完整性

## 许可证

MIT
