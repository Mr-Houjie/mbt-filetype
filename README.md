# mbt-filetype

零依赖的 MoonBit 文件类型识别与内容嗅探引擎：结构解析、证据链判定、可扩展规则，附命令行工具。

`mbt-filetype` 回答一个很具体的问题：**这段字节到底是什么文件？** 它不根据扩展名猜测，
而是按格式规范解析字节结构，并给出可核对、可加权的证据链。

## 特性

- **基于结构的识别，而不是字符串搜索**：ZIP 走 EOCD → 中央目录 → 条目名；OLE2 走 FAT → 目录扇区 → 流名；ISO-BMFF 走 box 树 → mdia/hdlr；RIFF 遍历 chunk；EBML 解 vint 取 DocType；tar 校验 header checksum；PE 校验 COFF/Optional Header
- **证据链 + 派生评分**：每条证据带种类、偏移、权重；置信度由总分推导，不是人工标注的标签
- **可扩展规则**：`Registry` + `Rule` + `Matcher`，调用方可以注册自己的签名与检测器，与内置规则走同一套流程
- **不猜原则**：结构校验不通过就降级或返回 `unknown`，歧义时返回候选列表
- **确定性**：纯函数识别，不访问网络、不依赖时区与 locale
- **边界安全**：所有字节访问都先检查长度，任意输入都不会越界；附带固定种子 fuzz
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
    println(file_type.id)       // "docx"
    println(file_type.mime)     // "application/vnd.openxmlformats-officedocument..."
    println(detection.score)    // 100
    for item in detection.evidence {
      println("\{item.kind} +\{item.weight}: \{item.label}")
    }
  }
  None => println("unknown")
}
```

## 置信度如何得出

评分是证据的累加，阈值是公开契约（`confidence_of_score`）：

| 证据类型 | 权重 | 例子 |
|---|---|---|
| 强魔数 | 90 | `PK\x03\x04`、`%PDF-` |
| 弱魔数 | 20 | `BM`、`MZ`、`P4` |
| 结构验证 | 40 ~ 70 | 中央目录解析成功、OLE2 目录流命中、PE 头校验通过 |
| 文本启发式 | 30 | JSON/CSV 形状 |

- 总分 ≥ 90 → `certain`，≥ 20 → `probable`，否则 `unknown`
- 所以「`BM` 开头的文本」只有 20 分且被 DIB header 校验拦下，会回落到 `text`；
  「结构完整的 docx」是 90 + 40 分，判定为 `certain`

`--explain` 会打印逐条证据：

```text
examples/sample.png
  type:       png
  mime:       image/png
  extension:  .png
  category:   image
  confidence: certain (90/100)
  evidence:   PNG signature
  offset:     0
  bytes:      8
    [1] magic +90 @0: PNG signature
```

## 扩展：自定义规则与检测器

```moonbit
let registry = @Mr-Houjie/mbt-filetype.Registry::new()

// 声明式规则：支持固定偏移、尾部偏移、位掩码、ASCII、与/或组合
registry.add_rule(
  @Mr-Houjie/mbt-filetype.Rule::new(
    "myfmt", "application/x-myfmt", "myfmt", @Mr-Houjie/mbt-filetype.Other,
    "MYFMT v1 魔数", 90,
    @Mr-Houjie/mbt-filetype.Matcher::all([
      @Mr-Houjie/mbt-filetype.Matcher::magic_at(0, b"MYFMT"),
      @Mr-Houjie/mbt-filetype.Matcher::masked_at(5, b"\x01\x00", b"\xff\x00"),
    ]),
  ),
)

// 命令式检测器：规则与内置签名都没命中时兜底
registry.add_detector(fn(data) { ... })

let detection = @Mr-Houjie/mbt-filetype.detect_with(registry, bytes)
```

优先级：用户规则 → 内置签名与容器判定 → 用户检测器 → 文本启发式。

## CLI

```bash
# 识别单个文件
moon run cmd/main -- examples/sample.png

# 以 JSON 输出
moon run cmd/main -- --json examples/sample.json

# 显示证据链、偏移与评分
moon run cmd/main -- --explain examples/sample.png

# 断言类型：不匹配时退出码为 1
moon run cmd/main -- --expect image/png examples/sample.png

# 递归扫描目录，报告扩展名与内容不符的文件
moon run cmd/main -- --scan examples

# 列出全部已知类型
moon run cmd/main -- --list-types
```

## 支持等级与判定终点

支持范围分三级，不是所有类型都走结构解析——这一点写在前面，避免误解：

| 等级 | 判定方式 | 覆盖 | 定位 |
|---|---|---|---|
| **A. 结构解析** | 按格式规范解析容器结构 | ZIP、OLE2、ISO-BMFF、RIFF/IFF、EBML、Ogg、tar、PE、BMP | 项目的实质贡献 |
| **B. 魔数 + 字段校验** | 魔数命中后校验长度、版本或枚举字段 | 其余图像、归档、字体、数据库、科学数据 | 兼容层 |
| **C. 保守启发式** | 文本结构判定，一律 `probable` | json / xml / html / csv / tsv / text | 显式标注不确定 |

A 级容器必须同时满足：结构合法的正例、对抗样本不误判、真实文件对拍记录。缺一项就不算「已支持」。

## 支持的结构判定

| 容器 | 解析方式 | 可区分 |
|---|---|---|
| ZIP | EOCD → 中央目录 → 条目名/压缩方法 | docx / xlsx / pptx / epub / odt / ods / odp / xps / apk / jar / zip |
| OLE2 | 512 字节头 → DIFAT → FAT → 目录扇区 → UTF-16LE 流名 | doc / xls / ppt / ole2 |
| ISO-BMFF | box 树 → ftyp brand + moov/trak/mdia/hdlr | mp4 / mov / m4a / heic / avif / 3gp |
| RIFF / IFF | chunk 遍历 + 必需块校验 | wav / avi / webp / aiff / riff / iff |
| EBML | vint 解码 → DocType | mkv / webm |
| Ogg | 页头 + segment table → 首包 | opus / ogg |
| tar | 512 字节 header 八进制 checksum | tar |
| PE | e_lfanew → COFF → Optional Header | pe（含机器类型、EXE/DLL、节数） |
| BMP | 保留字段 + DIB header 大小 | bmp |

B 级的实现细节见 `signatures.mbt`（魔数表 + 字段校验），A 级见 `structures.mbt`。

## 一致性语料与测试

识别行为由 `conformance.mbt` 中的 **142 条**「输入 → 期望类型」用例定义，测试与自检共用同一份数据。
语料不是手写的几个魔数字节，而是用构造器生成结构合法的容器：

- 完整 ZIP（本地头 + 中央目录 + EOCD），含 64 KiB 之后的中央目录用例
- 完整 OLE2（header + FAT + 目录扇区 + 流名），含 doc / xls / ppt 与「前缀相似流名」对抗样本
- 完整 RIFF/IFF chunk、ISO-BMFF box 树、EBML vint、Ogg 页、tar header、PE 头
- **对抗样本**：真 ZIP 里塞 `word/document.xml` 文本、`mimetype` 不在首位、
  缺少 `[Content_Types].xml`、`BMW 320i …` 文本、`MZ …` 文本

真实文件语料目前覆盖 ZIP / RIFF / tar；OLE2、ISO-BMFF、EBML、Ogg、PE、BMP
由结构构造器与对抗样本覆盖，真实样本对拍列入下一轮。

```bash
moon test          # 标准测试（部分 Windows 环境受嵌套进程限制）
moon run cmd/verify  # 独立自检入口，与 moon test 等价
```

## 跨库一致性对拍

`tools/crosscheck.py` 把本库的输出与 `libmagic` / npm `file-type` 逐文件对比：

```bash
# 准备一个真实文件语料目录，然后：
python tools/crosscheck.py corpus/
```

脚本会输出一致率、全部分歧清单，便于逐条归因。分歧不是失败——是下一轮规则修正的输入。

## 已知边界（都有明确的降级路径）

这些不是「没做」，而是有确定行为的降级——边界之外返回更保守的结果，而不是猜：

| 场景 | 行为 |
|---|---|
| deflate 条目内容 | 条目名仍从中央目录读取；内容只读 `stored` 条目（EPUB/ODF 规范要求 `mimetype` 必须 stored） |
| ZIP64 / 单条 > 2 GiB | 中央目录解析失败 → 降级为 `zip`，不猜具体子类型 |
| > 2 GiB 的 ISO-BMFF box | box 遍历停止 → 退回 ftyp brand 判定；64 位 largesize 仅支持高 32 位为 0 |
| 归档内部 | 不递归；`--scan` 只报告外层文件 |
| 文本类 | 一律 `probable`，不与二进制判定混用 |
| 恶意构造 / 完整性 | 不检测，本库不是安全扫描器 |

## 许可证

MIT
