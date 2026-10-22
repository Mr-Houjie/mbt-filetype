# MoonBit 十月黑客松 项目申报书（第二轮）

## 一、项目名称与仓库

- **项目名称**：mbt-filetype（MoonBit 原生文件类型识别与内容嗅探引擎）
- **GitHub 仓库**：https://github.com/Mr-Houjie/mbt-filetype
- **许可证**：MIT ｜ **MoonBit**：≥ 0.10.14

## 二、项目简介

mbt-filetype 用 MoonBit 原生实现文件类型识别。与「查魔数表」的做法不同，它按格式规范解析字节结构：

- ZIP：从 EOCD 定位中央目录，逐条解析条目名与压缩方法
- OLE2：读 DIFAT / FAT / 目录扇区，取出 UTF-16LE 流名
- ISO-BMFF：遍历 box 树，读 ftyp brand 并下钻 `moov/trak/mdia/hdlr`
- RIFF / IFF：遍历 chunk 并校验必需块
- EBML：解 vint 取 DocType；Ogg：按页头与 segment table 取首包
- tar：校验 header 八进制 checksum；PE：校验 COFF 与 Optional Header

判定结果由**加权证据链**推导：每条证据带种类、偏移、权重，置信度是总分的函数，而不是人工标注的标签。
识别核心对外提供可扩展接口：调用方可以注册自己的规则与检测器，与内置流程共用同一套语义。

## 三、本轮针对初审意见的改动

| 初审意见 | 本轮改动 |
|---|---|
| 主要依赖固定魔数及字符串搜索 | 删除全部子串扫描实现（`contains_bytes` 已从代码库移除）。容器判定一律走结构解析；无法解析时不猜，降级为通用容器或 `unknown` |
| 容器消歧缺乏充分的结构验证 | 新增 `structures.mbt` 约 900 行解析层：ZIP 中央目录、OLE2 FAT/目录项、ISO-BMFF box 树、RIFF chunk、EBML vint、tar checksum、PE 头、BMP DIB header |
| 未提供自定义签名和检测器扩展接口 | 新增 `rules.mbt`：`Registry` + `Rule` + `Matcher`（固定偏移 / 尾部偏移 / 位掩码 / ASCII / 与或组合），内置流程与用户规则同一套求值器 |
| 置信度标签不能替代判定依据 | `Detection` 增加 `score` 与 `evidence[]`；`confidence_of_score` 是公开契约（≥90 certain，≥20 probable） |
| 缺少真实文件语料 | 新增 `tools/make_corpus.py`，用 zlib/bz2/lzma/tarfile/wave/sqlite3/zipfile 生成真实编码器产出的语料；一致性语料改为用构造器生成结构合法的容器，并补充对抗样本 |
| 缺少跨库一致性验证 | 新增 `tools/crosscheck.py`，与 `libmagic`（python-magic）逐文件对拍，输出一致率与分歧归因 |

## 四、预期使用场景

1. **上传内容校验**：Web 服务收到无扩展名或伪装扩展名的文件时读取头部字节；把可执行文件改名为 `.png` 会被识别为 `elf` 并拒绝
2. **构建产物检查**：`--expect wasm` 断言产物类型，不匹配时返回非零退出码，CI 直接失败
3. **素材目录巡检**：`--scan assets/` 找出扩展名与内容不一致的文件，以 JSON 输出报告
4. **需要自定义格式的团队**：通过 `Registry` 注册私有格式规则，无需 fork 本库

## 五、核心功能

1. **结构解析优先**：A 级容器（ZIP / OLE2 / ISO-BMFF / RIFF / IFF / EBML / Ogg / tar / PE / BMP）均按规范解析，而不是在字节流里找字符串
2. **证据链输出**：`--explain` 打印每条证据的种类、权重、偏移与说明；`--json` 输出结构化 `evidence[]` 与 `score`
3. **可扩展规则**：`Matcher` 支持五种组合子，`add_rule` / `add_detector` 提供声明式与命令式两个扩展点
4. **不猜原则**：结构校验失败 → 降级；歧义 → 候选列表；证据不足 → `unknown`
5. **CLI 与 CI**：`text` / `json` / `--explain`；`--expect` 断言；`--scan` 报告扩展名不符
6. **可自检语料**：142 条「输入 → 期望类型」用例，`moon test` 与 `cmd/verify` 共用；固定种子 fuzz 2000 轮
7. **对抗样本**：真 ZIP 内含 `word/document.xml` 文本、`mimetype` 不在首位、缺 `[Content_Types].xml`、`BMW 320i …` 与 `MZ …` 文本，全部断言不误判

## 六、验证结果（可复现）

```bash
moon run cmd/verify          # conformance: 142 cases passed
python tools/make_corpus.py  # 生成 15 个真实编码器产出的文件
python tools/crosscheck.py corpus
```

对拍结果（libmagic 作为参照，MIME 命名差异按等价类归一）：

- 15 个语料文件：完全一致 12、本库更具体 3、真分歧 0
- 「更具体」指参照只给出 `text/plain`，本库给出 `application/json` / `text/csv` / `text/tab-separated-values`
- 上述结论只对该语料成立，不代表全格式覆盖

对拍过程中发现并修复了一个真实缺陷：中央目录里的 CRC32 常大于 `0x7FFFFFFF`，
曾被 32 位读取的溢出保护误判为越界，导致真实 ZIP 的解析中断。该问题只有用真实编码器产出的
ZIP 才会暴露，手写 hex 语料无法发现——这也是本轮补充真实语料与跨库对拍的直接价值。

## 七、支持等级、判定终点与参照系

项目不追求「全格式覆盖」，而是把支持范围拆成可以判定的三级：

| 等级 | 判定方式 | 覆盖 | 定位 |
|---|---|---|---|
| **A. 结构解析** | 按格式规范解析容器结构 | ZIP、OLE2、ISO-BMFF、RIFF/IFF、EBML、Ogg、tar、PE、BMP | 项目的实质贡献 |
| **B. 魔数 + 字段校验** | 魔数命中后校验长度、版本或枚举字段 | 其余图像、归档、字体、数据库、科学数据 | 兼容层 |
| **C. 保守启发式** | 文本结构判定，一律 `probable` | json / xml / html / csv / tsv / text | 显式标注不确定 |

**判定终点**（三项缺一，该容器不计入「已支持」）：

1. 结构合法的正例；
2. 「看起来像但结构不成立」的对抗样本，且断言不误判；
3. 真实文件的对拍记录（与 libmagic 一致，或书面归因分歧）——当前覆盖 ZIP / RIFF / tar，
   其余 A 级容器由结构构造器覆盖，真实样本列入下一轮。

**参照系**：检测语义与容器类型以 `file-type`、`libmagic` 的公开行为为参照，而不是凭空定义一套格式体系。
增量在于三点：

1. MoonBit 原生零依赖实现——识别核心所在包（根包）`moon.pkg` 为空，无任何第三方 import，可直接核验；
2. 可扩展规则接口（`Registry` / `Rule` / `Matcher`），第三方可注册私有格式而无需 fork；
3. 结构化证据链（`evidence[]` + 派生 `score`），置信度可复算。

所有解析代码为独立实现，未复制上述项目源码。

**明确的非目标**：不做解压、不递归归档、不做恶意构造检测、不做完整性校验；
ISO-BMFF 仅支持 `< 4 GiB` 的 largesize，ZIP64 走降级路径。
这些边界不被隐藏——它们正是 A 级验收标准的一部分：边界之外返回降级结果，而不是猜。

## 八、项目性质

**参照成熟库语义的独立实现（非移植）**。检测语义与容器类型以 `file-type`、`libmagic` 的公开行为为参照系；
所有解析代码独立编写，未复制其源码。签名与 MIME 取值参照 IANA 媒体类型注册表与各格式公开规范。
语料由标准库编码器生成，对拍脚本仅调用本库 CLI 与系统工具。

`main` 分支按「结构解析层 → 证据链 → 规则引擎 → 语料与对抗样本 → 对拍工具 → 文档」分层提交，无空提交、无重复提交。
