# MoonBit 十月黑客松 项目申报书

## 一、项目名称与 GitHub 仓库

- **项目名称**：mbt-filetype（基于 MoonBit 的文件类型识别与内容嗅探库）
- **GitHub 仓库**：https://github.com/Mr-Houjie/mbt-filetype
- **许可证**：MIT ｜ **语言**：MoonBit ≥ 0.10.14

## 二、项目简介

`mbt-filetype` 是一个用 MoonBit 原生实现的文件类型识别库，同时提供**可复用库**与**命令行工具**。
它只读文件内容头部，不依赖扩展名，把「这段字节是什么文件」变成**可解释、可测试、可放进 CI**
的工程能力，为 MoonBit 生态补齐 libmagic 级别的类型识别基础设施。

**架构分为五层**：类型模型（types）→ 有序签名表（signatures，104 条签名 / 96 种类型）→
检测引擎（detect：魔数匹配 → 容器消歧 → 文本启发式）→ 输出渲染（render：text / json / 类型清单）→
应用层（cmd/main 与 cmd/verify）。

**核心特色**：纯 MoonBit 实现（识别核心零第三方依赖）、不猜原则、可解释、任意字节不越界、内置自检语料。

## 三、项目方向与适用场景

**大赛方向归属**：对应大赛「**开发者工具 / 数据处理**」方向——面向文件处理与开发体验的通用组件。

**选题依据（已做全量生态排查）**：立项前我们对 mooncakes.io **官方索引**（3,133 个模块）
做了检索，`filetype`、`magic bytes`、`libmagic`、`content sniff` 均 **0 命中**；邮件 MIME、
字符编码、图片编解码等相邻方向已有成熟包，但都不提供「字节 → 文件类型」的通用识别能力。

**定位**：MoonBit 生态的文件类型识别基础设施，既可独立作为 CLI 使用，也可作为库嵌入上传校验、
构建工具与测试管线。

**适用场景**：上传内容类型校验；CLI / 构建工具的格式分发；测试与数据管线的资产检查；安全审计初筛；多后端统一识别。

## 四、核心功能

1. **104 条魔数签名、96 种类型**：图片、文档、归档、音视频、可执行、字体、数据库、科学数据、WASM、数据列存
2. **容器消歧**：ZIP → docx/xlsx/pptx/epub/apk/jar/odt/ods/odp/xps；RIFF → wav/avi/webp；
   ftyp → mp4/mov/heic/avif/m4a/3gp；EBML → mkv/webm；IFF → aiff；Ogg → opus；OLE2 / ASF 返回候选
3. **不猜原则**：弱签名只给 `probable`；证据不足返回 `unknown` 或候选列表，绝不返回错误答案
4. **可解释输出**：类型、MIME、扩展名、大类、置信度、命中签名、偏移、字节数与判定理由
5. **三种输出 + 两个 CI 模式**：`text` / `json` / `--explain`；`--expect <类型>` 断言类型，
   `--scan <目录>` 报告扩展名与内容不符的文件
6. **库 API**：`detect(Bytes) -> Detection`、`known_types()`、`render_*`，纯函数识别，不依赖网络与时区
7. **可自检的一致性语料**：128 条「输入 → 期望类型」用例作为识别行为的单一事实来源，
   `moon test` 与 `moon run cmd/verify` 共享同一份
8. **工程化**：GitHub Actions CI（检查 / 构建 / 测试 / 自检）、`--list-types`、`moon check --deny-warn` 零警告

## 五、项目性质

**原创实现**（非移植）。代码 100% 由作者独立编写；签名与 MIME 取值参照各格式公开规范与
IANA 媒体类型注册表，属公开标准参考，非代码复制。

**原创工程工作**：
- 用 MoonBit 代数数据类型设计 `FileType` / `Detection` / `Confidence` 模型，把「类型 + 置信度 + 证据 + 候选」统一成一个返回值
- **有序签名表 + 强弱分级**：冲突按固定优先级裁决，弱签名只给 `probable`，避免启发式误判
- **容器二次消歧**：ZIP / RIFF / ftyp / EBML / IFF / Ogg / OLE2 / ASF 先识别通用容器，再按结构或条目名细化
- **边界安全**：所有字节访问先检查长度，`detect` 对任意输入是全函数；固定种子 fuzz 2000 轮断言不 panic
- 在 Windows 下定位并绕过 `moon test` 嵌套进程受限的问题，用 `cmd/verify` 提供等价的独立验证路径

**外部参考**：IANA Media Types、PNG/JPEG/ZIP/ELF/WebAssembly 等公开规范与 libmagic 的分类思路（未复制代码）。
