# MoonBit 十月黑客松 项目申报书（第二轮）

## 一、项目名称与仓库

mbt-filetype（MoonBit 原生文件类型识别引擎）｜https://github.com/Mr-Houjie/mbt-filetype ｜ MIT ｜ MoonBit ≥ 0.10.14

## 二、项目简介

不查扩展名，按格式规范解析字节结构：ZIP 读 EOCD 与中央目录，OLE2 读 FAT 与目录扇区，ISO-BMFF 遍历 box 树并下钻 hdlr，RIFF 遍历 chunk，EBML 解 vint，tar 校验 checksum，PE 校验 COFF。判定由加权证据链推导，置信度是评分的函数；对外提供可扩展规则接口。仓库含库、CLI 与自检入口。

## 三、项目方向与通用性

方向为开发者工具 / 数据处理。识别核心是纯函数，只接收 `Bytes`，不依赖文件系统与网络，可用于上传校验、构建产物检查与测试管线。根包 `moon.pkg` 为空、无任何第三方 import（可直接核验）；mooncakes.io 检索 filetype / libmagic / content sniff 无匹配，MoonBit 侧缺少该能力。

## 四、针对初审意见的改动

| 初审意见 | 本轮改动 |
|---|---|
| 依赖固定魔数与字符串搜索 | 移除全部子串扫描；容器一律结构解析，失败则降级不猜 |
| 容器消歧缺结构验证 | 新增 913 行解析层：ZIP / OLE2 / ISO-BMFF / RIFF / EBML / tar / PE / BMP |
| 无自定义签名与检测器接口 | 新增 `Registry` / `Rule` / `Matcher`（偏移、掩码、ASCII、与或组合） |
| 置信度无判定依据 | `Detection` 携带 `evidence[]` 与 `score`，阈值公开可复算 |
| 缺真实语料与跨库验证 | 语料生成器 + libmagic 对拍：15 个真实文件，真分歧 0 |

## 五、预期使用场景

上传内容校验（伪装扩展名）、构建产物断言（`--expect`）、素材目录巡检（`--scan`）、私有格式扩展（`Registry`）。

## 六、核心功能

结构解析优先；证据链可解释（`--explain` / `--json`）；142 条自检语料含对抗样本；CLI 与 CI 断言。

## 七、验证结果

- `moon run cmd/verify` → 142 cases passed；GitHub Actions 四步全绿（check / build / test / verify）
- 与 libmagic 对拍 15 个真实文件：完全一致 12、本库更具体 3、真分歧 0（仅对该语料成立）
- 对拍暴露并修复：真实 ZIP 的 CRC32 常大于 `0x7FFFFFFF`，被 32 位读取的溢出保护误判为越界，导致中央目录解析中断

## 八、边界与判定终点

支持分三级：A 结构解析（9 类容器）、B 魔数 + 字段校验、C 文本启发式。A 级须同时具备结构正例、对抗样本、真实文件对拍，缺一不计入「已支持」。真实语料当前覆盖 ZIP / RIFF / tar，其余由构造器覆盖；不做解压与递归归档，不做恶意构造检测；ZIP64 与大文件走降级路径。

## 九、项目性质

参照 file-type / libmagic 语义的独立实现（非移植），未复制其源码；签名与 MIME 依据 IANA 注册表与各格式公开规范。

## 十、GitHub 与提交记录

首轮 10 个以上有效提交；第二轮按依赖分 5 层提交（结构层 / 引擎 / 语料 / 工具 / 文档），无空提交、无重复提交。
