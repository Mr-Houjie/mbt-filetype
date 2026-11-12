# 重新提交说明（v0.2.2）

本文档对应 `MoonBit 开源大赛 · 十月黑客松` 项目《mbt-filetype》第二轮提交。

## 一、结论先写

组委会指出的三个问题**全部属实，已在 v0.2.2 修复**。此外在修复过程中发现同类
问题不止评审点出的那几处，属于同一个根因，已一并清理。

| # | 反馈原文摘要 | 核查结果 | 状态 |
|---|---|---|---|
| 1 | 偏移计算整数溢出，64 字节 MZ 设 `e_lfanew=0x7fffffff` 即 panic | 属实，`PanicError` 稳定复现 | 已修复 |
| 2 | 导致识别和目录扫描异常退出 | 属实，`--scan` 遇该样本整进程崩溃，后续文件全部未处理 | 已修复 |
| 3 | IFF 大端解析不正确 | 属实，合法 AIFC（`FVER` 在 `COMM` 前）被误判为泛型 `iff` | 已修复 |
| 4 | 截断 ZIP/RIFF 的结构判定不正确 | 属实，截断 WAV 被判 `certain / 100 分` 且声称「chunk 都存在」；EOCD 虚报条目数仍称「中央目录结构有效」 | 已修复 |
| 5 | 核心边界检查不可靠 | 属实，且范围更大：ZIP 中央目录 `local_offset=0x7FFFFFFF` 同样 panic | 已修复 |

## 二、根因

MoonBit 的 `Int` 是 **32 位有符号整数，溢出回绕**（不是饱和、也不抛错）。可验证：

```
0x7FFFFFFE + 4  ==  -2147483646
```

原实现的全部边界检查都写成加法的形式：

```moonbit
if offset + width > length { return None }
```

当 `offset` 取自文件字段且接近 `2^31`（PE 的 `e_lfanew`、ZIP 中央目录的
`local header offset` 都天然是 32 位字段）时，`offset + width` 回绕成负数，
`> length` 不成立，越界被判定为**合法**，紧接着的索引访问即触发 panic。

这也解释了为什么项目原有的固定种子 fuzz 没能发现：它生成 ≤64 字节的随机数据，
同时命中 `MZ`、且第 60..63 字节恰好为 `FF FF FF 7F` 的概率极低。

## 三、修复内容

### 3.1 溢出（根本修复）

新增统一区间判定，写法改为减法：

```moonbit
fn in_range(offset : Int, width : Int, length : Int) -> Bool {
  offset >= 0 && width >= 0 && width <= length && offset <= length - width
}
```

`length - width` 不会溢出（`width <= length` 已先行保证），因此该式对任意
32 位 `offset` 都成立。替换范围：

- `match_at` / `u16_le` / `u16_be` / `u32_le` / `u32_be` / `slice_bytes` / `raw_string`
- OLE2 扇区偏移：先用除法约束扇区号再乘，避免 `(sector + 1) * sector_size` 回绕
- ISO-BMFF `read_box`、EBML 元素推进、ZIP 中央目录推进：全部改为减法比较

### 3.2 IFF 大端

`parse_chunk_container` 原先固定调用 `u32_le`，但 AIFF/AIFC 的 `FORM` 容器长度
与各 chunk 长度字段是**大端**。长度被读成天文数字后 chunk 遍历立刻中断，
子类型无法判定，最终落到泛型 `iff`。

修复：函数增加 `big_endian` 参数，`parse_riff` 传 `false`、`parse_iff` 传 `true`。

### 3.3 截断判定

`RiffInfo.complete` 与 `ZipArchive.complete` 原本**计算了却从未被使用**，
所以截断文件照样被判为结构完整。修复：

- `RiffInfo` 新增 `truncated` 字段：容器声明长度超过实际数据、
  或某个 chunk 体不完整时置位
- 新增 `degraded_detection`：只累加弱证据（20 + 40 = 60 分），落到 `probable`，
  与 `confidence_of_score` 的公开阈值保持一致，不再出现「100 分却说可能」
- `reason` 明确写出降级原因，例如
  `RIFF/WAVE，fmt 与 data chunk 头都存在，但声明长度超过实际数据（文件被截断）`
  或 `…（中央目录只解析出 2/5 条，文件可能被截断）`

### 3.4 顺带收紧的 ZIP 结构校验

- EOCD 定位优先选择「注释长度与文件末尾严格吻合」的那一条，避免文件中偶然出现的
  `PK\x05\x06` 被当作中央目录入口；无严格匹配时回退到最后一次出现（兼容自解压包）
- 中央目录偏移必须小于 EOCD 位置，否则判为伪造

## 四、复验方法

代码在 `Mr-Houjie/mbt-filetype` 的 `v0.2.2` tag。

```bash
git clone --branch v0.2.2 git@github.com:Mr-Houjie/mbt-filetype.git
cd mbt-filetype
moon test        # 23 个测试，含 6 个针对本次反馈的回归用例
moon run cmd/verify   # 142 条一致性用例
```

回归用例（`detect_test.mbt` 中「回归：…」系列）直接对应反馈条目：

| 用例 | 断言 |
|---|---|
| `e_lfanew 极大值不得 panic` | `0x7FFFFFFC/FFFFFFFD/FFFFFFFE/FFFFFFFF` 全部不 panic，且不得判为合法 PE |
| `ZIP 中央目录里的巨大 local header 偏移不得 panic` | `0x7FFFFFFF` 不 panic，降级为 `zip` |
| `合法 ZIP 仍判定为 EPUB 且为 certain` | 修复不得误伤正常文件 |
| `EOCD 虚报条目数时降级并说明只解析出几条` | 降级且 `reason` 含 `1/2` |
| `IFF 必须按大端解析，FVER 在前的 AIFC 仍识别为 aiff` | 判为 `aiff / certain` |
| `截断的 RIFF 必须降级并说明截断` | 判为 `wav / probable` 且 `reason` 含「截断」 |

复现原始故障（不依赖测试框架，直接喂字节）：

```bash
# 64 字节 MZ，e_lfanew = 0x7FFFFFFF
python -c "import struct;b=bytearray(64);b[0:2]=b'MZ';struct.pack_into('<I',b,60,0x7fffffff);open('mz.bin','wb').write(bytes(b))"
moon run cmd/main -- --explain mz.bin
# v0.2.1: PanicError
# v0.2.2: pe / probable（e_lfanew 指向的不是合法 PE 头）
```

## 五、验证记录

在 Windows / `moon 0.1.20261028` 上实测：

| 项目 | 结果 |
|---|---|
| `moon test` | 23 / 23 通过 |
| `cmd/verify` 一致性语料 | 142 cases passed |
| 结构化 fuzz（15 份语料头部单字节变异 + 逐段截断，共 1536 次执行） | 0 panic |
| `--scan` 含恶意样本的目录 | 正常跑完并输出统计，不再中断 |
| `moon check --deny-warn` | 无告警 |

## 六、遗留边界（明确不做的部分）

以下不属于本次反馈范围，仍在 README「已知边界」中如实声明，不做过度承诺：

- ZIP64、单条 > 2 GiB：中央目录解析失败即降级为 `zip`，不猜子类型
- > 2 GiB 的 ISO-BMFF box：退回 ftyp brand 判定
- 归档内部不递归
- 本库是类型识别器，不是完整性校验器或安全扫描器；截断只会被「识别出来并标注」，
  不会被「拒绝」
