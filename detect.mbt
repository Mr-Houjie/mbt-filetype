// 检测引擎。
//
// 整体流程：
//   1. 按签名表顺序做魔数匹配（强签名在前，弱签名在后）；
//   2. 命中通用容器后做一次消歧（ZIP / RIFF / ftyp / OLE2 / CAFEBABE / TTF）；
//   3. 没有命中签名时，做保守的文本启发式；
//   4. 仍然无法判断则返回 unknown，并保留证据说明。
//
// 所有字节访问都先做边界检查，因此任意输入都不会触发越界。

///|
/// 在 `offset` 处比对 `magic`，越界或长度不足返回 `false`。
fn match_at(data : Bytes, offset : Int, magic : Bytes) -> Bool {
  let n = data.length()
  let m = magic.length()
  if offset < 0 || m == 0 || offset + m > n {
    return false
  }
  let mut i = 0
  while i < m {
    if data[offset + i].to_int() != magic[i].to_int() {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// 在 `data` 的前 `limit` 个字节内搜索字节串。
fn contains_bytes(data : Bytes, pattern : Bytes, limit : Int) -> Bool {
  let end = if data.length() < limit { data.length() } else { limit }
  let m = pattern.length()
  if m == 0 || end < m {
    return false
  }
  let mut i = 0
  while i + m <= end {
    if match_at(data, i, pattern) {
      return true
    }
    i = i + 1
  }
  false
}

///|
/// 读取大端 16 位整数。
fn u16_be(data : Bytes, offset : Int) -> Int? {
  if offset < 0 || offset + 2 > data.length() {
    return None
  }
  Some(data[offset].to_int() * 256 + data[offset + 1].to_int())
}

///|
/// 读取大端 32 位整数。
fn u32_be(data : Bytes, offset : Int) -> Int? {
  if offset < 0 || offset + 4 > data.length() {
    return None
  }
  Some(
    data[offset].to_int() * 16777216 +
    data[offset + 1].to_int() * 65536 +
    data[offset + 2].to_int() * 256 +
    data[offset + 3].to_int(),
  )
}

///|
/// 读取小端 32 位整数。
fn u32_le(data : Bytes, offset : Int) -> Int? {
  if offset < 0 || offset + 4 > data.length() {
    return None
  }
  Some(
    data[offset + 3].to_int() * 16777216 +
    data[offset + 2].to_int() * 65536 +
    data[offset + 1].to_int() * 256 +
    data[offset].to_int(),
  )
}

///|
fn ascii_lower_byte(b : Int) -> Int {
  if b >= 65 && b <= 90 {
    b + 32
  } else {
    b
  }
}

///|
/// 大小写不敏感的前缀比较（仅 ASCII）。
fn starts_with_ci(data : Bytes, pattern : Bytes) -> Bool {
  if data.length() < pattern.length() {
    return false
  }
  let mut i = 0
  while i < pattern.length() {
    if ascii_lower_byte(data[i].to_int()) !=
      ascii_lower_byte(pattern[i].to_int()) {
      return false
    }
    i = i + 1
  }
  true
}

///|
fn unknown_detection(reason : String) -> Detection {
  {
    file_type: None,
    confidence: Unknown,
    reason,
    offset: 0,
    matched_len: 0,
    candidates: [],
  }
}

///|
fn certain_detection(sig : Signature) -> Detection {
  {
    file_type: Some(sig.file_type),
    confidence: if sig.strong {
      Certain
    } else {
      Probable
    },
    reason: sig.label,
    offset: sig.offset,
    matched_len: sig.magic.length(),
    candidates: [],
  }
}

///|
fn refined_detection(
  sig : Signature,
  file_type : FileType,
  confidence : Confidence,
  reason : String,
) -> Detection {
  {
    file_type: Some(file_type),
    confidence,
    reason,
    offset: sig.offset,
    matched_len: sig.magic.length(),
    candidates: [],
  }
}

///|
fn with_candidates(
  sig : Signature,
  file_type : FileType,
  confidence : Confidence,
  reason : String,
  candidates : Array[FileType],
) -> Detection {
  {
    file_type: Some(file_type),
    confidence,
    reason,
    offset: sig.offset,
    matched_len: sig.magic.length(),
    candidates,
  }
}

// ---------------------------------------------------------------------------
// 容器消歧
// ---------------------------------------------------------------------------

///|
fn refine_zip(sig : Signature, data : Bytes) -> Detection {
  let limit = 65536
  if contains_bytes(data, b"application/epub+zip", limit) {
    return refined_detection(
      sig,
      epub,
      Probable,
      "ZIP 容器内包含 EPUB mimetype 声明",
    )
  }
  if contains_bytes(data, b"application/vnd.oasis.opendocument.text", limit) {
    return refined_detection(
      sig,
      odt,
      Probable,
      "ZIP 容器内包含 OpenDocument text mimetype",
    )
  }
  if contains_bytes(
      data, b"application/vnd.oasis.opendocument.spreadsheet", limit,
    ) {
    return refined_detection(
      sig,
      ods,
      Probable,
      "ZIP 容器内包含 OpenDocument spreadsheet mimetype",
    )
  }
  if contains_bytes(
      data, b"application/vnd.oasis.opendocument.presentation", limit,
    ) {
    return refined_detection(
      sig,
      odp,
      Probable,
      "ZIP 容器内包含 OpenDocument presentation mimetype",
    )
  }
  if contains_bytes(data, b"FixedDocSeq.fdseq", limit) {
    return refined_detection(
      sig,
      xps,
      Probable,
      "ZIP 容器内包含 XPS 固定文档序列",
    )
  }
  if contains_bytes(data, b"AndroidManifest.xml", limit) {
    return refined_detection(
      sig,
      apk,
      Probable,
      "ZIP 容器内包含 AndroidManifest.xml",
    )
  }
  if contains_bytes(data, b"META-INF/MANIFEST.MF", limit) {
    return refined_detection(
      sig,
      jar,
      Probable,
      "ZIP 容器内包含 META-INF/MANIFEST.MF",
    )
  }
  if contains_bytes(data, b"word/", limit) {
    return refined_detection(
      sig,
      docx,
      Probable,
      "ZIP 容器内包含 word/ 目录",
    )
  }
  if contains_bytes(data, b"xl/", limit) {
    return refined_detection(
      sig,
      xlsx,
      Probable,
      "ZIP 容器内包含 xl/ 目录",
    )
  }
  if contains_bytes(data, b"ppt/", limit) {
    return refined_detection(
      sig,
      pptx,
      Probable,
      "ZIP 容器内包含 ppt/ 目录",
    )
  }
  certain_detection(sig)
}

///|
fn refine_riff(sig : Signature, data : Bytes) -> Detection {
  if match_at(data, 8, b"WAVE") {
    return refined_detection(sig, wav, Certain, "RIFF 容器，子类型 WAVE")
  }
  if match_at(data, 8, b"AVI ") {
    return refined_detection(sig, avi, Certain, "RIFF 容器，子类型 AVI ")
  }
  if match_at(data, 8, b"WEBP") {
    return refined_detection(sig, webp, Certain, "RIFF 容器，子类型 WEBP")
  }
  with_candidates(sig, riff, Probable, "RIFF 容器，但子类型未知", [
    wav, avi, webp,
  ])
}

///|
fn refine_ftyp(sig : Signature, data : Bytes) -> Detection {
  if match_at(data, 8, b"avif") || match_at(data, 8, b"avis") {
    return refined_detection(sig, avif, Certain, "ftyp brand = avif/avis")
  }
  if match_at(data, 8, b"heic") ||
    match_at(data, 8, b"heix") ||
    match_at(data, 8, b"hevc") ||
    match_at(data, 8, b"hevx") ||
    match_at(data, 8, b"mif1") ||
    match_at(data, 8, b"msf1") {
    return refined_detection(sig, heic, Certain, "ftyp brand = HEIF 系列")
  }
  if match_at(data, 8, b"M4A ") || match_at(data, 8, b"M4B ") {
    return refined_detection(sig, m4a, Certain, "ftyp brand = M4A/M4B")
  }
  if match_at(data, 8, b"3gp4") ||
    match_at(data, 8, b"3gp5") ||
    match_at(data, 8, b"3gp6") ||
    match_at(data, 8, b"3g2a") {
    return refined_detection(sig, threegp, Certain, "ftyp brand = 3GP 系列")
  }
  if match_at(data, 8, b"qt  ") {
    return refined_detection(sig, mov, Certain, "ftyp brand = qt  ")
  }
  if match_at(data, 8, b"isom") ||
    match_at(data, 8, b"iso2") ||
    match_at(data, 8, b"mp41") ||
    match_at(data, 8, b"mp42") ||
    match_at(data, 8, b"M4V ") ||
    match_at(data, 8, b"dash") {
    return refined_detection(sig, mp4, Certain, "ftyp brand = MP4 系列")
  }
  with_candidates(sig, ftyp, Probable, "ISO BMFF 容器，但 brand 未知", [
    mp4, mov, heic,
  ])
}

///|
fn refine_cafebabe(sig : Signature, data : Bytes) -> Detection {
  match u32_be(data, 4) {
    Some(count) =>
      if count >= 1 && count <= 16 {
        return refined_detection(
          sig,
          macho,
          Probable,
          "Mach-O universal binary (nfat_arch 合理)",
        )
      }
    None => ()
  }
  match u16_be(data, 6) {
    Some(major) =>
      if major >= 45 && major <= 70 {
        return refined_detection(
          sig,
          java_class,
          Probable,
          "Java class 主版本号在 45..70 之间",
        )
      }
    None => ()
  }
  with_candidates(
    sig,
    cafebabe,
    Probable,
    "CAFEBABE 头，但无法确定是 Mach-O fat 还是 Java class",
    [macho, java_class],
  )
}

///|
fn refine_ttf_raw(sig : Signature, data : Bytes) -> Detection {
  match u16_be(data, 4) {
    Some(tables) =>
      if tables >= 1 && tables <= 512 {
        refined_detection(
          sig,
          ttf,
          Probable,
          "TrueType sfnt 版本 0x00010000，表数量合理",
        )
      } else {
        unknown_detection("以 0x00010000 开头，但 sfnt 表数量异常")
      }
    None => unknown_detection("输入过短，无法校验 TrueType 表数量")
  }
}

///|
fn refine_pe(sig : Signature, data : Bytes) -> Detection {
  match u32_le(data, 60) {
    Some(pe_offset) =>
      if match_at(data, pe_offset, b"PE\x00\x00") {
        refined_detection(sig, pe, Certain, "MZ 头 + PE\\0\\0 签名")
      } else {
        refined_detection(sig, pe, Probable, "MZ 头，但未找到 PE 签名")
      }
    None => refined_detection(sig, pe, Probable, "MZ 头，但文件过短")
  }
}

///|
fn refine_ebml(sig : Signature, data : Bytes) -> Detection {
  if contains_bytes(data, b"webm", 4096) {
    return refined_detection(
      sig,
      webm,
      Probable,
      "EBML 容器内包含 webm DocType",
    )
  }
  if contains_bytes(data, b"matroska", 4096) {
    return refined_detection(
      sig,
      mkv,
      Probable,
      "EBML 容器内包含 matroska DocType",
    )
  }
  with_candidates(sig, ebml, Probable, "EBML 容器，但未找到 DocType", [
    mkv, webm,
  ])
}

///|
fn refine_ogg(sig : Signature, data : Bytes) -> Detection {
  if contains_bytes(data, b"OpusHead", 512) {
    return refined_detection(
      sig,
      opus,
      Probable,
      "Ogg 容器内包含 OpusHead",
    )
  }
  certain_detection(sig)
}

///|
fn refine_iff(sig : Signature, data : Bytes) -> Detection {
  if match_at(data, 8, b"AIFF") || match_at(data, 8, b"AIFC") {
    return refined_detection(
      sig,
      aiff,
      Certain,
      "IFF 容器，子类型 AIFF/AIFC",
    )
  }
  with_candidates(sig, iff, Probable, "IFF 容器，但子类型未知", [aiff])
}

///|
fn refine_postscript(sig : Signature, data : Bytes) -> Detection {
  if contains_bytes(data, b"%!PS-AdobeFont", 64) {
    return refined_detection(sig, pfa, Probable, "PostScript Type 1 字体头")
  }
  certain_detection(sig)
}

///|
fn refine_asf(sig : Signature, _data : Bytes) -> Detection {
  with_candidates(
    sig,
    asf,
    Probable,
    "ASF 容器；仅凭头部无法区分 wma / wmv",
    [wma, wmv],
  )
}

///|
fn refine(sig : Signature, data : Bytes) -> Detection {
  match sig.file_type.id {
    "zip" => refine_zip(sig, data)
    "riff" => refine_riff(sig, data)
    "ftyp" => refine_ftyp(sig, data)
    "ebml" => refine_ebml(sig, data)
    "ogg" => refine_ogg(sig, data)
    "iff" => refine_iff(sig, data)
    "postscript" => refine_postscript(sig, data)
    "asf" => refine_asf(sig, data)
    "cafebabe" => refine_cafebabe(sig, data)
    "ttf-raw" => refine_ttf_raw(sig, data)
    "pe" =>
      if sig.strong {
        certain_detection(sig)
      } else {
        refine_pe(sig, data)
      }
    "ole2" =>
      with_candidates(
        sig,
        ole2,
        Certain,
        "OLE2 复合文档头；仅凭头部无法区分 doc / xls / ppt",
        [doc, xls, ppt],
      )
    _ => certain_detection(sig)
  }
}

// ---------------------------------------------------------------------------
// 文本启发式
// ---------------------------------------------------------------------------

///|
/// 判断前 `limit` 个字节是否「看起来像文本」。
///
/// 这里做保守的 UTF-8 结构检查：拒绝 NUL、明显不可打印的控制字符、
/// 非法首字节与错误的续字节。校验不完整时（样本在码点中间截断）按文本处理。
fn looks_like_text(data : Bytes, limit : Int) -> Bool {
  let mut i = 0
  while i < limit {
    let b = data[i].to_int()
    if b < 32 {
      if b != 9 && b != 10 && b != 12 && b != 13 {
        return false
      }
      i = i + 1
    } else if b < 128 {
      i = i + 1
    } else {
      let needed = if b >= 194 && b <= 223 {
        1
      } else if b >= 224 && b <= 239 {
        2
      } else if b >= 240 && b <= 244 {
        3
      } else {
        return false
      }
      let mut j = 1
      while j <= needed {
        if i + j >= limit {
          return true
        }
        let continuation = data[i + j].to_int()
        if continuation < 128 || continuation > 191 {
          return false
        }
        j = j + 1
      }
      i = i + needed + 1
    }
  }
  true
}

///|
fn first_non_space(data : Bytes, limit : Int) -> Int {
  let mut i = 0
  while i < limit {
    let b = data[i].to_int()
    if b != 32 && b != 9 && b != 10 && b != 13 {
      return i
    }
    i = i + 1
  }
  limit
}

///|
fn count_byte(data : Bytes, start : Int, end : Int, value : Int) -> Int {
  let mut count = 0
  let mut i = start
  while i < end && i < data.length() {
    if data[i].to_int() == value {
      count = count + 1
    }
    i = i + 1
  }
  count
}

///|
/// 分隔符启发式：第一行至少一个分隔符，且第二行数量与第一行一致。
fn looks_like_delimited(data : Bytes, limit : Int, separator : Int) -> Bool {
  let mut first_end = -1
  let mut i = 0
  while i < limit {
    if data[i].to_int() == 10 {
      first_end = i
      break
    }
    i = i + 1
  }
  if first_end <= 0 {
    return false
  }
  let first_count = count_byte(data, 0, first_end, separator)
  if first_count == 0 {
    return false
  }
  if first_end + 1 >= limit {
    return true
  }
  let mut second_end = limit
  let mut j = first_end + 1
  while j < limit {
    if data[j].to_int() == 10 {
      second_end = j
      break
    }
    j = j + 1
  }
  count_byte(data, first_end + 1, second_end, separator) == first_count
}

///|
fn looks_like_csv(data : Bytes, limit : Int) -> Bool {
  looks_like_delimited(data, limit, 44)
}

///|
fn looks_like_tsv(data : Bytes, limit : Int) -> Bool {
  looks_like_delimited(data, limit, 9)
}

///|
fn text_detection(
  file_type : FileType,
  reason : String,
  offset : Int,
  matched_len : Int,
) -> Detection {
  {
    file_type: Some(file_type),
    confidence: Probable,
    reason,
    offset,
    matched_len,
    candidates: [],
  }
}

///|
fn detect_text(data : Bytes) -> Detection {
  let limit = if data.length() < 4096 { data.length() } else { 4096 }
  if !looks_like_text(data, limit) {
    return unknown_detection("二进制内容，但没有命中已知签名")
  }
  let i = first_non_space(data, limit)
  if i < limit {
    let b = data[i].to_int()
    if b == 123 || b == 91 {
      return text_detection(json, "首个非空白字节是 { 或 [", i, 1)
    }
  }
  if starts_with_ci(data, b"<?xml") {
    return text_detection(xml, "以 <?xml 开头", 0, 5)
  }
  if starts_with_ci(data, b"<!doctype html") {
    return text_detection(html, "以 <!DOCTYPE html 开头", 0, 14)
  }
  if starts_with_ci(data, b"<html") {
    return text_detection(html, "以 <html 开头", 0, 5)
  }
  if looks_like_tsv(data, limit) {
    return text_detection(tsv, "前两行的制表符数量一致", 0, 0)
  }
  if looks_like_csv(data, limit) {
    return text_detection(csv, "前两行的逗号数量一致", 0, 0)
  }
  text_detection(
    plain_text, "可打印文本，未命中更具体的类型", 0, 0,
  )
}

// ---------------------------------------------------------------------------
// 公共 API
// ---------------------------------------------------------------------------

///|
/// MPEG-TS 的同步字节 0x47 每隔 188 字节出现一次。
fn looks_like_mpeg_ts(data : Bytes) -> Bool {
  data.length() >= 377 &&
  data[0].to_int() == 71 &&
  data[188].to_int() == 71 &&
  data[376].to_int() == 71
}

///|
/// 根据字节内容识别文件类型。
///
/// 该函数是纯函数：不读文件、不访问网络、不依赖系统状态。
pub fn detect(data : Bytes) -> Detection {
  if data.length() == 0 {
    return unknown_detection("空输入")
  }
  if looks_like_mpeg_ts(data) {
    return text_detection(ts, "MPEG-TS 同步字节位于 0/188/376", 0, 1)
  }
  let mut i = 0
  while i < signatures.length() {
    let sig = signatures[i]
    if match_at(data, sig.offset, sig.magic) {
      return refine(sig, data)
    }
    i = i + 1
  }
  detect_text(data)
}

///|
/// 内置签名条数。
pub fn signature_count() -> Int {
  signatures.length()
}

///|
/// 由容器消歧推导出的类型：它们没有独立签名，但确实是可识别的已知类型。
fn container_types() -> Array[FileType] {
  [
    doc,
    xls,
    ppt,
    docx,
    xlsx,
    pptx,
    odt,
    ods,
    odp,
    xps,
    apk,
    jar,
    wav,
    aiff,
    opus,
    m4a,
    wma,
    mp4,
    mov,
    mkv,
    webm,
    avi,
    wmv,
    threegp,
    webp,
    avif,
    heic,
    macho,
    java_class,
  ]
}

///|
/// 全部已知类型（按首次出现顺序去重），用于 `--list-types`。
pub fn known_types() -> Array[FileType] {
  let out : Array[FileType] = []
  for sig in signatures {
    if !contains_type(out, sig.file_type.id) {
      out.push(sig.file_type)
    }
  }
  for file_type in container_types() {
    if !contains_type(out, file_type.id) {
      out.push(file_type)
    }
  }
  for file_type in text_types {
    if !contains_type(out, file_type.id) {
      out.push(file_type)
    }
  }
  out
}

///|
fn contains_type(types : Array[FileType], id : String) -> Bool {
  for file_type in types {
    if file_type.id == id {
      return true
    }
  }
  false
}
