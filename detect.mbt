// 检测引擎。
//
// 整体流程：
//   1. 用户规则（Registry）；
//   2. 按签名表顺序做魔数匹配（强签名在前，弱签名在后）；
//   3. 命中容器类签名后交给结构解析层判定（ZIP 中央目录 / OLE2 目录流 /
//      ISO-BMFF box / RIFF chunk / EBML DocType / PE 头）；
//   4. 命中弱签名时做结构校验，校验失败则回落；
//   5. 用户检测器；
//   6. 保守的文本启发式；
//   7. 仍然无法判断则返回 unknown。
//
// 置信度由证据累加得出（见 `confidence_of_score`），不是人工标注的标签。
// 所有字节访问都先做边界检查，因此任意输入都不会触发越界。

// ---------------------------------------------------------------------------
// 证据与结果构造
// ---------------------------------------------------------------------------

///|
const W_STRONG : Int = 90
const W_WEAK : Int = 20
const W_STRUCTURE : Int = 40
const W_DECISIVE : Int = 70
const W_HEURISTIC : Int = 30

///|
fn evidence(
  kind : String,
  label : String,
  offset : Int,
  matched_len : Int,
  weight : Int,
) -> Evidence {
  { kind, label, offset, matched_len, weight }
}

///|
fn make_detection(
  file_type : FileType?,
  reason : String,
  evidence : Array[Evidence],
  candidates : Array[FileType],
) -> Detection {
  let mut score = 0
  for item in evidence {
    score = score + item.weight
  }
  if score > 100 {
    score = 100
  }
  let offset = if evidence.length() > 0 { evidence[0].offset } else { 0 }
  let matched_len = if evidence.length() > 0 {
    evidence[0].matched_len
  } else {
    0
  }
  let confidence = match file_type {
    Some(_) => confidence_of_score(score)
    None => Unknown
  }
  {
    file_type,
    confidence,
    reason,
    offset,
    matched_len,
    candidates,
    score,
    evidence,
  }
}

///|
fn unknown_detection(reason : String) -> Detection {
  make_detection(None, reason, [], [])
}

///|
fn signature_evidence(sig : Signature) -> Evidence {
  evidence(
    "magic",
    sig.label,
    sig.offset,
    sig.magic.length(),
    if sig.strong {
      W_STRONG
    } else {
      W_WEAK
    },
  )
}

///|
fn certain_detection(sig : Signature) -> Detection {
  make_detection(
    Some(sig.file_type),
    sig.label,
    [signature_evidence(sig)],
    [],
  )
}

///|
/// 由「魔数 + 结构证据」构造结果。
fn structured_detection(
  sig : Signature,
  file_type : FileType,
  reason : String,
  structure_label : String,
  structure_weight : Int,
) -> Detection {
  make_detection(
    Some(file_type),
    reason,
    [
      signature_evidence(sig),
      evidence("structure", structure_label, 0, 0, structure_weight),
    ],
    [],
  )
}

///|
fn with_candidates(
  sig : Signature,
  file_type : FileType,
  reason : String,
  structure_label : String,
  candidates : Array[FileType],
) -> Detection {
  make_detection(
    Some(file_type),
    reason,
    [
      signature_evidence(sig),
      evidence("structure", structure_label, 0, 0, W_STRUCTURE),
    ],
    candidates,
  )
}

// ---------------------------------------------------------------------------
// 容器消歧：全部基于结构解析
// ---------------------------------------------------------------------------

///|
/// 读取 ZIP 第一个条目的 mimetype 内容（EPUB / ODF 规范要求它 stored 且排第一）。
fn zip_declared_mimetype(data : Bytes, archive : ZipArchive) -> String? {
  if archive.entries.length() == 0 {
    return None
  }
  let first = archive.entries[0]
  if first.name != "mimetype" || first.compression != 0 {
    return None
  }
  match zip_entry_content(data, first) {
    Some(content) => Some(raw_string(content, 0, content.length()))
    None => None
  }
}

///|
fn refine_zip(sig : Signature, data : Bytes) -> Detection {
  let archive = match parse_zip(data) {
    Some(a) => a
    None =>
      return make_detection(
        Some(zip),
        "ZIP 文件头，但中央目录无法解析（可能被截断或不是 ZIP）",
        [signature_evidence(sig)],
        [],
      )
  }
  let names = zip_entry_names(archive)
  let parsed = "\{archive.entries.length()}/\{archive.declared_entries}"
  let layout = "中央目录解析成功（\{parsed} 条目）"
  match zip_declared_mimetype(data, archive) {
    Some(mime) =>
      if mime == "application/epub+zip" {
        return structured_detection(
          sig, epub, "ZIP 首条目 mimetype 声明为 EPUB", "首条目是 stored 的 mimetype", W_DECISIVE,
        )
      } else if mime == "application/vnd.oasis.opendocument.text" {
        return structured_detection(
          sig, odt, "ZIP 首条目 mimetype 声明为 OpenDocument text", "首条目是 stored 的 mimetype", W_DECISIVE,
        )
      } else if mime == "application/vnd.oasis.opendocument.spreadsheet" {
        return structured_detection(
          sig, ods, "ZIP 首条目 mimetype 声明为 OpenDocument spreadsheet", "首条目是 stored 的 mimetype", W_DECISIVE,
        )
      } else if mime == "application/vnd.oasis.opendocument.presentation" {
        return structured_detection(
          sig, odp, "ZIP 首条目 mimetype 声明为 OpenDocument presentation", "首条目是 stored 的 mimetype", W_DECISIVE,
        )
      }
    None => ()
  }
  // OOXML：必须有 [Content_Types].xml，且主文档部件独立出现
  if contains_name(names, "[Content_Types].xml") {
    if contains_name(names, "word/document.xml") {
      return structured_detection(
        sig, docx, "OOXML：存在 word/document.xml 与 [Content_Types].xml", layout, W_STRUCTURE,
      )
    }
    if contains_name(names, "xl/workbook.xml") {
      return structured_detection(
        sig, xlsx, "OOXML：存在 xl/workbook.xml 与 [Content_Types].xml", layout, W_STRUCTURE,
      )
    }
    if contains_name(names, "ppt/presentation.xml") {
      return structured_detection(
        sig, pptx, "OOXML：存在 ppt/presentation.xml 与 [Content_Types].xml", layout, W_STRUCTURE,
      )
    }
  }
  if contains_name(names, "FixedDocSeq.fdseq") {
    return structured_detection(
      sig, xps, "XPS：存在 FixedDocSeq.fdseq", layout, W_STRUCTURE,
    )
  }
  if contains_name(names, "AndroidManifest.xml") &&
    contains_name(names, "classes.dex") {
    return structured_detection(
      sig, apk, "APK：同时存在 AndroidManifest.xml 与 classes.dex", layout, W_DECISIVE,
    )
  }
  if contains_name(names, "META-INF/MANIFEST.MF") {
    return structured_detection(
      sig, jar, "JAR：存在 META-INF/MANIFEST.MF 且无 classes.dex", layout, W_STRUCTURE,
    )
  }
  structured_detection(sig, zip, "ZIP 中央目录结构有效，未发现更具体的容器特征", layout, W_STRUCTURE)
}

///|
fn refine_ole2(sig : Signature, data : Bytes) -> Detection {
  match parse_ole2_streams(data) {
    Some(names) =>
      if contains_name(names, "WordDocument") {
        return structured_detection(
          sig, doc, "OLE2 目录中存在 WordDocument 流", "FAT 与目录扇区解析成功", W_DECISIVE,
        )
      } else if contains_name(names, "Workbook") ||
        contains_name(names, "Book") {
        return structured_detection(
          sig, xls, "OLE2 目录中存在 Workbook/Book 流", "FAT 与目录扇区解析成功", W_DECISIVE,
        )
      } else if contains_name(names, "PowerPoint Document") {
        return structured_detection(
          sig, ppt, "OLE2 目录中存在 PowerPoint Document 流", "FAT 与目录扇区解析成功", W_DECISIVE,
        )
      }
    None => ()
  }
  with_candidates(
    sig,
    ole2,
    "OLE2 复合文档头；目录结构无法解析或未包含已知流",
    "仅头部校验通过",
    [doc, xls, ppt],
  )
}

///|
fn refine_riff(sig : Signature, data : Bytes) -> Detection {
  let info = match parse_riff(data) {
    Some(v) => v
    None =>
      return with_candidates(
        sig, riff, "RIFF 容器，但 chunk 结构无法解析", "header 校验通过", [wav, avi, webp],
      )
  }
  if info.form == "WAVE" &&
    contains_name(info.chunks, "fmt ") &&
    contains_name(info.chunks, "data") {
    return structured_detection(
      sig, wav, "RIFF/WAVE，且 fmt 与 data chunk 都存在", "chunk 遍历命中 fmt + data", W_DECISIVE,
    )
  }
  if info.form == "AVI " &&
    (contains_name(info.chunks, "hdrl") || contains_name(info.chunks, "movi")) {
    return structured_detection(
      sig, avi, "RIFF/AVI，且 hdrl 或 movi chunk 存在", "chunk 遍历命中 AVI 必需块", W_DECISIVE,
    )
  }
  if info.form == "WEBP" &&
    (contains_name(info.chunks, "VP8 ") ||
      contains_name(info.chunks, "VP8L") ||
      contains_name(info.chunks, "VP8X")) {
    return structured_detection(
      sig, webp, "RIFF/WEBP，且存在 VP8/VP8L/VP8X chunk", "chunk 遍历命中 WebP 编码块", W_DECISIVE,
    )
  }
  with_candidates(
    sig,
    riff,
    "RIFF 容器，子类型未知或缺少必需 chunk",
    "chunk 遍历未命中已知子类型",
    [wav, avi, webp],
  )
}

///|
fn refine_iff(sig : Signature, data : Bytes) -> Detection {
  match parse_iff(data) {
    Some(info) =>
      if (info.form == "AIFF" || info.form == "AIFC") &&
        contains_name(info.chunks, "COMM") {
        return structured_detection(
          sig, aiff, "IFF/AIFF，且存在 COMM chunk", "chunk 遍历命中 COMM", W_DECISIVE,
        )
      }
    None => ()
  }
  with_candidates(
    sig, iff, "IFF 容器，但子类型未知", "header 校验通过", [aiff],
  )
}

///|
fn refine_ftyp(sig : Signature, data : Bytes) -> Detection {
  let brands = bmff_brands(data)
  let handlers = bmff_handlers(data)
  let brand_label = if brands.length() > 0 {
    "ftyp major brand = \{brands[0]}"
  } else {
    "ftyp 已解析"
  }
  if contains_name(brands, "avif") || contains_name(brands, "avis") {
    return structured_detection(
      sig, avif, "ISO-BMFF：brand 为 avif/avis", brand_label, W_DECISIVE,
    )
  }
  if contains_name(brands, "heic") ||
    contains_name(brands, "heix") ||
    contains_name(brands, "hevc") ||
    contains_name(brands, "hevx") ||
    contains_name(brands, "mif1") ||
    contains_name(brands, "msf1") {
    return structured_detection(
      sig, heic, "ISO-BMFF：brand 属于 HEIF 系列", brand_label, W_DECISIVE,
    )
  }
  if contains_name(brands, "M4A ") || contains_name(brands, "M4B ") {
    return structured_detection(
      sig, m4a, "ISO-BMFF：brand 为 M4A/M4B", brand_label, W_DECISIVE,
    )
  }
  if contains_name(brands, "3gp4") ||
    contains_name(brands, "3gp5") ||
    contains_name(brands, "3gp6") ||
    contains_name(brands, "3g2a") {
    return structured_detection(
      sig, threegp, "ISO-BMFF：brand 属于 3GP 系列", brand_label, W_DECISIVE,
    )
  }
  if contains_name(brands, "qt  ") {
    return structured_detection(
      sig, mov, "ISO-BMFF：brand 为 QuickTime", brand_label, W_DECISIVE,
    )
  }
  if contains_name(handlers, "vide") {
    return structured_detection(
      sig, mp4, "ISO-BMFF：mdia/hdlr 声明 vide", "box 树下钻到 hdlr = vide", W_DECISIVE,
    )
  }
  if contains_name(handlers, "soun") {
    return structured_detection(
      sig, m4a, "ISO-BMFF：mdia/hdlr 仅声明 soun", "box 树下钻到 hdlr = soun", W_DECISIVE,
    )
  }
  if contains_name(brands, "isom") ||
    contains_name(brands, "iso2") ||
    contains_name(brands, "mp41") ||
    contains_name(brands, "mp42") ||
    contains_name(brands, "M4V ") ||
    contains_name(brands, "dash") {
    return with_candidates(
      sig,
      mp4,
      "ISO-BMFF：brand 属于 MP4 系列，但未找到 handler",
      brand_label,
      [mov, m4a],
    )
  }
  with_candidates(
    sig,
    ftyp,
    "ISO-BMFF 容器，但 brand 未知",
    "box 头解析通过",
    [mp4, mov, heic],
  )
}

///|
fn refine_ebml(sig : Signature, data : Bytes) -> Detection {
  match ebml_doctype(data) {
    Some(doc_type) =>
      if doc_type == "webm" {
        return structured_detection(
          sig, webm, "EBML DocType = webm", "vint 解析出 DocType 元素", W_DECISIVE,
        )
      } else if doc_type == "matroska" {
        return structured_detection(
          sig, mkv, "EBML DocType = matroska", "vint 解析出 DocType 元素", W_DECISIVE,
        )
      }
    None => ()
  }
  with_candidates(
    sig, ebml, "EBML 容器，但未解析出 DocType", "EBML 头结构有效", [mkv, webm],
  )
}

///|
fn refine_ogg(sig : Signature, data : Bytes) -> Detection {
  if data.length() >= 27 {
    let segments = data[26].to_int()
    if segments > 0 && 27 + segments < data.length() {
      let packet_start = 27 + segments
      let packet_len = data[27].to_int()
      match slice_bytes(data, packet_start, packet_start + packet_len) {
        Some(packet) =>
          if match_at(packet, 0, b"OpusHead") {
            return structured_detection(
              sig, opus, "Ogg 首页首包为 OpusHead", "按 Ogg 页布局解析出首包", W_DECISIVE,
            )
          }
        None => ()
      }
    }
  }
  certain_detection(sig)
}

///|
fn refine_cafebabe(sig : Signature, data : Bytes) -> Detection {
  match u32_be(data, 4) {
    Some(count) =>
      if count >= 1 && count <= 16 {
        return structured_detection(
          sig, macho, "Mach-O universal binary：nfat_arch 合理", "fat header 的 nfat_arch 在 1..16", W_STRUCTURE,
        )
      }
    None => ()
  }
  match u16_be(data, 6) {
    Some(major) =>
      if major >= 45 && major <= 70 {
        return structured_detection(
          sig, java_class, "Java class：主版本号在 45..70", "class 文件版本字段校验通过", W_STRUCTURE,
        )
      }
    None => ()
  }
  with_candidates(
    sig,
    cafebabe,
    "CAFEBABE 头，但无法确定是 Mach-O fat 还是 Java class",
    "两种结构的判别字段都不成立",
    [macho, java_class],
  )
}

///|
fn refine_ttf_raw(sig : Signature, data : Bytes) -> Detection {
  match u16_be(data, 4) {
    Some(tables) =>
      if tables >= 1 && tables <= 512 {
        structured_detection(
          sig, ttf, "TrueType sfnt：表数量合理", "sfnt offset table 的 numTables 在 1..512", W_STRUCTURE,
        )
      } else {
        unknown_detection("以 0x00010000 开头，但 sfnt 表数量异常")
      }
    None => unknown_detection("输入过短，无法校验 TrueType 表数量")
  }
}

///|
fn refine_pe(sig : Signature, data : Bytes) -> Detection {
  match parse_pe(data) {
    Some(info) => {
      let kind = if info.is_dll { "DLL" } else { "EXE" }
      return structured_detection(
        sig,
        pe,
        "PE 结构有效：\{pe_machine_name(info)}，\{kind}，\{info.sections} 个节",
        "e_lfanew 指向合法 PE 头，COFF/Optional Header 校验通过",
        W_DECISIVE,
      )
    }
    None => ()
  }
  let limit = if data.length() < 4096 { data.length() } else { 4096 }
  if looks_like_text(data, limit) {
    return detect_text(data)
  }
  make_detection(
    Some(pe),
    "MZ 头，但 e_lfanew 指向的不是合法 PE 头",
    [signature_evidence(sig)],
    [],
  )
}

///|
/// BMP 的结构校验：保留字段必须为 0，DIB header 大小必须在已知取值集合内。
fn refine_bmp(sig : Signature, data : Bytes) -> Detection {
  if data.length() >= 30 {
    let reserved = u32_le(data, 6)
    let dib = u32_le(data, 14)
    match reserved {
      Some(r) =>
        match dib {
          Some(size) =>
            if r == 0 &&
              (size == 12 ||
                size == 40 ||
                size == 52 ||
                size == 56 ||
                size == 64 ||
                size == 108 ||
                size == 124) {
              return structured_detection(
                sig,
                bmp,
                "BMP 结构有效：DIB header = \{size}",
                "保留字段为 0 且 DIB header 大小合法",
                W_DECISIVE,
              )
            }
          None => ()
        }
      None => ()
    }
  }
  let limit = if data.length() < 4096 { data.length() } else { 4096 }
  if looks_like_text(data, limit) {
    return detect_text(data)
  }
  make_detection(
    Some(bmp),
    "BM 头，但 DIB header 未通过校验",
    [signature_evidence(sig)],
    [],
  )
}

///|
/// PNM 的弱签名要求魔数后紧跟空白字符。
fn refine_pnm(sig : Signature, data : Bytes) -> Detection {
  if data.length() > sig.magic.length() {
    let next = data[sig.magic.length()].to_int()
    if next == 32 || next == 9 || next == 10 || next == 13 {
      return make_detection(
        Some(pnm),
        "PNM 魔数后紧跟空白字符",
        [
          signature_evidence(sig),
          evidence("structure", "PNM 魔数后是分隔符", sig.magic.length(), 1, W_STRUCTURE),
        ],
        [],
      )
    }
  }
  detect_text(data)
}

///|
fn refine_tar(sig : Signature, data : Bytes) -> Detection {
  if tar_checksum_ok(data) {
    return structured_detection(
      sig,
      tar,
      "tar header 的八进制 checksum 校验通过",
      "512 字节 header 的 checksum 与内容一致",
      W_DECISIVE,
    )
  }
  make_detection(
    Some(tar),
    "存在 ustar 标识，但 header checksum 不匹配",
    [signature_evidence(sig)],
    [],
  )
}

///|
fn refine_postscript(sig : Signature, data : Bytes) -> Detection {
  if match_at(data, 0, b"%!PS-AdobeFont") || match_at(data, 0, b"%!FontType1") {
    return structured_detection(
      sig, pfa, "PostScript Type 1 字体头", "Adobe Font 专用标识匹配", W_STRUCTURE,
    )
  }
  certain_detection(sig)
}

///|
fn refine_asf(sig : Signature, _data : Bytes) -> Detection {
  with_candidates(
    sig,
    asf,
    "ASF 容器；仅凭头部无法区分 wma / wmv",
    "ASF header GUID 匹配",
    [wma, wmv],
  )
}

///|
fn refine(sig : Signature, data : Bytes) -> Detection {
  match sig.file_type.id {
    "zip" => refine_zip(sig, data)
    "riff" => refine_riff(sig, data)
    "iff" => refine_iff(sig, data)
    "ftyp" => refine_ftyp(sig, data)
    "ebml" => refine_ebml(sig, data)
    "ogg" => refine_ogg(sig, data)
    "postscript" => refine_postscript(sig, data)
    "asf" => refine_asf(sig, data)
    "cafebabe" => refine_cafebabe(sig, data)
    "ttf-raw" => refine_ttf_raw(sig, data)
    "tar" => refine_tar(sig, data)
    "pe" => refine_pe(sig, data)
    "bmp" => refine_bmp(sig, data)
    "pnm" => refine_pnm(sig, data)
    "ole2" => refine_ole2(sig, data)
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
fn starts_with_ci(data : Bytes, pattern : Bytes) -> Bool {
  if data.length() < pattern.length() {
    return false
  }
  let mut i = 0
  while i < pattern.length() {
    let mut a = data[i].to_int()
    let mut b = pattern[i].to_int()
    if a >= 65 && a <= 90 {
      a = a + 32
    }
    if b >= 65 && b <= 90 {
      b = b + 32
    }
    if a != b {
      return false
    }
    i = i + 1
  }
  true
}

///|
fn text_detection(
  file_type : FileType,
  reason : String,
  offset : Int,
  matched_len : Int,
) -> Detection {
  make_detection(
    Some(file_type),
    reason,
    [evidence("heuristic", reason, offset, matched_len, W_HEURISTIC)],
    [],
  )
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
  if looks_like_delimited(data, limit, 9) {
    return text_detection(tsv, "前两行的制表符数量一致", 0, 0)
  }
  if looks_like_delimited(data, limit, 44) {
    return text_detection(csv, "前两行的逗号数量一致", 0, 0)
  }
  text_detection(plain_text, "可打印文本，未命中更具体的类型", 0, 0)
}

// ---------------------------------------------------------------------------
// 公共 API
// ---------------------------------------------------------------------------

///|
/// MPEG-TS 的同步字节 0x47 每隔 188 字节出现一次。
fn looks_like_mpeg_ts(data : Bytes) -> Bool {
  if data.length() < 377 {
    return false
  }
  let mut i = 0
  let mut hits = 0
  while i < data.length() && i < 188 * 8 {
    if data[i].to_int() == 71 {
      hits = hits + 1
    }
    i = i + 188
  }
  hits >= 3
}

///|
/// 内置签名与容器判定；没有命中时返回 `None`（不包含文本启发式）。
fn detect_signatures(data : Bytes) -> Detection? {
  if looks_like_mpeg_ts(data) {
    return Some(
      make_detection(
        Some(ts),
        "MPEG-TS：0x47 同步字节按 188 字节周期出现",
        [
          evidence("structure", "0x47 同步字节周期为 188", 0, 1, W_DECISIVE),
        ],
        [],
      ),
    )
  }
  let mut i = 0
  while i < signatures.length() {
    let sig = signatures[i]
    if match_at(data, sig.offset, sig.magic) {
      return Some(refine(sig, data))
    }
    i = i + 1
  }
  None
}

///|
/// 根据字节内容识别文件类型（使用内置规则集）。
///
/// 该函数是纯函数：不读文件、不访问网络、不依赖系统状态。
pub fn detect(data : Bytes) -> Detection {
  detect_with(Registry::new(), data)
}

///|
/// 使用自定义规则集与检测器识别文件类型。
///
/// 优先级：用户规则 → 内置签名与容器判定 → 用户检测器 → 文本启发式。
pub fn detect_with(registry : Registry, data : Bytes) -> Detection {
  if data.length() == 0 {
    return unknown_detection("空输入")
  }
  for rule in registry.rules {
    match eval_matcher(rule.matcher, data) {
      Some(offset) =>
        return make_detection(
          Some({
            id: rule.id,
            mime: rule.mime,
            ext: rule.ext,
            category: rule.category,
          }),
          rule.label,
          [rule_evidence(rule, offset)],
          [],
        )
      None => ()
    }
  }
  match detect_signatures(data) {
    Some(detection) => return detection
    None => ()
  }
  for detector in registry.detectors {
    match detector(data) {
      Some(detection) => return detection
      None => ()
    }
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
