// 结构解析层。
//
// 这一层的职责不是「找字节」，而是「按格式规范解析字节」：
//   - ZIP：从 EOCD 定位中央目录，逐条解析条目名与压缩方法；
//   - OLE2：读 FAT 与目录扇区，取出真实的流名；
//   - ISO-BMFF：按 box 树遍历，读 ftyp brand 与 hdlr handler；
//   - RIFF：遍历 chunk，校验必需块是否存在；
//   - EBML：按 vint 解析 DocType；
//   - TAR：校验 header 的八进制 checksum；
//   - PE：读 COFF / Optional Header，校验机器类型与子系统。
//
// 所有解析都先做边界检查；任何结构不一致都返回 `None`，由上层决定是否降级，
// 绝不把「看起来像」当成「结构成立」。

// ---------------------------------------------------------------------------
// 基础读取
// ---------------------------------------------------------------------------

///|
/// 比对 `offset` 处的 `magic`，越界或长度不足返回 `false`。
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
fn byte_at(data : Bytes, offset : Int) -> Int? {
  if offset < 0 || offset >= data.length() {
    return None
  }
  Some(data[offset].to_int())
}

///|
/// 读小端 16 位。
fn u16_le(data : Bytes, offset : Int) -> Int? {
  if offset < 0 || offset + 2 > data.length() {
    return None
  }
  Some(data[offset].to_int() + data[offset + 1].to_int() * 256)
}

///|
/// 读大端 16 位。
fn u16_be(data : Bytes, offset : Int) -> Int? {
  if offset < 0 || offset + 2 > data.length() {
    return None
  }
  Some(data[offset].to_int() * 256 + data[offset + 1].to_int())
}

///|
/// 读小端 32 位。
///
/// 最高字节 ≥ 0x80 时数值超出内存缓冲区的可寻址范围，按越界处理返回 `None`，
/// 这样所有调用点都不需要再单独防溢出。
fn u32_le(data : Bytes, offset : Int) -> Int? {
  if offset < 0 || offset + 4 > data.length() {
    return None
  }
  let high = data[offset + 3].to_int()
  if high >= 128 {
    return None
  }
  Some(
    high * 16777216 +
    data[offset + 2].to_int() * 65536 +
    data[offset + 1].to_int() * 256 +
    data[offset].to_int(),
  )
}

///|
/// 读大端 32 位（同上，超出范围返回 `None`）。
fn u32_be(data : Bytes, offset : Int) -> Int? {
  if offset < 0 || offset + 4 > data.length() {
    return None
  }
  let high = data[offset].to_int()
  if high >= 128 {
    return None
  }
  Some(
    high * 16777216 +
    data[offset + 1].to_int() * 65536 +
    data[offset + 2].to_int() * 256 +
    data[offset + 3].to_int(),
  )
}

///|
fn slice_bytes(data : Bytes, start : Int, end : Int) -> Bytes? {
  if start < 0 || end < start || end > data.length() {
    return None
  }
  let out : Array[Byte] = []
  let mut i = start
  while i < end {
    out.push(data[i])
    i = i + 1
  }
  Some(Bytes::from_array(out.exact_view()))
}

///|
/// 写一个码点，越界时退化为 `?`。
fn write_code(builder : StringBuilder, code : Int) -> Unit {
  match code.to_char() {
    Some(c) => builder.write_char(c)
    None => builder.write_char('?')
  }
}

///|
/// 把一段原始字节按 UTF-8 解码为字符串。
///
/// 不能用 `Bytes::to_unchecked_string`（它按 UTF-16 重新解释字节），
/// 也不能用 `Bytes::to_string`（它返回 `b"..."` 调试形式），
/// 所以这里显式做 UTF-8 解码。
fn raw_string(data : Bytes, offset : Int, length : Int) -> String {
  if offset < 0 || length <= 0 || offset + length > data.length() {
    return ""
  }
  let builder = StringBuilder()
  let mut i = 0
  while i < length {
    let b = data[offset + i].to_int()
    if b < 128 {
      builder.write_char(data[offset + i].to_char())
      i = i + 1
    } else {
      let needed = if b >= 194 && b <= 223 {
        1
      } else if b >= 224 && b <= 239 {
        2
      } else if b >= 240 && b <= 244 {
        3
      } else {
        0
      }
      if needed == 0 || i + needed >= length {
        builder.write_char('?')
        i = i + 1
      } else {
        let base = if needed == 1 {
          192
        } else if needed == 2 {
          224
        } else {
          240
        }
        let mut code = b - base
        let mut j = 1
        while j <= needed {
          code = code * 64 + (data[offset + i + j].to_int() - 128)
          j = j + 1
        }
        write_code(builder, code)
        i = i + needed + 1
      }
    }
  }
  builder.to_string()
}

///|
fn contains_name(names : Array[String], wanted : String) -> Bool {
  for name in names {
    if name == wanted {
      return true
    }
  }
  false
}

// ---------------------------------------------------------------------------
// ZIP：中央目录
// ---------------------------------------------------------------------------

///|
pub struct ZipEntry {
  name : String
  /// 压缩方法：0 = stored，8 = deflate
  compression : Int
  compressed_size : Int
  uncompressed_size : Int
  /// 条目数据在输入中的起始偏移
  data_offset : Int
  local_offset : Int
}

///|
pub struct ZipArchive {
  entries : Array[ZipEntry]
  /// EOCD 中声明的条目总数
  declared_entries : Int
  /// 是否完整解析了声明的全部条目
  complete : Bool
}

///|
fn find_eocd(data : Bytes) -> Int? {
  let len = data.length()
  if len < 22 {
    return None
  }
  let mut pos = len - 22
  let floor = if len > 65557 { len - 65557 } else { 0 }
  while pos >= floor {
    if match_at(data, pos, b"PK\x05\x06") {
      return Some(pos)
    }
    pos = pos - 1
  }
  None
}

///|
fn zip_data_offset(data : Bytes, local_offset : Int) -> Int? {
  if !match_at(data, local_offset, b"PK\x03\x04") {
    return None
  }
  let name_len = match u16_le(data, local_offset + 26) {
    Some(v) => v
    None => return None
  }
  let extra_len = match u16_le(data, local_offset + 28) {
    Some(v) => v
    None => return None
  }
  let start = local_offset + 30 + name_len + extra_len
  if start > data.length() {
    return None
  }
  Some(start)
}

///|
/// 解析 ZIP 中央目录。返回 `None` 表示这不是结构完整的 ZIP。
pub fn parse_zip(data : Bytes) -> ZipArchive? {
  let eocd = match find_eocd(data) {
    Some(v) => v
    None => return None
  }
  let declared = match u16_le(data, eocd + 10) {
    Some(v) => v
    None => return None
  }
  let cd_offset = match u32_le(data, eocd + 16) {
    Some(v) => v
    None => return None
  }
  if declared == 0 || cd_offset >= data.length() {
    return None
  }
  let entries : Array[ZipEntry] = []
  let mut pos = cd_offset
  let mut count = 0
  while count < declared && count < 100000 {
    if !match_at(data, pos, b"PK\x01\x02") {
      break
    }
    let compression = match u16_le(data, pos + 10) {
      Some(v) => v
      None => break
    }
    // 注意：不要读 CRC32。真实 ZIP 的 CRC 经常 > 0x7FFFFFFF，
    // 会被 u32_le 的溢出保护判为越界，导致整份中央目录解析中断。
    let compressed = match u32_le(data, pos + 20) {
      Some(v) => v
      None => break
    }
    let uncompressed = match u32_le(data, pos + 24) {
      Some(v) => v
      None => break
    }
    let name_len = match u16_le(data, pos + 28) {
      Some(v) => v
      None => break
    }
    let extra_len = match u16_le(data, pos + 30) {
      Some(v) => v
      None => break
    }
    let comment_len = match u16_le(data, pos + 32) {
      Some(v) => v
      None => break
    }
    let local_offset = match u32_le(data, pos + 42) {
      Some(v) => v
      None => break
    }
    if pos + 46 + name_len > data.length() {
      break
    }
    let name = raw_string(data, pos + 46, name_len)
    let start = match zip_data_offset(data, local_offset) {
      Some(v) => v
      None => break
    }
    entries.push({
      name,
      compression,
      compressed_size: compressed,
      uncompressed_size: uncompressed,
      data_offset: start,
      local_offset,
    })
    pos = pos + 46 + name_len + extra_len + comment_len
    count = count + 1
  }
  if entries.length() == 0 {
    return None
  }
  Some({
    entries,
    declared_entries: declared,
    complete: entries.length() == declared,
  })
}

///|
/// 取出 stored 条目的原始内容（deflate 条目不解压，返回 `None`）。
pub fn zip_entry_content(data : Bytes, entry : ZipEntry) -> Bytes? {
  if entry.compression != 0 {
    return None
  }
  slice_bytes(
    data,
    entry.data_offset,
    entry.data_offset + entry.compressed_size,
  )
}

///|
/// 按名字精确查找条目（不是子串搜索）。
pub fn zip_find_entry(archive : ZipArchive, name : String) -> ZipEntry? {
  for entry in archive.entries {
    if entry.name == name {
      return Some(entry)
    }
  }
  None
}

///|
/// 条目名快照，用于算法判定与证据输出。
pub fn zip_entry_names(archive : ZipArchive) -> Array[String] {
  let out : Array[String] = []
  for entry in archive.entries {
    out.push(entry.name)
  }
  out
}

// ---------------------------------------------------------------------------
// OLE2：FAT 与目录项
// ---------------------------------------------------------------------------

///|
fn ole_sector_offset(sector : Int, sector_size : Int) -> Int {
  // 扇区号 + 1 才是文件偏移（头部占第 0 个扇区的位置）
  if sector < 0 || sector > 1048576 {
    return -1
  }
  (sector + 1) * sector_size
}

///|
fn utf16le_name(data : Bytes, offset : Int, byte_len : Int) -> String {
  let builder = StringBuilder()
  let mut i = 0
  while i + 1 < byte_len {
    let low = data[offset + i].to_int()
    let high = data[offset + i + 1].to_int()
    let code = high * 256 + low
    if code == 0 {
      break
    }
    write_code(builder, code)
    i = i + 2
  }
  builder.to_string()
}

///|
/// 解析 OLE2 复合文档的目录项名称（WordDocument / Workbook / PowerPoint Document …）。
///
/// 返回 `None` 表示头部或 FAT 结构不成立；返回空数组表示结构成立但没有可读流名。
pub fn parse_ole2_streams(data : Bytes) -> Array[String]? {
  if data.length() < 512 {
    return None
  }
  if !match_at(data, 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
    return None
  }
  let shift = match u16_le(data, 30) {
    Some(v) => v
    None => return None
  }
  if shift < 7 || shift > 16 {
    return None
  }
  let sector_size = 1 << shift
  let fat_count = match u32_le(data, 44) {
    Some(v) => v
    None => return None
  }
  let dir_start = match u32_le(data, 48) {
    Some(v) => v
    None => return None
  }
  if fat_count == 0 || fat_count > 4096 {
    return None
  }
  // 头部 DIFAT 的前 109 项就是 FAT 扇区号
  let fat_sectors : Array[Int] = []
  let mut i = 0
  while i < 109 && i < fat_count {
    match u32_le(data, 76 + i * 4) {
      Some(sector) => fat_sectors.push(sector)
      None => break
    }
    i = i + 1
  }
  if fat_sectors.length() == 0 {
    return None
  }
  let fat : Array[Int] = []
  for sector in fat_sectors {
    let base = ole_sector_offset(sector, sector_size)
    if base >= 0 && base + sector_size <= data.length() {
      let mut j = 0
      while j < sector_size {
        match u32_le(data, base + j) {
          Some(v) => fat.push(v)
          None => fat.push(-1)
        }
        j = j + 4
      }
    }
  }
  if fat.length() == 0 {
    return None
  }
  let names : Array[String] = []
  let mut sector = dir_start
  let mut steps = 0
  while sector >= 0 && steps < 4096 {
    let base = ole_sector_offset(sector, sector_size)
    if base < 0 || base + sector_size > data.length() {
      break
    }
    let mut off = 0
    while off + 128 <= sector_size {
      let pos = base + off
      let name_len = match u16_le(data, pos + 64) {
        Some(v) => v
        None => 0
      }
      let etype = match byte_at(data, pos + 66) {
        Some(v) => v
        None => 0
      }
      if (etype == 1 || etype == 2 || etype == 5) &&
        name_len >= 2 && name_len <= 64 {
        let name = utf16le_name(data, pos, name_len)
        if !name.is_empty() {
          names.push(name)
        }
      }
      off = off + 128
    }
    let next = if sector < fat.length() { fat[sector] } else { -1 }
    sector = next
    steps = steps + 1
  }
  Some(names)
}

// ---------------------------------------------------------------------------
// ISO-BMFF：box 树
// ---------------------------------------------------------------------------

///|
priv struct BmffBox {
  typ : String
  payload : Int
  end : Int
}

///|
fn read_box(data : Bytes, pos : Int, limit : Int) -> BmffBox? {
  if pos + 8 > limit {
    return None
  }
  let size32 = match u32_be(data, pos) {
    Some(v) => v
    None => return None
  }
  let typ = raw_string(data, pos + 4, 4)
  if size32 == 0 {
    return Some({ typ, payload: pos + 8, end: limit })
  }
  if size32 == 1 {
    // 64 位 largesize：这里只支持高 32 位为 0（< 4 GiB）
    let high = match u32_be(data, pos + 8) {
      Some(v) => v
      None => return None
    }
    let low = match u32_be(data, pos + 12) {
      Some(v) => v
      None => return None
    }
    if high != 0 || low < 16 {
      return None
    }
    let end = pos + low
    if end > limit {
      return None
    }
    return Some({ typ, payload: pos + 16, end })
  }
  if size32 < 8 {
    return None
  }
  let end = pos + size32
  if end > limit {
    return None
  }
  Some({ typ, payload: pos + 8, end })
}

///|
fn child_boxes(data : Bytes, parent : BmffBox) -> Array[BmffBox] {
  let out : Array[BmffBox] = []
  let mut pos = parent.payload
  let mut scanned = 0
  while pos + 8 <= parent.end && scanned < 4096 {
    match read_box(data, pos, parent.end) {
      Some(b) => {
        if b.end <= pos {
          break
        }
        out.push(b)
        pos = b.end
      }
      None => break
    }
    scanned = scanned + 1
  }
  out
}

///|
fn find_top_box(data : Bytes, typ : String) -> BmffBox? {
  let limit = data.length()
  let mut pos = 0
  let mut scanned = 0
  while pos + 8 <= limit && scanned < 4096 {
    match read_box(data, pos, limit) {
      Some(b) => {
        if b.typ == typ {
          return Some(b)
        }
        if b.end <= pos {
          break
        }
        pos = b.end
      }
      None => break
    }
    scanned = scanned + 1
  }
  None
}

///|
/// 收集 handler 类型（`vide` / `soun`），路径为 moov → trak* → mdia → hdlr。
pub fn bmff_handlers(data : Bytes) -> Array[String] {
  let out : Array[String] = []
  let moov = match find_top_box(data, "moov") {
    Some(b) => b
    None => return out
  }
  for trak in child_boxes(data, moov) {
    if trak.typ == "trak" {
      for mdia in child_boxes(data, trak) {
        if mdia.typ == "mdia" {
          for hdlr in child_boxes(data, mdia) {
            if hdlr.typ == "hdlr" && hdlr.payload + 12 <= hdlr.end {
              let handler = raw_string(data, hdlr.payload + 8, 4)
              out.push(handler)
            }
          }
        }
      }
    }
  }
  out
}

///|
/// 读 ftyp：major brand + compatible brands。
pub fn bmff_brands(data : Bytes) -> Array[String] {
  let out : Array[String] = []
  let ftyp = match find_top_box(data, "ftyp") {
    Some(b) => b
    None => return out
  }
  if ftyp.payload + 8 > ftyp.end {
    return out
  }
  out.push(raw_string(data, ftyp.payload, 4))
  let mut pos = ftyp.payload + 8
  while pos + 4 <= ftyp.end {
    out.push(raw_string(data, pos, 4))
    pos = pos + 4
  }
  out
}

// ---------------------------------------------------------------------------
// RIFF：chunk 遍历
// ---------------------------------------------------------------------------

///|
pub struct RiffInfo {
  /// 容器子类型，例如 `WAVE` / `AVI ` / `WEBP`
  form : String
  /// 实际遍历到的 chunk id
  chunks : Array[String]
  /// chunk 遍历是否走到预期结尾
  complete : Bool
}

///|
fn parse_chunk_container(data : Bytes, tag : Bytes) -> RiffInfo? {
  if data.length() < 12 || !match_at(data, 0, tag) {
    return None
  }
  let declared = match u32_le(data, 4) {
    Some(v) => v
    None => return None
  }
  let form = raw_string(data, 8, 4)
  let limit = if 8 + declared < data.length() {
    8 + declared
  } else {
    data.length()
  }
  let chunks : Array[String] = []
  let mut pos = 12
  let mut scanned = 0
  while pos + 8 <= limit && scanned < 4096 {
    let id = raw_string(data, pos, 4)
    let size = match u32_le(data, pos + 4) {
      Some(v) => v
      None => break
    }
    chunks.push(id)
    let advance = 8 + size + (size % 2)
    if advance <= 8 {
      break
    }
    pos = pos + advance
    scanned = scanned + 1
  }
  Some({
    form,
    chunks,
    complete: chunks.length() > 0 && pos >= limit - 1,
  })
}

///|
pub fn parse_riff(data : Bytes) -> RiffInfo? {
  parse_chunk_container(data, b"RIFF")
}

///|
/// IFF（AIFF/AIFC 等）用的是 `FORM` 容器标记，chunk 布局与 RIFF 相同。
pub fn parse_iff(data : Bytes) -> RiffInfo? {
  parse_chunk_container(data, b"FORM")
}

// ---------------------------------------------------------------------------
// EBML：vint 与 DocType
// ---------------------------------------------------------------------------

///|
fn vint_length(first : Int) -> Int {
  if first >= 128 {
    1
  } else if first >= 64 {
    2
  } else if first >= 32 {
    3
  } else if first >= 16 {
    4
  } else if first >= 8 {
    5
  } else if first >= 4 {
    6
  } else if first >= 2 {
    7
  } else if first >= 1 {
    8
  } else {
    0
  }
}

///|
/// 读变长整数，返回 (原始值, 字节数)。原始值保留 marker 位。
fn read_vint(data : Bytes, offset : Int, limit : Int) -> (Int, Int)? {
  if offset < 0 || offset >= limit {
    return None
  }
  let first = data[offset].to_int()
  let n = vint_length(first)
  if n == 0 || n > 4 || offset + n > limit {
    return None
  }
  let mut value = first
  let mut i = 1
  while i < n {
    value = value * 256 + data[offset + i].to_int()
    i = i + 1
  }
  Some((value, n))
}

///|
/// 去掉 vint 的 marker 位，得到实际长度值。
fn vint_payload(value : Int, n : Int) -> Int {
  let marker = 1 << ((n - 1) * 8 + (8 - n))
  value - marker
}

///|
/// 解析 EBML 头部里的 DocType（`webm` / `matroska`）。
pub fn ebml_doctype(data : Bytes) -> String? {
  let limit = data.length()
  if limit < 4 || !match_at(data, 0, b"\x1a\x45\xdf\xa3") {
    return None
  }
  let element_id_len = match read_vint(data, 0, limit) {
    Some((_, n)) => n
    None => return None
  }
  let header_size = match read_vint(data, element_id_len, limit) {
    Some((value, n)) => vint_payload(value, n)
    None => return None
  }
  let header_size_len = match read_vint(data, element_id_len, limit) {
    Some((_, n)) => n
    None => return None
  }
  let mut pos = element_id_len + header_size_len
  let end = if pos + header_size < limit { pos + header_size } else { limit }
  let mut scanned = 0
  while pos < end && scanned < 256 {
    let (id_value, element_id_len) = match read_vint(data, pos, end) {
      Some(v) => v
      None => break
    }
    let size_pos = pos + element_id_len
    let (size_value, size_len) = match read_vint(data, size_pos, end) {
      Some(v) => v
      None => break
    }
    let payload_len = vint_payload(size_value, size_len)
    let payload = size_pos + size_len
    if payload + payload_len > end {
      break
    }
    if id_value == 0x4282 {
      return Some(raw_string(data, payload, payload_len))
    }
    pos = payload + payload_len
    scanned = scanned + 1
  }
  None
}

// ---------------------------------------------------------------------------
// TAR：header checksum
// ---------------------------------------------------------------------------

///|
/// 校验 POSIX tar header 的八进制 checksum（字段 148..155，计算时按空格处理）。
pub fn tar_checksum_ok(data : Bytes) -> Bool {
  if data.length() < 512 {
    return false
  }
  let mut stored = 0
  let mut digits = 0
  let mut i = 0
  while i < 8 {
    let b = data[148 + i].to_int()
    if b >= 48 && b <= 55 {
      stored = stored * 8 + (b - 48)
      digits = digits + 1
    } else if b != 0 && b != 32 {
      return false
    }
    i = i + 1
  }
  if digits == 0 {
    return false
  }
  let mut sum = 0
  let mut j = 0
  while j < 512 {
    if j >= 148 && j < 156 {
      sum = sum + 32
    } else {
      sum = sum + data[j].to_int()
    }
    j = j + 1
  }
  stored == sum
}

// ---------------------------------------------------------------------------
// PE：COFF / Optional Header
// ---------------------------------------------------------------------------

///|
pub struct PeInfo {
  machine : Int
  is_64 : Bool
  is_dll : Bool
  subsystem : Int
  sections : Int
}

///|
fn machine_name(machine : Int) -> String {
  match machine {
    0x014c => "i386"
    0x8664 => "x86-64"
    0x01c0 => "ARM"
    0xaa64 => "ARM64"
    _ => "unknown"
  }
}

///|
/// 解析 PE 结构。返回 `None` 表示 `e_lfanew` 指向的位置没有合法的 PE 头。
pub fn parse_pe(data : Bytes) -> PeInfo? {
  if data.length() < 64 || !match_at(data, 0, b"MZ") {
    return None
  }
  let pe_offset = match u32_le(data, 60) {
    Some(v) => v
    None => return None
  }
  if !match_at(data, pe_offset, b"PE\x00\x00") {
    return None
  }
  let machine = match u16_le(data, pe_offset + 4) {
    Some(v) => v
    None => return None
  }
  if machine_name(machine) == "unknown" {
    return None
  }
  let sections = match u16_le(data, pe_offset + 6) {
    Some(v) => v
    None => return None
  }
  let characteristics = match u16_le(data, pe_offset + 22) {
    Some(v) => v
    None => return None
  }
  let optional = pe_offset + 24
  let magic = match u16_le(data, optional) {
    Some(v) => v
    None => return None
  }
  if magic != 0x10b && magic != 0x20b {
    return None
  }
  let subsystem = match u16_le(data, optional + 68) {
    Some(v) => v
    None => return None
  }
  Some({
    machine,
    is_64: magic == 0x20b,
    is_dll: (characteristics / 8192) % 2 == 1,
    subsystem,
    sections,
  })
}

///|
pub fn pe_machine_name(info : PeInfo) -> String {
  machine_name(info.machine)
}
