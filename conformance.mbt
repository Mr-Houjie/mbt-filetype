// 一致性语料：识别行为的单一事实来源。
//
// `moon test` 与 `cmd/verify` 共用同一份用例，避免测试与自检脚本漂移。
//
// 这里刻意用「构造器」生成结构合法的容器（ZIP 中央目录、RIFF chunk、
// ISO-BMFF box、EBML vint、Ogg 页、tar header、PE 头），
// 而不是只写几个魔数字节——否则测的只是魔数表，而不是解析能力。

///|
priv struct Case {
  label : String
  expected : String
  data : Bytes
}

///|
fn hex_value(c : Char) -> Int {
  if c >= '0' && c <= '9' {
    c.to_int() - 48
  } else if c >= 'a' && c <= 'f' {
    c.to_int() - 87
  } else if c >= 'A' && c <= 'F' {
    c.to_int() - 55
  } else {
    -1
  }
}

///|
fn bytes_of_hex(hex : String) -> Bytes {
  let out : Array[Byte] = []
  let chars = hex.iter().to_array()
  let mut i = 0
  while i + 1 < chars.length() {
    let hi = hex_value(chars[i])
    let lo = hex_value(chars[i + 1])
    if hi < 0 || lo < 0 {
      break
    }
    out.push((hi * 16 + lo).to_byte())
    i = i + 2
  }
  Bytes::from_array(out.exact_view())
}

///|
fn ascii_bytes(s : String) -> Bytes {
  let out : Array[Byte] = []
  for c in s {
    out.push(c.to_int().to_byte())
  }
  Bytes::from_array(out.exact_view())
}

///|
fn concat_bytes(a : Bytes, b : Bytes) -> Bytes {
  let out : Array[Byte] = []
  let mut i = 0
  while i < a.length() {
    out.push(a[i])
    i = i + 1
  }
  let mut j = 0
  while j < b.length() {
    out.push(b[j])
    j = j + 1
  }
  Bytes::from_array(out.exact_view())
}

///|
fn bytes_to_array(data : Bytes) -> Array[Byte] {
  let out : Array[Byte] = []
  let mut i = 0
  while i < data.length() {
    out.push(data[i])
    i = i + 1
  }
  out
}

///|
fn push_u16_le(out : Array[Byte], value : Int) -> Unit {
  out.push((value % 256).to_byte())
  out.push((value / 256 % 256).to_byte())
}

///|
fn push_u32_le(out : Array[Byte], value : Int) -> Unit {
  out.push((value % 256).to_byte())
  out.push((value / 256 % 256).to_byte())
  out.push((value / 65536 % 256).to_byte())
  out.push((value / 16777216 % 256).to_byte())
}

///|
fn push_u32_be(out : Array[Byte], value : Int) -> Unit {
  out.push((value / 16777216 % 256).to_byte())
  out.push((value / 65536 % 256).to_byte())
  out.push((value / 256 % 256).to_byte())
  out.push((value % 256).to_byte())
}

///|
fn push_ascii(out : Array[Byte], text : String) -> Unit {
  for c in text {
    out.push(c.to_int().to_byte())
  }
}

///|
fn repeat_ascii(text : String, count : Int) -> String {
  let builder = StringBuilder()
  let mut i = 0
  while i < count {
    builder.write_string(text)
    i = i + 1
  }
  builder.to_string()
}

// ---------------------------------------------------------------------------
// 容器构造器
// ---------------------------------------------------------------------------

///|
/// 构造结构合法的 ZIP（全部 stored，带中央目录与 EOCD）。
fn zip_of(entries : Array[(String, String)]) -> Bytes {
  let out : Array[Byte] = []
  let local_offsets : Array[Int] = []
  for entry in entries {
    let (name, content) = entry
    let name_bytes = ascii_bytes(name)
    let data_bytes = ascii_bytes(content)
    local_offsets.push(out.length())
    // local file header
    push_u32_le(out, 0x04034b50)
    push_u16_le(out, 20)
    push_u16_le(out, 0)
    push_u16_le(out, 0)
    push_u16_le(out, 0)
    push_u16_le(out, 0)
    push_u32_le(out, 0)
    push_u32_le(out, data_bytes.length())
    push_u32_le(out, data_bytes.length())
    push_u16_le(out, name_bytes.length())
    push_u16_le(out, 0)
    push_ascii(out, name)
    for b in bytes_to_array(data_bytes) {
      out.push(b)
    }
  }
  let cd_start = out.length()
  let mut i = 0
  while i < entries.length() {
    let (name, content) = entries[i]
    let name_bytes = ascii_bytes(name)
    let data_bytes = ascii_bytes(content)
    push_u32_le(out, 0x02014b50)
    push_u16_le(out, 20)
    push_u16_le(out, 20)
    push_u16_le(out, 0)
    push_u16_le(out, 0)
    push_u16_le(out, 0)
    push_u16_le(out, 0)
    push_u32_le(out, 0)
    push_u32_le(out, data_bytes.length())
    push_u32_le(out, data_bytes.length())
    push_u16_le(out, name_bytes.length())
    push_u16_le(out, 0)
    push_u16_le(out, 0)
    push_u16_le(out, 0)
    push_u16_le(out, 0)
    push_u32_le(out, 0)
    push_u32_le(out, local_offsets[i])
    push_ascii(out, name)
    i = i + 1
  }
  let cd_size = out.length() - cd_start
  push_u32_le(out, 0x06054b50)
  push_u16_le(out, 0)
  push_u16_le(out, 0)
  push_u16_le(out, entries.length())
  push_u16_le(out, entries.length())
  push_u32_le(out, cd_size)
  push_u32_le(out, cd_start)
  push_u16_le(out, 0)
  Bytes::from_array(out.exact_view())
}

///|
fn riff_bytes(tag : String, form : String, chunks : Array[(String, Int)]) -> Bytes {
  let body : Array[Byte] = []
  for chunk in chunks {
    let (id, size) = chunk
    push_ascii(body, id)
    push_u32_le(body, size)
    let mut i = 0
    while i < size {
      body.push((0).to_byte())
      i = i + 1
    }
    if size % 2 == 1 {
      body.push((0).to_byte())
    }
  }
  let out : Array[Byte] = []
  push_ascii(out, tag)
  push_u32_le(out, 4 + body.length())
  push_ascii(out, form)
  for b in body {
    out.push(b)
  }
  Bytes::from_array(out.exact_view())
}

///|
fn bmff_box(typ : String, payload : Bytes) -> Bytes {
  let out : Array[Byte] = []
  push_u32_be(out, 8 + payload.length())
  push_ascii(out, typ)
  for b in bytes_to_array(payload) {
    out.push(b)
  }
  Bytes::from_array(out.exact_view())
}

///|
fn ftyp_bytes(major : String) -> Bytes {
  let out : Array[Byte] = []
  push_u32_be(out, 16)
  push_ascii(out, "ftyp")
  push_ascii(out, major)
  push_u32_be(out, 0)
  Bytes::from_array(out.exact_view())
}

///|
fn hdlr_bytes(handler : String) -> Bytes {
  let out : Array[Byte] = []
  push_u32_be(out, 0)
  push_u32_be(out, 0)
  push_ascii(out, handler)
  push_u32_be(out, 0)
  push_u32_be(out, 0)
  push_u32_be(out, 0)
  out.push((0).to_byte())
  Bytes::from_array(out.exact_view())
}

///|
/// ftyp + moov/trak/mdia/hdlr，用来验证真正的 box 树下钻。
fn bmff_with_handler(brand : String, handler : String) -> Bytes {
  let hdlr = bmff_box("hdlr", hdlr_bytes(handler))
  let mdia = bmff_box("mdia", hdlr)
  let trak = bmff_box("trak", mdia)
  let moov = bmff_box("moov", trak)
  concat_bytes(concat_bytes(ftyp_bytes(brand), moov), b"")
}

///|
/// EBML 头 + DocType 元素（vint 编码）。
fn ebml_bytes(doc_type : String) -> Bytes {
  let payload : Array[Byte] = []
  payload.push((66).to_byte()) // 0x42
  payload.push((130).to_byte()) // 0x82
  // DocType 长度用 1 字节 vint：0x80 | len
  payload.push((128 + doc_type.length()).to_byte())
  push_ascii(payload, doc_type)
  let out : Array[Byte] = []
  out.push((26).to_byte()) // EBML ID 1A
  out.push((69).to_byte()) // 45
  out.push((223).to_byte()) // DF
  out.push((163).to_byte()) // A3
  out.push((128 + payload.length()).to_byte())
  for b in payload {
    out.push(b)
  }
  Bytes::from_array(out.exact_view())
}

///|
fn tar_bytes() -> Bytes {
  let out : Array[Byte] = []
  let mut i = 0
  while i < 512 {
    out.push((0).to_byte())
    i = i + 1
  }
  let name = ascii_bytes("sample.txt")
  let mut j = 0
  while j < name.length() {
    out[j] = name[j]
    j = j + 1
  }
  // mode = 0000644
  let mode = ascii_bytes("0000644")
  let mut k = 0
  while k < mode.length() {
    out[100 + k] = mode[k]
    k = k + 1
  }
  // size = 00000000000
  let size = ascii_bytes("00000000000")
  let mut s = 0
  while s < size.length() {
    out[124 + s] = size[s]
    s = s + 1
  }
  // magic "ustar\0" + version "00"
  let magic = ascii_bytes("ustar")
  let mut m = 0
  while m < magic.length() {
    out[257 + m] = magic[m]
    m = m + 1
  }
  out[262] = (0).to_byte()
  out[263] = (48).to_byte()
  out[264] = (48).to_byte()
  // chksum：先按空格计算，再写回 6 位八进制 + NUL + 空格
  let mut sum = 0
  let mut c = 0
  while c < 512 {
    if c >= 148 && c < 156 {
      sum = sum + 32
    } else {
      sum = sum + out[c].to_int()
    }
    c = c + 1
  }
  let digits : Array[Int] = []
  let mut value = sum
  let mut d = 0
  while d < 6 {
    digits.push(value % 8)
    value = value / 8
    d = d + 1
  }
  let mut e = 0
  while e < 6 {
    out[148 + e] = (48 + digits[5 - e]).to_byte()
    e = e + 1
  }
  out[154] = (0).to_byte()
  out[155] = (32).to_byte()
  Bytes::from_array(out.exact_view())
}

///|
fn pe_bytes() -> Bytes {
  let out : Array[Byte] = []
  let mut i = 0
  while i < 512 {
    out.push((0).to_byte())
    i = i + 1
  }
  // MZ
  out[0] = (77).to_byte()
  out[1] = (90).to_byte()
  // e_lfanew = 128（小端）
  out[60] = (128).to_byte()
  out[61] = (0).to_byte()
  out[62] = (0).to_byte()
  out[63] = (0).to_byte()
  // PE\0\0
  out[128] = (80).to_byte()
  out[129] = (69).to_byte()
  // machine = 0x8664 (x86-64)
  out[132] = (0x64).to_byte()
  out[133] = (0x86).to_byte()
  // numberOfSections = 3
  out[134] = (3).to_byte()
  // characteristics = 0x0022
  out[150] = (0x22).to_byte()
  // optional header magic = 0x20b (PE32+)
  out[152] = (0x0b).to_byte()
  out[153] = (0x02).to_byte()
  // subsystem = 3（console）
  out[220] = (3).to_byte()
  Bytes::from_array(out.exact_view())
}

///|
fn iso_bytes() -> Bytes {
  let out : Array[Byte] = []
  let mut i = 0
  while i < 32774 {
    out.push((0).to_byte())
    i = i + 1
  }
  out[32769] = (67).to_byte()
  out[32770] = (68).to_byte()
  out[32771] = (48).to_byte()
  out[32772] = (48).to_byte()
  out[32773] = (49).to_byte()
  Bytes::from_array(out.exact_view())
}

///|
fn ts_bytes() -> Bytes {
  let out : Array[Byte] = []
  let mut i = 0
  while i < 377 {
    out.push((0).to_byte())
    i = i + 1
  }
  out[0] = (71).to_byte()
  out[188] = (71).to_byte()
  out[376] = (71).to_byte()
  Bytes::from_array(out.exact_view())
}

///|
fn mobi_bytes() -> Bytes {
  let out : Array[Byte] = []
  let mut i = 0
  while i < 60 {
    out.push((0).to_byte())
    i = i + 1
  }
  for c in "BOOKMOBI" {
    out.push(c.to_int().to_byte())
  }
  Bytes::from_array(out.exact_view())
}

///|
/// 结构合法的 Ogg 页：page_segments = 1，首段长度 19，首包以 OpusHead 开头。
fn ogg_opus_bytes() -> Bytes {
  let out : Array[Byte] = []
  push_ascii(out, "OggS")
  let mut i = 0
  while i < 22 {
    out.push((0).to_byte())
    i = i + 1
  }
  out.push((1).to_byte()) // 偏移 26：page_segments
  out.push((19).to_byte()) // 偏移 27：首段长度
  push_ascii(out, "OpusHead")
  let mut j = 0
  while j < 11 {
    out.push((0).to_byte())
    j = j + 1
  }
  Bytes::from_array(out.exact_view())
}

///|
fn set_u16_le(out : Array[Byte], offset : Int, value : Int) -> Unit {
  out[offset] = (value % 256).to_byte()
  out[offset + 1] = (value / 256 % 256).to_byte()
}

///|
fn set_u32_le(out : Array[Byte], offset : Int, value : Int) -> Unit {
  out[offset] = (value % 256).to_byte()
  out[offset + 1] = (value / 256 % 256).to_byte()
  out[offset + 2] = (value / 65536 % 256).to_byte()
  out[offset + 3] = (value / 16777216 % 256).to_byte()
}

///|
/// 写一个 128 字节的 OLE2 目录项：UTF-16LE 名称 + 名称长度 + 类型。
fn write_dir_entry(
  out : Array[Byte],
  base : Int,
  name : String,
  kind : Int,
) -> Unit {
  let mut i = 0
  while i < 128 {
    out[base + i] = (0).to_byte()
    i = i + 1
  }
  let name_bytes : Array[Byte] = []
  for c in name {
    let code = c.to_int()
    name_bytes.push((code % 256).to_byte())
    name_bytes.push((code / 256 % 256).to_byte())
  }
  let mut j = 0
  while j < name_bytes.length() && j < 64 {
    out[base + j] = name_bytes[j]
    j = j + 1
  }
  // 名称长度包含结尾的 NUL（2 字节）
  set_u16_le(out, base + 64, name_bytes.length() + 2)
  out[base + 66] = kind.to_byte()
}

///|
/// 构造结构合法的 OLE2 复合文档：
/// 512 字节 header + 1 个 FAT 扇区 + 1 个目录扇区，目录里放一个指定名称的流。
fn ole2_bytes(stream_name : String) -> Bytes {
  let out : Array[Byte] = []
  let mut i = 0
  while i < 1536 {
    out.push((0).to_byte())
    i = i + 1
  }
  // 头部 magic
  out[0] = (0xd0).to_byte()
  out[1] = (0xcf).to_byte()
  out[2] = (0x11).to_byte()
  out[3] = (0xe0).to_byte()
  out[4] = (0xa1).to_byte()
  out[5] = (0xb1).to_byte()
  out[6] = (0x1a).to_byte()
  out[7] = (0xe1).to_byte()
  set_u16_le(out, 26, 3) // major version
  set_u16_le(out, 28, 0xfffe) // byte order
  set_u16_le(out, 30, 9) // sector shift -> 512
  set_u16_le(out, 32, 6) // mini sector shift
  set_u32_le(out, 44, 1) // FAT 扇区数
  set_u32_le(out, 48, 1) // 目录起始扇区
  set_u32_le(out, 56, 4096) // mini stream cutoff
  // 60..76：mini FAT / DIFAT 均置为 ENDOFCHAIN 或 0
  out[60] = (0xfe).to_byte()
  out[61] = (0xff).to_byte()
  out[62] = (0xff).to_byte()
  out[63] = (0xff).to_byte()
  out[68] = (0xfe).to_byte()
  out[69] = (0xff).to_byte()
  out[70] = (0xff).to_byte()
  out[71] = (0xff).to_byte()
  set_u32_le(out, 76, 0) // DIFAT[0] = FAT 扇区 0
  // 其余 DIFAT 位置填 FREESECT
  let mut d = 80
  while d < 512 {
    out[d] = (0xff).to_byte()
    d = d + 1
  }
  // 扇区 0：FAT
  out[512] = (0xfd).to_byte() // [0] = FATSECT
  out[513] = (0xff).to_byte()
  out[514] = (0xff).to_byte()
  out[515] = (0xff).to_byte()
  out[516] = (0xfe).to_byte() // [1] = ENDOFCHAIN（目录链到此结束）
  out[517] = (0xff).to_byte()
  out[518] = (0xff).to_byte()
  out[519] = (0xff).to_byte()
  let mut f = 520
  while f < 1024 {
    out[f] = (0xff).to_byte()
    f = f + 1
  }
  // 扇区 1：目录（4 个 128 字节目录项）
  write_dir_entry(out, 1024, "Root Entry", 5)
  write_dir_entry(out, 1152, stream_name, 2)
  Bytes::from_array(out.exact_view())
}

///|
fn case_hex(label : String, expected : String, hex : String) -> Case {
  { label, expected, data: bytes_of_hex(hex), }
}

///|
fn make_cases() -> Array[Case] {
  let cases : Array[Case] = [
    // 图片
    case_hex("png", "png", "89504e470d0a1a0a0000000d49484452"),
    case_hex("jpeg", "jpeg", "ffd8ffe000104a46494600010100000100010000"),
    case_hex("gif87a", "gif", "47494638376101000100"),
    case_hex("gif89a", "gif", "47494638396101000100"),
    case_hex("tiff-le", "tiff", "49492a000800000000000000"),
    case_hex("tiff-be", "tiff", "4d4d002a0000000800000000"),
    case_hex("psd", "psd", "384250530001000000000000"),
    case_hex("xcf", "xcf", "67696d70207863662000"),
    case_hex("ico", "ico", "000001000100101000000000"),
    case_hex("bmp", "bmp", "424d3600000000000000"),
    // BMP 结构有效：保留字段为 0，DIB header = 40
    case_hex("bmp-dib40", "bmp", "424d360000000000000036000000280000000100000001000000010018000000000000000000000000000000000000"),
    case_hex("jp2", "jp2", "0000000c6a5020200d0a870a00000000"),
    case_hex("jxl", "jxl", "0000000c4a584c200d0a870a00000000"),
    case_hex("icns", "icns", "69636e7300000000"),
    case_hex("cur", "cur", "000002000100101000000000"),
    case_hex("dds", "dds", "4444532000000000"),
    case_hex("ktx", "ktx", "ab4b5458203131bb0d0a1a0a"),
    case_hex("ktx2", "ktx2", "ab4b5458203230bb0d0a1a0a"),
    case_hex("exr", "exr", "762f310100000000"),
    case_hex("hdr", "hdr", "233f52414449414e43450a"),
    case_hex("pnm", "pnm", "50360a3120310a"),
    // 文档
    case_hex("pdf", "pdf", "255044462d312e370a"),
    case_hex("postscript", "postscript", "252150532d41646f62652d332e300a"),
    case_hex("rtf", "rtf", "7b5c727466315c616e7369"),
    case_hex("djvu", "djvu", "41542654464f524d00000000"),
    case_hex("ole2", "ole2", "d0cf11e0a1b11ae1"),
    case_hex(
      "pem", "pem", "2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a",
    ),
    case_hex(
      "pgp", "pgp", "2d2d2d2d2d424547494e20504750205055424c4943204b455920424c4f434b2d2d2d2d2d",
    ),
    case_hex("chm", "chm", "495453460300000060000000"),
    case_hex("pfa", "pfa", "252150532d41646f6265466f6e742d312e300a"),
    // 归档
    case_hex("zip", "zip", "504b0304"),
    case_hex("zip-empty", "zip", "504b0506"),
    case_hex("gzip", "gzip", "1f8b0800000000000003"),
    case_hex("bzip2", "bzip2", "425a6839314159265359"),
    case_hex("xz", "xz", "fd377a585a0000000000"),
    case_hex("zstd", "zstd", "28b52ffd00000000"),
    case_hex("7z", "7z", "377abcaf271c00000000"),
    case_hex("rar4", "rar", "526172211a0700"),
    case_hex("rar5", "rar", "526172211a070100"),
    case_hex("cab", "cab", "4d53434600000000"),
    case_hex("lz4", "lz4", "04224d1800000000"),
    case_hex("cpio-newc", "cpio", "30373037303130303030303030"),
    case_hex("cpio-odc", "cpio", "30373037303730303030303030"),
    case_hex("rpm", "rpm", "edabeedb00000000"),
    case_hex("deb", "deb", "213c617263683e0a64656269616e2d62696e617279"),
    case_hex("ar", "ar", "213c617263683e0a"),
    case_hex("xar", "xar", "7861722100000000"),
    case_hex("squashfs", "squashfs", "6873717300000000"),
    case_hex("crx", "crx", "4372323403000000"),
    case_hex("compress-z", "compress", "1f9d000000000000"),
    // 可执行
    case_hex("elf", "elf", "7f454c46020101000000000000000000"),
    case_hex("wasm", "wasm", "0061736d01000000"),
    case_hex("macho64", "macho", "cffaedfe0700000103000080"),
    case_hex("macho-fat", "macho", "cafebabe00000002"),
    case_hex("java-class", "class", "cafebabe0000004112340000"),
    case_hex("dex", "dex", "6465780a3033350000000000"),
    case_hex("luac", "luac", "1b4c756153000000"),
    case_hex("pcf", "pcf", "0166637000000000"),
    case_hex("bdf", "bdf", "5354415254464f4e54202d"),
    case_hex("hdf4", "hdf4", "0e03130100000000"),
    case_hex("grib", "grib", "4752494200000000"),
    case_hex("mat", "mat", "4d41544c414220352e30204d41542d66696c65"),
    case_hex("npy", "npy", "934e554d5059010000"),
    case_hex("parquet", "parquet", "5041523100000000"),
    case_hex("arrow", "arrow", "4152524f573100000000"),
    case_hex("avro", "avro", "4f626a0100000000"),
    case_hex("orc", "orc", "4f52430000000000"),
    case_hex("jks", "jks", "feedfeed00000000"),
    case_hex("pcap", "pcap", "0a0d0d0a00000000"),
    // 字体
    case_hex("ttf", "ttf", "00010000000a000000000000"),
    case_hex("otf", "otf", "4f54544f00000000"),
    case_hex("woff", "woff", "774f464600010000"),
    case_hex("woff2", "woff2", "774f463200010000"),
    case_hex("ttc", "ttc", "7474636600010000"),
    // 数据库与科学数据
    case_hex("sqlite", "sqlite", "53514c69746520666f726d6174203300"),
    case_hex("hdf5", "hdf5", "894844460d0a1a0a00000000"),
    case_hex("netcdf", "netcdf", "43444601000000000000"),
    case_hex("fits", "fits", "53494d504c4520203d20202020"),
    // 音视频
    case_hex("flac", "flac", "664c614300000022"),
    case_hex("au", "au", "2e736e640000000000000017"),
    case_hex("wavpack", "wavpack", "7776706b00000000"),
    case_hex("ape", "ape", "4d41432000000000"),
    case_hex("amr", "amr", "2321414d520a"),
    case_hex("asf", "asf", "3026b2758e66cf11a6d900aa0062ce6c"),
    case_hex("midi", "midi", "4d5468640000000600000000"),
    case_hex("mp3-id3", "mp3", "49443303000000000000"),
    // 文本启发式
    case_hex("json-object", "json", "7b2261223a317d"),
    case_hex("json-array", "json", "5b312c322c335d"),
    case_hex("xml", "xml", "3c3f786d6c2076657273696f6e3d22312e30223f3e"),
    case_hex("html", "html", "3c21444f43545950452068746d6c3e"),
    case_hex("csv", "csv", "612c622c630a312c322c330a"),
    case_hex("tsv", "tsv", "61096209630a31093209330a"),
    case_hex("plain", "text", "68656c6c6f0a"),
    case_hex("plain-utf8", "text", "e4b8ade696870a"),
    // 未知
    case_hex("empty", "unknown", ""),
    case_hex("unknown-nul", "unknown", "00010203"),
    case_hex("unknown-ff", "unknown", "ffffffffffffffff"),
    case_hex("unknown-invalid-utf8", "unknown", "c0c1c2c3"),
    // 结构合法性要求：短样本不能凭魔数就被认成容器
    case_hex("truncated-png", "unknown", "89504e47"),
    // 对抗样本：文本内容长得像弱签名的格式
    case_hex(
      "bmp-lookalike-text",
      "text",
      "424d57203332306920e8bda6e4b8bbe6898be5868c20e4bdbfe794a8e8afb4e6988e20e8afb7e58bbfe794a8e58a9b0a",
    ),
    case_hex(
      "mz-lookalike-text",
      "text",
      "4d5a20e698afe58e8be7bca9e6a0bce5bc8fe6a087e8aeb00a",
    ),
  ]
  // Ogg / EBML / RIFF / IFF / ISO-BMFF / tar / PE / ISO / TS
  cases.push({ label: "ogg-opus", expected: "opus", data: ogg_opus_bytes(), })
  cases.push({ label: "webm", expected: "webm", data: ebml_bytes("webm"), })
  cases.push({
    label: "matroska",
    expected: "mkv",
    data: ebml_bytes("matroska"),
  })
  cases.push({
    label: "wav",
    expected: "wav",
    data: riff_bytes("RIFF", "WAVE", [("fmt ", 16), ("data", 0)]),
  })
  cases.push({
    label: "avi",
    expected: "avi",
    data: riff_bytes("RIFF", "AVI ", [("hdrl", 4), ("movi", 0)]),
  })
  cases.push({
    label: "webp",
    expected: "webp",
    data: riff_bytes("RIFF", "WEBP", [("VP8 ", 4)]),
  })
  cases.push({
    label: "aiff",
    expected: "aiff",
    data: riff_bytes("FORM", "AIFF", [("COMM", 18)]),
  })
  cases.push({
    label: "aifc",
    expected: "aiff",
    data: riff_bytes("FORM", "AIFC", [("COMM", 18)]),
  })
  cases.push({ label: "tar", expected: "tar", data: tar_bytes(), })
  // OLE2：目录项里的流名决定 doc / xls / ppt
  cases.push({
    label: "ole2-doc",
    expected: "doc",
    data: ole2_bytes("WordDocument"),
  })
  cases.push({ label: "ole2-xls", expected: "xls", data: ole2_bytes("Workbook") })
  cases.push({
    label: "ole2-ppt",
    expected: "ppt",
    data: ole2_bytes("PowerPoint Document"),
  })
  cases.push({
    label: "ole2-unknown-stream",
    expected: "ole2",
    data: ole2_bytes("SummaryInformation"),
  })
  // 对抗样本：流名只是前缀相似，不能当成 doc
  cases.push({
    label: "ole2-lookalike-stream",
    expected: "ole2",
    data: ole2_bytes("WordDocumentBackup"),
  })
  cases.push({ label: "pe", expected: "pe", data: pe_bytes(), })
  cases.push({ label: "mobi", expected: "mobi", data: mobi_bytes(), })
  cases.push({ label: "iso9660", expected: "iso", data: iso_bytes(), })
  cases.push({ label: "mpeg-ts", expected: "ts", data: ts_bytes(), })
  // ISO-BMFF：brand 判定
  cases.push({ label: "m4a", expected: "m4a", data: ftyp_bytes("M4A "), })
  cases.push({ label: "3gp", expected: "3gp", data: ftyp_bytes("3gp4"), })
  cases.push({ label: "avif", expected: "avif", data: ftyp_bytes("avif"), })
  cases.push({ label: "heic", expected: "heic", data: ftyp_bytes("heic"), })
  cases.push({ label: "mov-qt", expected: "mov", data: ftyp_bytes("qt  "), })
  cases.push({ label: "mp4-isom", expected: "mp4", data: ftyp_bytes("isom"), })
  // ISO-BMFF：handler 下钻
  cases.push({
    label: "mp4-hdlr-vide",
    expected: "mp4",
    data: bmff_with_handler("isom", "vide"),
  })
  cases.push({
    label: "m4a-hdlr-soun",
    expected: "m4a",
    data: bmff_with_handler("isom", "soun"),
  })
  // ZIP：结构 + 规范约束
  cases.push({
    label: "zip-docx",
    expected: "docx",
    data: zip_of([
      ("[Content_Types].xml", "<Types/>"), ("word/document.xml", "<w:document/>"),
    ]),
  })
  cases.push({
    label: "zip-xlsx",
    expected: "xlsx",
    data: zip_of([
      ("[Content_Types].xml", "<Types/>"), ("xl/workbook.xml", "<workbook/>"),
    ]),
  })
  cases.push({
    label: "zip-pptx",
    expected: "pptx",
    data: zip_of([
      ("[Content_Types].xml", "<Types/>"),
      ("ppt/presentation.xml", "<p:presentation/>"),
    ]),
  })
  cases.push({
    label: "zip-epub",
    expected: "epub",
    data: zip_of([
      ("mimetype", "application/epub+zip"), ("META-INF/container.xml", "<container/>"),
    ]),
  })
  cases.push({
    label: "zip-odt",
    expected: "odt",
    data: zip_of([
      ("mimetype", "application/vnd.oasis.opendocument.text"),
      ("content.xml", "<office/>"),
    ]),
  })
  cases.push({
    label: "zip-ods",
    expected: "ods",
    data: zip_of([
      ("mimetype", "application/vnd.oasis.opendocument.spreadsheet"),
      ("content.xml", "<office/>"),
    ]),
  })
  cases.push({
    label: "zip-odp",
    expected: "odp",
    data: zip_of([
      ("mimetype", "application/vnd.oasis.opendocument.presentation"),
      ("content.xml", "<office/>"),
    ]),
  })
  cases.push({
    label: "zip-xps",
    expected: "xps",
    data: zip_of([("FixedDocSeq.fdseq", "<FixedDocumentSequence/>")]),
  })
  cases.push({
    label: "zip-apk",
    expected: "apk",
    data: zip_of([("AndroidManifest.xml", ""), ("classes.dex", "")]),
  })
  cases.push({
    label: "zip-jar",
    expected: "jar",
    data: zip_of([("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")]),
  })
  // 对抗样本：容器里出现字符串，但结构不成立
  cases.push({
    label: "zip-with-word-in-content",
    expected: "zip",
    data: zip_of([
      ("notes.txt", "see word/document.xml and xl/workbook.xml for details"),
    ]),
  })
  cases.push({
    label: "zip-epub-string-in-content",
    expected: "zip",
    data: zip_of([("notes.txt", "application/epub+zip")]),
  })
  cases.push({
    label: "zip-ooxml-without-content-types",
    expected: "zip",
    data: zip_of([("word/document.xml", "<w:document/>")]),
  })
  cases.push({
    label: "zip-mimetype-not-first",
    expected: "zip",
    data: zip_of([
      ("README.txt", "hi"), ("mimetype", "application/epub+zip"),
    ]),
  })
  // 中央目录在 64 KiB 之后：字符串扫描会漏，结构解析不会
  cases.push({
    label: "zip-docx-beyond-64k",
    expected: "docx",
    data: zip_of([
      ("padding.bin", repeat_ascii("A", 70000)),
      ("[Content_Types].xml", "<Types/>"),
      ("word/document.xml", "<w:document/>"),
    ]),
  })
  cases
}

///|
fn actual_id(detection : Detection) -> String {
  match detection.file_type {
    Some(file_type) => file_type.id
    None => "unknown"
  }
}

///|
/// 一致性语料总条数。
pub fn conformance_case_count() -> Int {
  make_cases().length()
}

///|
/// 运行一致性语料，返回失败描述（空数组表示全部通过）。
pub fn run_conformance() -> Array[String] {
  let failures : Array[String] = []
  for case in make_cases() {
    let detection = detect(case.data)
    let actual = actual_id(detection)
    if actual != case.expected {
      failures.push(
        "\{case.label}: expected \{case.expected}, got \{actual} (\{detection.reason})",
      )
    }
  }
  failures
}
