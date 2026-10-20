// 一致性语料：识别行为的单一事实来源。
//
// `moon test` 与 `cmd/verify` 共用同一份用例，避免测试与自检脚本漂移。

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
fn zip_with(entry : String) -> Bytes {
  concat_bytes(b"PK\x03\x04", ascii_bytes(entry))
}

///|
fn tar_bytes() -> Bytes {
  let out : Array[Byte] = []
  let mut i = 0
  while i < 257 {
    out.push((0).to_byte())
    i = i + 1
  }
  for c in "ustar" {
    out.push(c.to_int().to_byte())
  }
  Bytes::from_array(out.exact_view())
}

///|
fn pe_bytes() -> Bytes {
  let out : Array[Byte] = []
  let mut i = 0
  while i < 128 {
    out.push((0).to_byte())
    i = i + 1
  }
  out[0] = (77).to_byte()
  out[1] = (90).to_byte()
  out[60] = (64).to_byte()
  out[64] = (80).to_byte()
  out[65] = (69).to_byte()
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
    case_hex("aiff", "aiff", "464f524d0000000041494646464f524d"),
    case_hex("aifc", "aiff", "464f524d0000000041494643464f524d"),
    case_hex("au", "au", "2e736e640000000000000017"),
    case_hex("wavpack", "wavpack", "7776706b00000000"),
    case_hex("ape", "ape", "4d41432000000000"),
    case_hex("amr", "amr", "2321414d520a"),
    case_hex("m4a", "m4a", "0000001c667479704d34412000000200"),
    case_hex("3gp", "3gp", "00000018667479703367703400000000"),
    case_hex("asf", "asf", "3026b2758e66cf11a6d900aa0062ce6c"),
    case_hex("ogg", "ogg", "4f6767530002000000000000"),
    case_hex("midi", "midi", "4d5468640000000600000000"),
    case_hex("mp3-id3", "mp3", "49443303000000000000"),
    case_hex("mp4-isom", "mp4", "000000186674797069736f6d00000200"),
    case_hex("mp4-avif", "avif", "000000186674797061766966"),
    case_hex("mp4-heic", "heic", "000000186674797068656963"),
    case_hex("mov-qt", "mov", "00000014667479707174202000000000"),
    case_hex("wav", "wav", "524946462400000057415645666d7420"),
    case_hex("webp", "webp", "52494646240000005745425056503820"),
    case_hex("avi", "avi", "52494646240000004156492000000000"),
    case_hex("ebml", "ebml", "1a45dfa3"),
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
  ]
  cases.push({ label: "tar", expected: "tar", data: tar_bytes(), })
  cases.push({ label: "pe", expected: "pe", data: pe_bytes(), })
  cases.push({ label: "mobi", expected: "mobi", data: mobi_bytes(), })
  cases.push({ label: "iso9660", expected: "iso", data: iso_bytes(), })
  cases.push({ label: "mpeg-ts", expected: "ts", data: ts_bytes(), })
  cases.push({
    label: "ogg-opus",
    expected: "opus",
    data: concat_bytes(b"OggS", ascii_bytes("OpusHead")),
  })
  cases.push({
    label: "zip-docx",
    expected: "docx",
    data: zip_with("word/document.xml"),
  })
  cases.push({
    label: "zip-xlsx",
    expected: "xlsx",
    data: zip_with("xl/workbook.xml"),
  })
  cases.push({
    label: "zip-pptx",
    expected: "pptx",
    data: zip_with("ppt/presentation.xml"),
  })
  cases.push({
    label: "zip-epub",
    expected: "epub",
    data: zip_with("application/epub+zip"),
  })
  cases.push({
    label: "zip-apk",
    expected: "apk",
    data: zip_with("AndroidManifest.xml"),
  })
  cases.push({
    label: "zip-jar",
    expected: "jar",
    data: zip_with("META-INF/MANIFEST.MF"),
  })
  cases.push({
    label: "zip-odt",
    expected: "odt",
    data: zip_with("application/vnd.oasis.opendocument.text"),
  })
  cases.push({
    label: "zip-ods",
    expected: "ods",
    data: zip_with("application/vnd.oasis.opendocument.spreadsheet"),
  })
  cases.push({
    label: "zip-odp",
    expected: "odp",
    data: zip_with("application/vnd.oasis.opendocument.presentation"),
  })
  cases.push({
    label: "zip-xps",
    expected: "xps",
    data: zip_with("FixedDocSeq.fdseq"),
  })
  cases.push({
    label: "webm",
    expected: "webm",
    data: concat_bytes(b"\x1a\x45\xdf\xa3", ascii_bytes("webm")),
  })
  cases.push({
    label: "matroska",
    expected: "mkv",
    data: concat_bytes(b"\x1a\x45\xdf\xa3", ascii_bytes("matroska")),
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
