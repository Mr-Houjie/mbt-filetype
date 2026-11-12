// 黑盒测试：只通过公开 API 使用本库。
//
// 识别行为的主体由 `conformance.mbt` 的一致性语料覆盖；
// 这里补充边界输入、证据字段、渲染输出与「任意字节不 panic」检查。

///|
fn bytes_of_hex(hex : String) -> Bytes {
  let out : Array[Byte] = []
  let chars = hex.iter().to_array()
  let mut i = 0
  while i + 1 < chars.length() {
    let high = hex_digit(chars[i])
    let low = hex_digit(chars[i + 1])
    if high < 0 || low < 0 {
      break
    }
    out.push((high * 16 + low).to_byte())
    i = i + 2
  }
  Bytes::from_array(out.exact_view())
}

///|
fn hex_digit(c : Char) -> Int {
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
test "conformance: 全部内置语料通过" {
  let failures = @Mr-Houjie/mbt-filetype.run_conformance()
  for failure in failures {
    println("FAIL \{failure}")
  }
  assert_eq(failures.length(), 0)
  assert_true(@Mr-Houjie/mbt-filetype.conformance_case_count() >= 120)
}

///|
test "类型清单完整且唯一" {
  let types = @Mr-Houjie/mbt-filetype.known_types()
  assert_true(types.length() >= 90)
  let mut i = 0
  while i < types.length() {
    let mut j = i + 1
    while j < types.length() {
      assert_true(types[i].id != types[j].id)
      j = j + 1
    }
    i = i + 1
  }
  let rendered = @Mr-Houjie/mbt-filetype.render_types()
  assert_true(rendered.contains("tsv"))
  assert_true(rendered.contains("opus"))
  assert_true(rendered.contains("wasm"))
}

///|
test "边界输入" {
  let empty = @Mr-Houjie/mbt-filetype.detect(b"")
  match empty.file_type {
    Some(_) => assert_true(false)
    None => assert_eq(empty.reason, "空输入")
  }
  let truncated = @Mr-Houjie/mbt-filetype.detect(b"\x89PNG")
  let truncated_is_unknown = match truncated.file_type {
    None => true
    Some(_) => false
  }
  assert_true(truncated_is_unknown)
}

///|
test "置信度与证据字段" {
  let png = @Mr-Houjie/mbt-filetype.detect(bytes_of_hex("89504e470d0a1a0a"))
  assert_eq(@Mr-Houjie/mbt-filetype.confidence_name(png.confidence), "certain")
  assert_eq(png.offset, 0)
  assert_eq(png.matched_len, 8)
  let ole = @Mr-Houjie/mbt-filetype.detect(bytes_of_hex("d0cf11e0a1b11ae1"))
  assert_eq(ole.candidates.length(), 3)
  assert_true(ole.reason.contains("OLE2"))
  let asf = @Mr-Houjie/mbt-filetype.detect(
    bytes_of_hex("3026b2758e66cf11a6d900aa0062ce6c"),
  )
  assert_eq(asf.candidates.length(), 2)
  let bmp = @Mr-Houjie/mbt-filetype.detect(bytes_of_hex("424d36000000"))
  assert_eq(@Mr-Houjie/mbt-filetype.confidence_name(bmp.confidence), "probable")
}

///|
test "输出渲染" {
  let png = @Mr-Houjie/mbt-filetype.detect(bytes_of_hex("89504e470d0a1a0a"))
  let text = @Mr-Houjie/mbt-filetype.render_text("a.png", png, true)
  assert_true(text.contains("type:       png"))
  assert_true(text.contains("mime:       image/png"))
  assert_true(text.contains("offset:     0"))
  let json = @Mr-Houjie/mbt-filetype.render_json("a.png", png)
  assert_true(json.contains("\"type\":\"png\""))
  assert_true(json.contains("\"confidence\":\"certain\""))
  assert_true(json.contains("\"candidates\":[]"))
  let types = @Mr-Houjie/mbt-filetype.render_types()
  assert_true(types.contains("png"))
  assert_true(types.contains("docx"))
  let unknown = @Mr-Houjie/mbt-filetype.detect(b"")
  let unknown_text = @Mr-Houjie/mbt-filetype.render_text(
    "x.bin", unknown, false,
  )
  assert_true(unknown_text.contains("type:       unknown"))
  let unknown_json = @Mr-Houjie/mbt-filetype.render_json("x.bin", unknown)
  assert_true(unknown_json.contains("\"type\":\"unknown\""))
  assert_true(unknown_json.contains("\"confidence\":\"unknown\""))
}

///|
test "任意字节输入不 panic（固定种子 fuzz）" {
  let mut state = 20261020
  let mut round = 0
  while round < 2000 {
    state = state * 48271 % 2147483647
    let length = state % 65
    let out : Array[Byte] = []
    let mut i = 0
    while i < length {
      state = state * 48271 % 2147483647
      out.push((state % 256).to_byte())
      i = i + 1
    }
    let detection = @Mr-Houjie/mbt-filetype.detect(
      Bytes::from_array(out.exact_view()),
    )
    assert_true(detection.reason.length() > 0)
    round = round + 1
  }
}

// ---------------------------------------------------------------------------
// 回归测试：验收反馈里的整数溢出、IFF 大端与截断判定
// ---------------------------------------------------------------------------

///|
fn push_u8(out : Array[Byte], value : Int) -> Unit {
  out.push((value & 0xff).to_byte())
}

///|
fn push_u16_le(out : Array[Byte], value : Int) -> Unit {
  push_u8(out, value & 0xff)
  push_u8(out, (value >> 8) & 0xff)
}

///|
fn push_u32_le(out : Array[Byte], value : Int) -> Unit {
  push_u8(out, value & 0xff)
  push_u8(out, (value >> 8) & 0xff)
  push_u8(out, (value >> 16) & 0xff)
  push_u8(out, (value >> 24) & 0xff)
}

///|
fn push_u32_be(out : Array[Byte], value : Int) -> Unit {
  push_u8(out, (value >> 24) & 0xff)
  push_u8(out, (value >> 16) & 0xff)
  push_u8(out, (value >> 8) & 0xff)
  push_u8(out, value & 0xff)
}

///|
fn push_all(out : Array[Byte], data : Bytes) -> Unit {
  let mut i = 0
  while i < data.length() {
    out.push(data[i])
    i = i + 1
  }
}

///|
fn as_bytes(out : Array[Byte]) -> Bytes {
  Bytes::from_array(out.exact_view())
}

///|
/// ASCII 字符串转字节。不能用 `String::to_bytes()`——它按 UTF-16LE 编码。
fn ascii_bytes(s : String) -> Bytes {
  let out : Array[Byte] = []
  for c in s {
    out.push(c.to_int().to_byte())
  }
  as_bytes(out)
}

///|
/// 构造 64 字节的 MZ 文件，`e_lfanew` 由参数指定。
fn mz_with_lfanew(value : Int) -> Bytes {
  let out : Array[Byte] = []
  for i = 0; i < 64; i = i + 1 {
    out.push(b'\x00')
  }
  out[0] = b'M'
  out[1] = b'Z'
  push_u32_le_at(out, 60, value)
  as_bytes(out)
}

///|
fn push_u32_le_at(out : Array[Byte], offset : Int, value : Int) -> Unit {
  out[offset] = (value & 0xff).to_byte()
  out[offset + 1] = ((value >> 8) & 0xff).to_byte()
  out[offset + 2] = ((value >> 16) & 0xff).to_byte()
  out[offset + 3] = ((value >> 24) & 0xff).to_byte()
}

///|
/// 构造单条目 stored ZIP；`local_offset` 可注入非法值，`declared` 可虚报条目数。
fn stored_zip(
  name : String,
  content : String,
  local_offset : Int,
  declared : Int,
) -> Bytes {
  let out : Array[Byte] = []
  let name_bytes = ascii_bytes(name)
  let content_bytes = ascii_bytes(content)
  // 本地文件头
  push_all(out, b"PK\x03\x04")
  push_u16_le(out, 20)
  push_u16_le(out, 0)
  push_u16_le(out, 0)
  push_u16_le(out, 0)
  push_u16_le(out, 0)
  push_u32_le(out, 0)
  push_u32_le(out, content_bytes.length())
  push_u32_le(out, content_bytes.length())
  push_u16_le(out, name_bytes.length())
  push_u16_le(out, 0)
  push_all(out, name_bytes)
  push_all(out, content_bytes)
  // 中央目录
  let cd_offset = out.length()
  push_all(out, b"PK\x01\x02")
  push_u16_le(out, 20)
  push_u16_le(out, 20)
  push_u16_le(out, 0)
  push_u16_le(out, 0)
  push_u16_le(out, 0)
  push_u16_le(out, 0)
  push_u32_le(out, 0)
  push_u32_le(out, content_bytes.length())
  push_u32_le(out, content_bytes.length())
  push_u16_le(out, name_bytes.length())
  push_u16_le(out, 0)
  push_u16_le(out, 0)
  push_u16_le(out, 0)
  push_u16_le(out, 0)
  push_u32_le(out, 0)
  push_u32_le(out, local_offset)
  push_all(out, name_bytes)
  let cd_size = out.length() - cd_offset
  // EOCD
  push_all(out, b"PK\x05\x06")
  push_u16_le(out, 0)
  push_u16_le(out, 0)
  push_u16_le(out, declared)
  push_u16_le(out, declared)
  push_u32_le(out, cd_size)
  push_u32_le(out, cd_offset)
  push_u16_le(out, 0)
  as_bytes(out)
}

///|
test "回归：e_lfanew 极大值不得 panic，也不得误报为合法 PE" {
  let values = [
    0x7ffffffc, 0x7ffffffd, 0x7ffffffe, 0x7fffffff, 0x80000000, 0xffffffff,
  ]
  for value in values {
    let detection = @Mr-Houjie/mbt-filetype.detect(mz_with_lfanew(value))
    match detection.file_type {
      Some(file_type) => assert_eq(file_type.id, "pe")
      None => assert_true(false)
    }
    assert_eq(
      @Mr-Houjie/mbt-filetype.confidence_name(detection.confidence),
      "probable",
    )
  }
}

///|
test "回归：ZIP 中央目录里的巨大 local header 偏移不得 panic" {
  let detection = @Mr-Houjie/mbt-filetype.detect(
    stored_zip("mimetype", "application/epub+zip", 0x7fffffff, 1),
  )
  match detection.file_type {
    Some(file_type) => assert_eq(file_type.id, "zip")
    None => assert_true(false)
  }
  assert_eq(
    @Mr-Houjie/mbt-filetype.confidence_name(detection.confidence),
    "probable",
  )
}

///|
test "回归：合法 ZIP 仍判定为 EPUB 且为 certain" {
  let detection = @Mr-Houjie/mbt-filetype.detect(
    stored_zip("mimetype", "application/epub+zip", 0, 1),
  )
  match detection.file_type {
    Some(file_type) => assert_eq(file_type.id, "epub")
    None => assert_true(false)
  }
  assert_eq(
    @Mr-Houjie/mbt-filetype.confidence_name(detection.confidence),
    "certain",
  )
}

///|
test "回归：EOCD 虚报条目数时降级并说明只解析出几条" {
  let detection = @Mr-Houjie/mbt-filetype.detect(
    stored_zip("mimetype", "application/epub+zip", 0, 2),
  )
  match detection.file_type {
    Some(file_type) => assert_eq(file_type.id, "epub")
    None => assert_true(false)
  }
  assert_eq(
    @Mr-Houjie/mbt-filetype.confidence_name(detection.confidence),
    "probable",
  )
  assert_true(detection.reason.contains("1/2"))
}

///|
/// 构造 AIFC：`FVER` 在 `COMM` 之前，长度字段全部大端。
fn aifc_with_fver_first() -> Bytes {
  let out : Array[Byte] = []
  push_all(out, b"FORM")
  push_u32_be(out, 42)
  push_all(out, b"AIFC")
  push_all(out, b"FVER")
  push_u32_be(out, 4)
  push_u32_be(out, 0xa2805140)
  push_all(out, b"COMM")
  push_u32_be(out, 18)
  push_u16_le(out, 1)
  push_u32_be(out, 44100)
  push_u16_le(out, 16)
  for i = 0; i < 10; i = i + 1 {
    out.push(b'\x00')
  }
  as_bytes(out)
}

///|
test "回归：IFF 必须按大端解析，FVER 在前的 AIFC 仍识别为 aiff" {
  let detection = @Mr-Houjie/mbt-filetype.detect(aifc_with_fver_first())
  match detection.file_type {
    Some(file_type) => assert_eq(file_type.id, "aiff")
    None => assert_true(false)
  }
  assert_eq(
    @Mr-Houjie/mbt-filetype.confidence_name(detection.confidence),
    "certain",
  )
}

///|
test "回归：截断的 RIFF 必须降级并说明截断，而不是宣称结构完整" {
  let out : Array[Byte] = []
  push_all(out, b"RIFF")
  push_u32_le(out, 1000)
  push_all(out, b"WAVE")
  push_all(out, b"fmt ")
  push_u32_le(out, 16)
  for i = 0; i < 16; i = i + 1 {
    out.push(b'\x00')
  }
  push_all(out, b"data")
  push_u32_le(out, 0x00010000)
  let detection = @Mr-Houjie/mbt-filetype.detect(as_bytes(out))
  match detection.file_type {
    Some(file_type) => assert_eq(file_type.id, "wav")
    None => assert_true(false)
  }
  assert_eq(
    @Mr-Houjie/mbt-filetype.confidence_name(detection.confidence),
    "probable",
  )
  assert_true(detection.reason.contains("截断"))
}
