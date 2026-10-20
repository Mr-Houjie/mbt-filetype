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
