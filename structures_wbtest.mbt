// 白盒测试：直接验证结构解析层与可扩展规则接口。
//
// 黑盒测试（detect_test.mbt）只走公开 API；这里补充对内部解析器
// 与 Registry 扩展点的验证。

///|
test "ZIP：按中央目录精确解析条目名" {
  let data = zip_of([
    ("[Content_Types].xml", "<Types/>"), ("word/document.xml", "<w:document/>"),
  ])
  match parse_zip(data) {
    Some(archive) => {
      assert_eq(archive.entries.length(), 2)
      assert_eq(archive.declared_entries, 2)
      assert_true(archive.complete)
      assert_eq(archive.entries[0].name, "[Content_Types].xml")
      assert_eq(archive.entries[1].name, "word/document.xml")
    }
    None => assert_true(false)
  }
}

///|
test "ZIP：内容里出现 word/ 不会被判成 docx" {
  let data = zip_of([("notes.txt", "see word/document.xml for details")])
  let detection = detect(data)
  assert_eq(detection.file_type.unwrap().id, "zip")
  assert_true(detection.score >= 100)
}

///|
test "ZIP：mimetype 必须排第一且 stored" {
  let epub = zip_of([
    ("mimetype", "application/epub+zip"), ("content.opf", "<package/>"),
  ])
  assert_eq(detect(epub).file_type.unwrap().id, "epub")
  let not_first = zip_of([
    ("content.opf", "<package/>"), ("mimetype", "application/epub+zip"),
  ])
  assert_eq(detect(not_first).file_type.unwrap().id, "zip")
}

///|
test "ISO-BMFF：box 树下钻到 hdlr" {
  let vide = bmff_handlers(bmff_with_handler("isom", "vide"))
  assert_eq(vide.length(), 1)
  assert_eq(vide[0], "vide")
  assert_eq(detect(bmff_with_handler("isom", "vide")).file_type.unwrap().id, "mp4")
  assert_eq(detect(bmff_with_handler("isom", "soun")).file_type.unwrap().id, "m4a")
}

///|
test "EBML：vint 解出 DocType" {
  assert_eq(ebml_doctype(ebml_bytes("webm")), Some("webm"))
  assert_eq(ebml_doctype(ebml_bytes("matroska")), Some("matroska"))
}

///|
test "RIFF：chunk 遍历与必需块校验" {
  let wav = riff_bytes("RIFF", "WAVE", [("fmt ", 16), ("data", 0)])
  match parse_riff(wav) {
    Some(info) => {
      assert_eq(info.form, "WAVE")
      assert_eq(info.chunks.length(), 2)
      assert_true(contains_name(info.chunks, "data"))
    }
    None => assert_true(false)
  }
  // form 正确但缺 data chunk：只能给候选，不能直接判 wav
  let incomplete = riff_bytes("RIFF", "WAVE", [("fmt ", 16)])
  let detection = detect(incomplete)
  assert_eq(detection.file_type.unwrap().id, "riff")
  assert_true(detection.candidates.length() > 0)
}

///|
test "TAR：header checksum 校验" {
  assert_true(tar_checksum_ok(tar_bytes()))
  let broken = bytes_to_array(tar_bytes())
  broken[0] = (88).to_byte()
  assert_true(!tar_checksum_ok(Bytes::from_array(broken.exact_view())))
}

///|
test "PE：解析 COFF 与 Optional Header" {
  match parse_pe(pe_bytes()) {
    Some(info) => {
      assert_eq(pe_machine_name(info), "x86-64")
      assert_true(info.is_64)
      assert_eq(info.sections, 3)
    }
    None => assert_true(false)
  }
  assert_eq(detect(pe_bytes()).file_type.unwrap().id, "pe")
}

///|
test "扩展：自定义规则优先于内置签名" {
  let registry = Registry::new()
  registry.add_rule(
    Rule::new(
      "foo", "application/x-foo", "foo", Other, "自定义 FOO! 魔数", 95,
      MagicAt(0, b"FOO!"),
    ),
  )
  assert_eq(registry.rule_count(), 1)
  let detection = detect_with(registry, b"FOO!\x00\x01\x02")
  assert_eq(detection.file_type.unwrap().id, "foo")
  assert_eq(detection.score, 95)
  assert_eq(detection.evidence.length(), 1)
  // 未命中自定义规则时，仍然走内置判定
  assert_eq(detect_with(registry, b"\x89PNG\r\n\x1a\n").file_type.unwrap().id, "png")
}

///|
test "扩展：MaskedAt / AsciiAt / MagicAtEnd / All / Any" {
  let masked = Registry::new()
  masked.add_rule(
    Rule::new("mask", "application/x-mask", "mask", Other, "掩码匹配", 90, MaskedAt(0, b"B\x00", b"\xff\x00")),
  )
  assert_eq(detect_with(masked, b"B\x99rest").file_type.unwrap().id, "mask")

  let ascii = Registry::new()
  ascii.add_rule(
    Rule::new("ascii", "application/x-ascii", "ascii", Other, "ASCII 匹配", 90, AsciiAt(4, "HEAD")),
  )
  assert_eq(detect_with(ascii, b"----HEADxxxx").file_type.unwrap().id, "ascii")

  let tail = Registry::new()
  tail.add_rule(
    Rule::new("tail", "application/x-tail", "tail", Other, "尾部匹配", 90, MagicAtEnd(0, b"EOF!")),
  )
  assert_eq(detect_with(tail, b"anythingEOF!").file_type.unwrap().id, "tail")

  let all = Registry::new()
  all.add_rule(
    Rule::new(
      "all", "application/x-all", "all", Other, "与条件", 90,
      All([MagicAt(0, b"AB"), AsciiAt(2, "CD")]),
    ),
  )
  assert_eq(detect_with(all, b"ABCD").file_type.unwrap().id, "all")
  // 与条件不成立时回落到文本启发式，而不是误报
  assert_eq(detect_with(all, b"ABCE").file_type.unwrap().id, "text")

  let any = Registry::new()
  any.add_rule(
    Rule::new(
      "any", "application/x-any", "any", Other, "或条件", 90,
      Any([MagicAt(0, b"XX"), MagicAt(0, b"YY")]),
    ),
  )
  assert_eq(detect_with(any, b"YYrest").file_type.unwrap().id, "any")
}

///|
test "扩展：自定义检测器作为兜底" {
  let registry = Registry::new()
  registry.add_detector(fn(data) {
    if match_at(data, 0, b"DET!") {
      Some(
        make_detection(
          Some(ft("detected", "application/x-detected", "det", Other)),
          "自定义检测器命中",
          [evidence("rule", "DET! 前缀", 0, 4, 100)],
          [],
        ),
      )
    } else {
      None
    }
  })
  assert_eq(registry.detector_count(), 1)
  let detection = detect_with(registry, b"DET!payload")
  assert_eq(detection.file_type.unwrap().id, "detected")
  assert_eq(confidence_name(detection.confidence), "certain")
}
