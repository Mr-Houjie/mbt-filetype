// 输出渲染：text / json / 类型列表。

///|
fn hex2(n : Int) -> String {
  let digits = "0123456789abcdef"
  let builder = StringBuilder()
  match digits.get_char(n / 16) {
    Some(c) => builder.write_char(c)
    None => ()
  }
  match digits.get_char(n % 16) {
    Some(c) => builder.write_char(c)
    None => ()
  }
  builder.to_string()
}

///|
fn json_escape(s : String) -> String {
  let builder = StringBuilder()
  for c in s {
    match c {
      '"' => builder.write_string("\\\"")
      '\\' => builder.write_string("\\\\")
      '\n' => builder.write_string("\\n")
      '\r' => builder.write_string("\\r")
      '\t' => builder.write_string("\\t")
      _ => {
        let code = c.to_int()
        if code < 32 {
          builder.write_string("\\u00")
          builder.write_string(hex2(code))
        } else {
          builder.write_char(c)
        }
      }
    }
  }
  builder.to_string()
}

///|
fn padded(s : String, width : Int) -> String {
  let builder = StringBuilder()
  builder.write_string(s)
  let mut n = s.length()
  while n < width {
    builder.write_char(' ')
    n = n + 1
  }
  builder.to_string()
}

///|
/// 渲染人类可读的识别结果。
pub fn render_text(
  path : String,
  detection : Detection,
  explain : Bool,
) -> String {
  let builder = StringBuilder()
  builder.write_string(path)
  builder.write_string("\n")
  match detection.file_type {
    Some(file_type) => {
      builder.write_string("  type:       \{file_type.id}\n")
      builder.write_string("  mime:       \{file_type.mime}\n")
      builder.write_string("  extension:  .\{file_type.ext}\n")
      builder.write_string(
        "  category:   \{category_name(file_type.category)}\n",
      )
    }
    None => {
      builder.write_string("  type:       unknown\n")
      builder.write_string("  mime:       application/octet-stream\n")
      builder.write_string("  extension:  -\n")
      builder.write_string("  category:   unknown\n")
    }
  }
  builder.write_string(
    "  confidence: \{confidence_name(detection.confidence)}\n",
  )
  builder.write_string("  evidence:   \{detection.reason}\n")
  if explain {
    builder.write_string("  offset:     \{detection.offset}\n")
    builder.write_string("  bytes:      \{detection.matched_len}\n")
  }
  if detection.candidates.length() > 0 {
    builder.write_string("  candidates: ")
    let mut first = true
    for candidate in detection.candidates {
      if !first {
        builder.write_string(", ")
      }
      builder.write_string(candidate.id)
      first = false
    }
    builder.write_string("\n")
  }
  builder.to_string()
}

///|
/// 渲染单行 JSON。
pub fn render_json(path : String, detection : Detection) -> String {
  let builder = StringBuilder()
  builder.write_string("{\"path\":\"\{json_escape(path)}\"")
  match detection.file_type {
    Some(file_type) => {
      builder.write_string(",\"type\":\"\{json_escape(file_type.id)}\"")
      builder.write_string(",\"mime\":\"\{json_escape(file_type.mime)}\"")
      builder.write_string(",\"ext\":\"\{json_escape(file_type.ext)}\"")
      builder.write_string(
        ",\"category\":\"\{category_name(file_type.category)}\"",
      )
    }
    None => {
      builder.write_string(",\"type\":\"unknown\"")
      builder.write_string(",\"mime\":\"application/octet-stream\"")
      builder.write_string(",\"ext\":\"\"")
      builder.write_string(",\"category\":\"unknown\"")
    }
  }
  builder.write_string(
    ",\"confidence\":\"\{confidence_name(detection.confidence)}\"",
  )
  builder.write_string(",\"offset\":\{detection.offset}")
  builder.write_string(",\"bytes\":\{detection.matched_len}")
  builder.write_string(",\"reason\":\"\{json_escape(detection.reason)}\"")
  builder.write_string(",\"candidates\":[")
  let mut first = true
  for candidate in detection.candidates {
    if !first {
      builder.write_string(",")
    }
    builder.write_string("\"\{json_escape(candidate.id)}\"")
    first = false
  }
  builder.write_string("]}")
  builder.to_string()
}

///|
/// 渲染类型清单（`--list-types`）。
pub fn render_types() -> String {
  let builder = StringBuilder()
  builder.write_string(
    "\{padded("ID", 12)}\{padded("EXT", 10)}\{padded("CATEGORY", 12)}MIME\n",
  )
  for file_type in known_types() {
    builder.write_string("\{padded(file_type.id, 12)}")
    builder.write_string("\{padded(".\{file_type.ext}", 10)}")
    builder.write_string("\{padded(category_name(file_type.category), 12)}")
    builder.write_string("\{file_type.mime}\n")
  }
  builder.to_string()
}
