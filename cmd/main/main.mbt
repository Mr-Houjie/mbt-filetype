// mbt-filetype 命令行入口。
//
// 识别逻辑全部在库包 `Mr-Houjie/mbt-filetype`；这里只负责
// 参数解析、文件读写、输出与退出码。

///|
const VERSION : String = "0.1.0"

///|
fn usage() -> String {
  let s = StringBuilder()
  s.write_string(
    "mbt-filetype \{VERSION} — 文件类型识别与内容嗅探\n\n",
  )
  s.write_string("用法:\n")
  s.write_string("  mbt-filetype [选项] <文件...>\n")
  s.write_string("  mbt-filetype --scan <目录>\n\n")
  s.write_string("选项:\n")
  s.write_string("  --json                以单行 JSON 输出\n")
  s.write_string(
    "  --explain             额外显示签名偏移与字节数\n",
  )
  s.write_string(
    "  --expect <id|mime|ext>  断言类型，不匹配时退出码为 1\n",
  )
  s.write_string(
    "  --scan <目录>         递归扫描并报告扩展名与内容不符的文件\n",
  )
  s.write_string("  --list-types          列出全部已知类型\n")
  s.write_string("  -v, --version         显示版本\n")
  s.write_string("  -h, --help            显示本帮助\n\n")
  s.write_string("退出码:\n")
  s.write_string("  0  成功（或 --expect 匹配）\n")
  s.write_string("  1  --expect 不匹配 / 扫描发现扩展名不符\n")
  s.write_string("  2  用法错误或读写失败\n")
  s.to_string()
}

///|
struct Options {
  paths : Array[String]
  mut json : Bool
  mut explain : Bool
  mut expect : String?
  mut scan : String?
  mut list_types : Bool
  mut help : Bool
  mut version : Bool
}

///|
fn Options::new() -> Options {
  {
    paths: [],
    json: false,
    explain: false,
    expect: None,
    scan: None,
    list_types: false,
    help: false,
    version: false,
  }
}

///|
/// 输出文本并去掉末尾换行，避免 `println` 追加空行。
fn output(text : String) -> Unit {
  let chars = text.iter().to_array()
  let mut n = chars.length()
  while n > 0 && (chars[n - 1] == '\n' || chars[n - 1] == '\r') {
    n = n - 1
  }
  if n == 0 {
    return
  }
  let buffer = StringBuilder()
  for i = 0; i < n; i = i + 1 {
    buffer.write_char(chars[i])
  }
  println(buffer.to_string())
}

///|
fn usage_error(message : String) -> Unit {
  println("错误: \{message}")
  println("")
  output(usage())
  @sys.exit(2)
}

///|
fn next_arg(args : Array[String], i : Int, name : String) -> String {
  if i + 1 >= args.length() {
    usage_error("\{name} 需要一个参数")
  }
  args[i + 1]
}

///|
fn parse_args(args : Array[String]) -> Options {
  let options = Options::new()
  let mut i = 1
  while i < args.length() {
    let arg = args[i]
    match arg {
      "--json" => options.json = true
      "--explain" => options.explain = true
      "--list-types" => options.list_types = true
      "--help" | "-h" => options.help = true
      "--version" | "-v" => options.version = true
      "--expect" => {
        options.expect = Some(next_arg(args, i, "--expect"))
        i = i + 1
      }
      "--scan" => {
        options.scan = Some(next_arg(args, i, "--scan"))
        i = i + 1
      }
      _ =>
        if arg.has_prefix("-") {
          usage_error("未知选项「\{arg}」")
        } else {
          options.paths.push(arg)
        }
    }
    i = i + 1
  }
  options
}

///|
fn ascii_lower(s : String) -> String {
  let buffer = StringBuilder()
  for c in s {
    buffer.write_char(c.to_ascii_lowercase())
  }
  buffer.to_string()
}

///|
fn read_file(path : String) -> Result[Bytes, String] {
  Ok(@fs.read_file_to_bytes(path)) catch {
    _ => Err("读取文件失败")
  }
}

///|
fn matches_expect(detection : @lib.Detection, expect : String) -> Bool {
  match detection.file_type {
    None => false
    Some(file_type) => {
      let wanted = ascii_lower(expect)
      wanted == ascii_lower(file_type.id) ||
      wanted == ascii_lower(file_type.mime) ||
      wanted == ascii_lower(file_type.ext) ||
      wanted == "." + ascii_lower(file_type.ext)
    }
  }
}

///|
/// 处理单个文件：0 成功，1 断言不匹配，2 读写失败。
fn process_file(path : String, options : Options) -> Int {
  match read_file(path) {
    Err(message) => {
      println("无法读取「\{path}」: \{message}")
      2
    }
    Ok(bytes) => {
      let detection = @lib.detect(bytes)
      if options.json {
        output(@lib.render_json(path, detection))
      } else {
        output(@lib.render_text(path, detection, options.explain))
      }
      match options.expect {
        Some(expect) => if matches_expect(detection, expect) { 0 } else { 1 }
        None => 0
      }
    }
  }
}

///|
fn path_ext(path : String) -> String {
  let chars = path.iter().to_array()
  let mut last_dot = -1
  let mut last_separator = -1
  let mut i = 0
  while i < chars.length() {
    let c = chars[i]
    if c == '.' {
      last_dot = i
    }
    if c == '/' || c == '\\' {
      last_separator = i
    }
    i = i + 1
  }
  if last_dot > last_separator + 1 {
    let buffer = StringBuilder()
    let mut j = last_dot + 1
    while j < chars.length() {
      buffer.write_char(chars[j])
      j = j + 1
    }
    buffer.to_string()
  } else {
    ""
  }
}

///|
fn ext_matches(declared : String, file_type : @lib.FileType) -> Bool {
  let ext = ascii_lower(declared)
  if ext == ascii_lower(file_type.ext) {
    return true
  }
  match file_type.id {
    "jpeg" => ext == "jpg" || ext == "jpe" || ext == "jfif"
    "tiff" => ext == "tif"
    "html" => ext == "htm"
    "mp4" => ext == "m4v"
    "heic" => ext == "heif"
    "jp2" => ext == "j2k" || ext == "jpx" || ext == "jpf"
    "ts" => ext == "m2ts" || ext == "mts"
    "3gp" => ext == "3gpp"
    "pnm" => ext == "pgm" || ext == "ppm" || ext == "pbm"
    "pe" => ext == "exe" || ext == "dll" || ext == "sys"
    "macho" => ext == "dylib" || ext == "o"
    "ole2" => ext == "doc" || ext == "xls" || ext == "ppt"
    _ => false
  }
}

///|
fn join_path(directory : String, name : String) -> String {
  if directory.has_suffix("/") || directory.has_suffix("\\") {
    directory + name
  } else {
    directory + "/" + name
  }
}

///|
struct ScanStats {
  mut total : Int
  mut mismatches : Int
}

///|
fn check_scan_file(path : String, options : Options, stats : ScanStats) -> Unit {
  let declared = path_ext(path)
  if declared.is_empty() {
    return
  }
  match read_file(path) {
    Err(_) => ()
    Ok(bytes) => {
      let detection = @lib.detect(bytes)
      match detection.file_type {
        None => ()
        Some(file_type) =>
          if @lib.is_text_category(file_type) ||
            ext_matches(declared, file_type) {
            ()
          } else {
            stats.mismatches = stats.mismatches + 1
            if options.json {
              output(@lib.render_json(path, detection))
            } else {
              println(
                "\{path}: 扩展名 .\{declared}，实际 \{file_type.id} (\{file_type.mime})",
              )
            }
          }
      }
    }
  }
}

///|
fn scan_directory(
  directory : String,
  depth : Int,
  options : Options,
  stats : ScanStats,
) -> Unit {
  if depth > 32 {
    println("扫描深度超过 32，跳过「\{directory}」")
    return
  }
  let entries = @fs.read_dir(directory) catch {
    _ => {
      println("无法读取目录「\{directory}」")
      return
    }
  }
  for name in entries {
    let path = join_path(directory, name)
    let is_directory = @fs.is_dir(path) catch { _ => false }
    if is_directory {
      scan_directory(path, depth + 1, options, stats)
    } else {
      stats.total = stats.total + 1
      check_scan_file(path, options, stats)
    }
  }
}

///|
fn main {
  let args = @env.args()
  let options = parse_args(args)
  if options.help {
    output(usage())
    @sys.exit(0)
    return
  }
  if options.version {
    println("mbt-filetype \{VERSION}")
    @sys.exit(0)
    return
  }
  if options.list_types {
    output(@lib.render_types())
    @sys.exit(0)
    return
  }
  if options.paths.is_empty() && options.scan is None {
    usage_error("至少需要一个文件，或使用 --scan <目录>")
  }
  let mut code = 0
  for path in options.paths {
    let result = process_file(path, options)
    if result > code {
      code = result
    }
  }
  match options.scan {
    Some(directory) => {
      let stats = { total: 0, mismatches: 0, }
      scan_directory(directory, 0, options, stats)
      println("")
      println(
        "scan: \{stats.total} files, \{stats.mismatches} extension mismatches",
      )
      if stats.mismatches > 0 && code < 1 {
        code = 1
      }
    }
    None => ()
  }
  @sys.exit(code)
}
