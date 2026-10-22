// 独立自检入口。
//
// Windows 下 `moon test` 可能受嵌套进程限制（os error 5），
// 因此提供与 `moon test` 等价的自检路径：
//   1. 一致性语料；
//   2. 扩展规则 / 检测器的公开 API 冒烟检查。

///|
fn check_extension_api() -> Array[String] {
  let failures : Array[String] = []

  // 声明式规则：命中后应当优先于内置签名
  let registry = @Mr-Houjie/mbt-filetype.Registry::new()
  registry.add_rule(
    @Mr-Houjie/mbt-filetype.Rule::new(
      "foo",
      "application/x-foo",
      "foo",
      @Mr-Houjie/mbt-filetype.Other,
      "FOO! 魔数",
      95,
      @Mr-Houjie/mbt-filetype.Matcher::magic_at(0, b"FOO!"),
    ),
  )
  let hit = @Mr-Houjie/mbt-filetype.detect_with(registry, b"FOO!rest")
  match hit.file_type {
    Some(file_type) =>
      if file_type.id != "foo" {
        failures.push("扩展规则未生效：得到 \{file_type.id}")
      }
    None => failures.push("扩展规则未生效：得到 unknown")
  }
  if hit.score != 95 {
    failures.push("扩展规则评分异常：\{hit.score}")
  }
  if registry.rule_count() != 1 {
    failures.push("Registry::rule_count 异常")
  }

  // 组合子：掩码 + 与条件
  let combo = @Mr-Houjie/mbt-filetype.Registry::new()
  combo.add_rule(
    @Mr-Houjie/mbt-filetype.Rule::new(
      "combo",
      "application/x-combo",
      "combo",
      @Mr-Houjie/mbt-filetype.Other,
      "掩码 + ASCII",
      90,
      @Mr-Houjie/mbt-filetype.Matcher::all([
        @Mr-Houjie/mbt-filetype.Matcher::magic_at(0, b"AB"),
        @Mr-Houjie/mbt-filetype.Matcher::masked_at(2, b"\x01\x00", b"\xff\x00"),
        @Mr-Houjie/mbt-filetype.Matcher::ascii_at(4, "CD"),
      ]),
    ),
  )
  let combo_hit = @Mr-Houjie/mbt-filetype.detect_with(combo, b"AB\x01\xffCD")
  match combo_hit.file_type {
    Some(file_type) =>
      if file_type.id != "combo" {
        failures.push("组合匹配器未生效：得到 \{file_type.id}")
      }
    None => failures.push("组合匹配器未生效：得到 unknown")
  }

  // 命令式检测器：内置签名未命中时兜底
  let with_detector = @Mr-Houjie/mbt-filetype.Registry::new()
  with_detector.add_detector(fn(data) {
    let is_det = data.length() >= 4 &&
      data[0].to_int() == 68 &&
      data[1].to_int() == 69 &&
      data[2].to_int() == 84 &&
      data[3].to_int() == 33
    if is_det {
      Some(
        ({
          file_type: Some({
            id: "detected",
            mime: "application/x-detected",
            ext: "det",
            category: @Mr-Houjie/mbt-filetype.Other,
          }),
          confidence: @Mr-Houjie/mbt-filetype.Certain,
          reason: "DET! 前缀",
          offset: 0,
          matched_len: 4,
          candidates: [],
          score: 100,
          evidence: [],
        } : @Mr-Houjie/mbt-filetype.Detection),
      )
    } else {
      None
    }
  })
  if with_detector.detector_count() != 1 {
    failures.push("Registry::detector_count 异常")
  }
  match @Mr-Houjie/mbt-filetype.detect_with(with_detector, b"DET!payload").file_type {
    Some(file_type) =>
      if file_type.id != "detected" {
        failures.push("自定义检测器未生效：得到 \{file_type.id}")
      }
    None => failures.push("自定义检测器未生效：得到 unknown")
  }

  failures
}

///|
fn main {
  let total = @Mr-Houjie/mbt-filetype.conformance_case_count()
  let failures = @Mr-Houjie/mbt-filetype.run_conformance()
  let api_failures = check_extension_api()
  if failures.length() == 0 && api_failures.length() == 0 {
    println("conformance: \{total} cases passed")
    println("extension api: ok")
    @sys.exit(0)
    return
  }
  for failure in failures {
    println("FAIL \{failure}")
  }
  for failure in api_failures {
    println("FAIL \{failure}")
  }
  println(
    "conformance: \{failures.length()} / \{total} failed, api: \{api_failures.length()} failed",
  )
  @sys.exit(1)
}
