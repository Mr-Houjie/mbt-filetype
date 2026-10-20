// 独立自检入口。
//
// Windows 下 `moon test` 可能受嵌套进程限制（os error 5），
// 因此提供与 `moon test` 等价的一致性语料校验路径。

///|
fn main {
  let total = @Mr-Houjie/mbt-filetype.conformance_case_count()
  let failures = @Mr-Houjie/mbt-filetype.run_conformance()
  if failures.length() == 0 {
    println("conformance: \{total} cases passed")
    @sys.exit(0)
    return
  }
  for failure in failures {
    println("FAIL \{failure}")
  }
  println("conformance: \{failures.length()} / \{total} failed")
  @sys.exit(1)
}
