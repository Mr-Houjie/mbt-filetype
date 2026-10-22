// 可扩展规则接口。
//
// 内置的 100 多条签名只是「默认规则集」，不是硬编码的判定逻辑：
// 调用方可以构造 `Registry`，追加自己的规则或检测器，
// 用 `detect_with` 在同一套流程里生效。
//
// 优先级：用户规则 → 内置签名与容器消歧 → 用户检测器 → 文本启发式。

///|
/// 规则匹配器。
///
/// 组合子让规则可以表达「强魔数 + 掩码」「多条件与/或」，
/// 而不是为每种变体在签名表里堆一条硬编码。
pub enum Matcher {
  /// 在固定偏移处匹配字节串
  MagicAt(Int, Bytes)
  /// 从文件尾部倒数 `back` 字节处匹配（例如 ZIP 的 EOCD）
  MagicAtEnd(Int, Bytes)
  /// 在固定偏移处按位掩码匹配：`(data & mask) == (magic & mask)`
  MaskedAt(Int, Bytes, Bytes)
  /// 在固定偏移处匹配 ASCII 文本
  AsciiAt(Int, String)
  /// 全部子匹配器命中
  All(Array[Matcher])
  /// 任一子匹配器命中
  Any(Array[Matcher])
}

///|
/// 具名构造器。比起直接写枚举变体，调用方更容易读写，也让文档示例更短。
pub fn Matcher::magic_at(offset : Int, magic : Bytes) -> Matcher {
  MagicAt(offset, magic)
}

///|
pub fn Matcher::magic_at_end(back : Int, magic : Bytes) -> Matcher {
  MagicAtEnd(back, magic)
}

///|
pub fn Matcher::masked_at(offset : Int, magic : Bytes, mask : Bytes) -> Matcher {
  MaskedAt(offset, magic, mask)
}

///|
pub fn Matcher::ascii_at(offset : Int, text : String) -> Matcher {
  AsciiAt(offset, text)
}

///|
pub fn Matcher::all(items : Array[Matcher]) -> Matcher {
  All(items)
}

///|
pub fn Matcher::any(items : Array[Matcher]) -> Matcher {
  Any(items)
}

///|
/// 一条声明式规则。
pub struct Rule {
  id : String
  mime : String
  ext : String
  category : Category
  /// 证据描述
  label : String
  /// 命中后贡献的分值
  weight : Int
  matcher : Matcher
}

///|
pub fn Rule::new(
  id : String,
  mime : String,
  ext : String,
  category : Category,
  label : String,
  weight : Int,
  matcher : Matcher,
) -> Rule {
  { id, mime, ext, category, label, weight, matcher }
}

///|
/// 用户扩展入口。
pub struct Registry {
  rules : Array[Rule]
  detectors : Array[(Bytes) -> Detection?]
}

///|
pub fn Registry::new() -> Registry {
  { rules: [], detectors: [] }
}

///|
/// 追加一条规则。用户规则优先于内置签名表。
pub fn Registry::add_rule(self : Registry, rule : Rule) -> Unit {
  self.rules.push(rule)
}

///|
/// 追加一个检测器。它只在规则与内置签名都没命中时被调用，
/// 返回 `Some` 即作为最终结果。
pub fn Registry::add_detector(
  self : Registry,
  detector : (Bytes) -> Detection?,
) -> Unit {
  self.detectors.push(detector)
}

///|
pub fn Registry::rule_count(self : Registry) -> Int {
  self.rules.length()
}

///|
pub fn Registry::detector_count(self : Registry) -> Int {
  self.detectors.length()
}

///|
fn string_bytes(text : String) -> Bytes {
  let out : Array[Byte] = []
  for c in text {
    out.push(c.to_int().to_byte())
  }
  Bytes::from_array(out.exact_view())
}

///|
fn match_masked(
  data : Bytes,
  offset : Int,
  magic : Bytes,
  mask : Bytes,
) -> Bool {
  let n = data.length()
  let m = magic.length()
  if offset < 0 || m == 0 || mask.length() != m || offset + m > n {
    return false
  }
  let mut i = 0
  while i < m {
    let mask_byte = mask[i].to_int()
    let actual = data[offset + i].to_int() & mask_byte
    let expected = magic[i].to_int() & mask_byte
    if actual != expected {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// 求值匹配器，命中返回证据偏移。
pub fn eval_matcher(matcher : Matcher, data : Bytes) -> Int? {
  match matcher {
    MagicAt(offset, magic) =>
      if match_at(data, offset, magic) {
        Some(offset)
      } else {
        None
      }
    MagicAtEnd(back, magic) => {
      let offset = data.length() - magic.length() - back
      if match_at(data, offset, magic) {
        Some(offset)
      } else {
        None
      }
    }
    MaskedAt(offset, magic, mask) =>
      if match_masked(data, offset, magic, mask) {
        Some(offset)
      } else {
        None
      }
    AsciiAt(offset, text) =>
      if match_at(data, offset, string_bytes(text)) {
        Some(offset)
      } else {
        None
      }
    All(items) => {
      let mut first : Int? = None
      let mut i = 0
      let mut ok = true
      while i < items.length() && ok {
        match eval_matcher(items[i], data) {
          Some(offset) =>
            match first {
              Some(_) => ()
              None => first = Some(offset)
            }
          None => ok = false
        }
        i = i + 1
      }
      if ok {
        first
      } else {
        None
      }
    }
    Any(items) => {
      let mut found : Int? = None
      let mut i = 0
      let mut go = true
      while i < items.length() && go {
        match eval_matcher(items[i], data) {
          Some(offset) => {
            found = Some(offset)
            go = false
          }
          None => ()
        }
        i = i + 1
      }
      found
    }
  }
}

///|
/// 命中规则时构造证据。
pub fn rule_evidence(rule : Rule, offset : Int) -> Evidence {
  {
    kind: "rule",
    label: rule.label,
    offset,
    matched_len: 0,
    weight: rule.weight,
  }
}
