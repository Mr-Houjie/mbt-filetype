// 公共数据类型。
//
// 本库刻意不依赖任何第三方包，所有判定都只基于输入字节，
// 因此同一份输入在任何后端上都会得到相同结果。

///|
/// 文件大类。
pub(all) enum Category {
  Image
  Document
  Archive
  Audio
  Video
  Executable
  Font
  Database
  Scientific
  Wasm
  Text
  Other
}

///|
/// 判定置信度。
///
/// - `Certain`：命中强签名，或容器结构可以明确消歧；
/// - `Probable`：弱签名、结构校验不完整或文本启发式；
/// - `Unknown`：没有足够证据，宁可返回未知也不猜。
///
/// 具体取值由 `confidence_of_score` 从证据评分推导。
pub(all) enum Confidence {
  Certain
  Probable
  Unknown
}

///|
/// 一种文件类型。
pub(all) struct FileType {
  /// 稳定的类型 id，例如 `png`、`docx`
  id : String
  /// IANA 风格的 MIME 类型
  mime : String
  /// 不带点号的推荐扩展名
  ext : String
  category : Category
}

///|
/// 一条判定证据。
///
/// 置信度不是人工标注的标签，而是由证据累加得到的评分：
/// 强魔数 90 分、弱魔数 20 分、结构验证 40~70 分、文本启发式 30 分；
/// 总分 ≥ 90 判 `Certain`，≥ 20 判 `Probable`，否则 `Unknown`。
pub(all) struct Evidence {
  /// 证据种类：`magic` / `structure` / `heuristic` / `rule`
  kind : String
  /// 人类可读描述
  label : String
  offset : Int
  matched_len : Int
  /// 该证据贡献的分值
  weight : Int
}

///|
/// 一次识别结果。
pub(all) struct Detection {
  /// 识别出的类型；`None` 表示未知
  file_type : FileType?
  confidence : Confidence
  /// 人类可读的证据说明（摘要）
  reason : String
  /// 主证据在输入中的偏移
  offset : Int
  /// 主证据的字节数
  matched_len : Int
  /// 存在歧义时的候选类型（例如 OLE2 容器）
  candidates : Array[FileType]
  /// 证据累加得到的评分（0~100）
  score : Int
  /// 完整证据链，按贡献顺序排列
  evidence : Array[Evidence]
}

///|
/// 由评分推导置信度。阈值是公开契约，不随调用点变化。
pub fn confidence_of_score(score : Int) -> Confidence {
  if score >= 90 {
    Certain
  } else if score >= 20 {
    Probable
  } else {
    Unknown
  }
}

///|
/// 大类名称。
pub fn category_name(category : Category) -> String {
  match category {
    Image => "image"
    Document => "document"
    Archive => "archive"
    Audio => "audio"
    Video => "video"
    Executable => "executable"
    Font => "font"
    Database => "database"
    Scientific => "scientific"
    Wasm => "wasm"
    Text => "text"
    Other => "other"
  }
}

///|
/// 置信度名称。
pub fn confidence_name(confidence : Confidence) -> String {
  match confidence {
    Certain => "certain"
    Probable => "probable"
    Unknown => "unknown"
  }
}

///|
/// 该类型是否属于文本大类。
pub fn is_text_category(file_type : FileType) -> Bool {
  match file_type.category {
    Text => true
    _ => false
  }
}
