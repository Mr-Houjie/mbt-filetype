// 公共数据类型。
//
// 本库刻意不依赖任何第三方包，所有判定都只基于输入字节，
// 因此同一份输入在任何后端上都会得到相同结果。

///|
/// 文件大类。
pub enum Category {
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
/// - `Probable`：弱签名、容器内文件名启发式或文本启发式；
/// - `Unknown`：没有足够证据，宁可返回未知也不猜。
pub enum Confidence {
  Certain
  Probable
  Unknown
}

///|
/// 一种文件类型。
pub struct FileType {
  /// 稳定的类型 id，例如 `png`、`docx`
  id : String
  /// IANA 风格的 MIME 类型
  mime : String
  /// 不带点号的推荐扩展名
  ext : String
  category : Category
}

///|
/// 一次识别结果。
pub struct Detection {
  /// 识别出的类型；`None` 表示未知
  file_type : FileType?
  confidence : Confidence
  /// 人类可读的证据说明
  reason : String
  /// 命中的签名在输入中的偏移
  offset : Int
  /// 命中签名的字节数
  matched_len : Int
  /// 存在歧义时的候选类型（例如 OLE2 容器）
  candidates : Array[FileType]
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
