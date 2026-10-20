// 内置签名表与文件类型定义。
//
// 设计约束：
// 1. 表是有序的，先匹配到的签名生效；
// 2. 强签名在前，弱签名（如 `BM`、`MZ`）在后；
// 3. 容器类格式（ZIP / RIFF / ftyp / OLE2 / CAFEBABE / TTF）先给出通用类型，
//    再由 `detect.mbt` 做进一步消歧。

///|
fn ft(
  id : String,
  mime : String,
  ext : String,
  category : Category,
) -> FileType {
  { id, mime, ext, category, }
}

///|
/// 一条魔数签名。
priv struct Signature {
  /// 签名在输入中的固定偏移
  offset : Int
  magic : Bytes
  file_type : FileType
  label : String
  /// 强签名命中即可判定为 `Certain`，弱签名只能给 `Probable`
  strong : Bool
}

// ---------------------------------------------------------------------------
// 图片
// ---------------------------------------------------------------------------

///|
let png : FileType = ft("png", "image/png", "png", Image)

///|
let jpeg : FileType = ft("jpeg", "image/jpeg", "jpg", Image)

///|
let gif : FileType = ft("gif", "image/gif", "gif", Image)

///|
let bmp : FileType = ft("bmp", "image/bmp", "bmp", Image)

///|
let tiff : FileType = ft("tiff", "image/tiff", "tiff", Image)

///|
let ico : FileType = ft("ico", "image/x-icon", "ico", Image)

///|
let psd : FileType = ft("psd", "image/vnd.adobe.photoshop", "psd", Image)

///|
let xcf : FileType = ft("xcf", "image/x-xcf", "xcf", Image)

///|
let webp : FileType = ft("webp", "image/webp", "webp", Image)

///|
let avif : FileType = ft("avif", "image/avif", "avif", Image)

///|
let heic : FileType = ft("heic", "image/heic", "heic", Image)

///|
let jp2 : FileType = ft("jp2", "image/jp2", "jp2", Image)

///|
let jxl : FileType = ft("jxl", "image/jxl", "jxl", Image)

///|
let icns : FileType = ft("icns", "image/icns", "icns", Image)

///|
let cur : FileType = ft("cur", "image/x-icon", "cur", Image)

///|
let dds : FileType = ft("dds", "image/vnd.ms-dds", "dds", Image)

///|
let ktx : FileType = ft("ktx", "image/ktx", "ktx", Image)

///|
let ktx2 : FileType = ft("ktx2", "image/ktx2", "ktx2", Image)

///|
let exr : FileType = ft("exr", "image/x-exr", "exr", Image)

///|
let hdr : FileType = ft("hdr", "image/vnd.radiance", "hdr", Image)

///|
let pnm : FileType = ft("pnm", "image/x-portable-anymap", "pnm", Image)

// ---------------------------------------------------------------------------
// 文档
// ---------------------------------------------------------------------------

///|
let pdf : FileType = ft("pdf", "application/pdf", "pdf", Document)

///|
let postscript : FileType = ft(
  "postscript",
  "application/postscript",
  "ps",
  Document,
)

///|
let rtf : FileType = ft("rtf", "application/rtf", "rtf", Document)

///|
let djvu : FileType = ft("djvu", "image/vnd.djvu", "djvu", Document)

///|
let ole2 : FileType = ft("ole2", "application/x-ole-storage", "ole", Document)

///|
let doc : FileType = ft("doc", "application/msword", "doc", Document)

///|
let xls : FileType = ft("xls", "application/vnd.ms-excel", "xls", Document)

///|
let ppt : FileType = ft("ppt", "application/vnd.ms-powerpoint", "ppt", Document)

///|
let epub : FileType = ft("epub", "application/epub+zip", "epub", Document)

///|
let docx : FileType = ft(
  "docx",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "docx",
  Document,
)

///|
let xlsx : FileType = ft(
  "xlsx",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "xlsx",
  Document,
)

///|
let pptx : FileType = ft(
  "pptx",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "pptx",
  Document,
)

///|
let pem : FileType = ft("pem", "application/x-pem-file", "pem", Document)

///|
let pgp : FileType = ft("pgp", "application/pgp-encrypted", "pgp", Document)

///|
let mobi : FileType = ft(
  "mobi",
  "application/x-mobipocket-ebook",
  "mobi",
  Document,
)

///|
let chm : FileType = ft("chm", "application/vnd.ms-htmlhelp", "chm", Document)

///|
let odt : FileType = ft(
  "odt",
  "application/vnd.oasis.opendocument.text",
  "odt",
  Document,
)

///|
let ods : FileType = ft(
  "ods",
  "application/vnd.oasis.opendocument.spreadsheet",
  "ods",
  Document,
)

///|
let odp : FileType = ft(
  "odp",
  "application/vnd.oasis.opendocument.presentation",
  "odp",
  Document,
)

///|
let xps : FileType = ft(
  "xps",
  "application/vnd.ms-xpsdocument",
  "xps",
  Document,
)

// ---------------------------------------------------------------------------
// 归档与压缩
// ---------------------------------------------------------------------------

///|
let zip : FileType = ft("zip", "application/zip", "zip", Archive)

///|
let apk : FileType = ft(
  "apk",
  "application/vnd.android.package-archive",
  "apk",
  Archive,
)

///|
let jar : FileType = ft("jar", "application/java-archive", "jar", Archive)

///|
let gzip : FileType = ft("gzip", "application/gzip", "gz", Archive)

///|
let bzip2 : FileType = ft("bzip2", "application/x-bzip2", "bz2", Archive)

///|
let xz : FileType = ft("xz", "application/x-xz", "xz", Archive)

///|
let zstd : FileType = ft("zstd", "application/zstd", "zst", Archive)

///|
let sevenz : FileType = ft("7z", "application/x-7z-compressed", "7z", Archive)

///|
let rar : FileType = ft("rar", "application/vnd.rar", "rar", Archive)

///|
let tar : FileType = ft("tar", "application/x-tar", "tar", Archive)

///|
let cab : FileType = ft(
  "cab",
  "application/vnd.ms-cab-compressed",
  "cab",
  Archive,
)

///|
let lz4 : FileType = ft("lz4", "application/x-lz4", "lz4", Archive)

///|
let cpio : FileType = ft("cpio", "application/x-cpio", "cpio", Archive)

///|
let rpm : FileType = ft("rpm", "application/x-rpm", "rpm", Archive)

///|
let ar : FileType = ft("ar", "application/x-archive", "a", Archive)

///|
let deb : FileType = ft(
  "deb",
  "application/vnd.debian.binary-package",
  "deb",
  Archive,
)

///|
let xar : FileType = ft("xar", "application/x-xar", "xar", Archive)

///|
let squashfs : FileType = ft(
  "squashfs",
  "application/vnd.squashfs",
  "sqfs",
  Archive,
)

///|
let crx : FileType = ft("crx", "application/x-chrome-extension", "crx", Archive)

///|
let iso : FileType = ft("iso", "application/x-iso9660-image", "iso", Archive)

///|
let compress_z : FileType = ft(
  "compress",
  "application/x-compress",
  "Z",
  Archive,
)

// ---------------------------------------------------------------------------
// 音频
// ---------------------------------------------------------------------------

///|
let mp3 : FileType = ft("mp3", "audio/mpeg", "mp3", Audio)

///|
let flac : FileType = ft("flac", "audio/flac", "flac", Audio)

///|
let ogg : FileType = ft("ogg", "audio/ogg", "ogg", Audio)

///|
let wav : FileType = ft("wav", "audio/wav", "wav", Audio)

///|
let midi : FileType = ft("midi", "audio/midi", "mid", Audio)

///|
let aac : FileType = ft("aac", "audio/aac", "aac", Audio)

///|
let iff : FileType = ft("iff", "application/x-iff", "iff", Other)

///|
let aiff : FileType = ft("aiff", "audio/aiff", "aiff", Audio)

///|
let au : FileType = ft("au", "audio/basic", "au", Audio)

///|
let wavpack : FileType = ft("wavpack", "audio/x-wavpack", "wv", Audio)

///|
let ape : FileType = ft("ape", "audio/x-ape", "ape", Audio)

///|
let amr : FileType = ft("amr", "audio/amr", "amr", Audio)

///|
let opus : FileType = ft("opus", "audio/opus", "opus", Audio)

///|
let m4a : FileType = ft("m4a", "audio/mp4", "m4a", Audio)

// ---------------------------------------------------------------------------
// 视频
// ---------------------------------------------------------------------------

///|
let mp4 : FileType = ft("mp4", "video/mp4", "mp4", Video)

///|
let mov : FileType = ft("mov", "video/quicktime", "mov", Video)

///|
let mkv : FileType = ft("mkv", "video/x-matroska", "mkv", Video)

///|
let webm : FileType = ft("webm", "video/webm", "webm", Video)

///|
let ebml : FileType = ft("ebml", "application/octet-stream", "mkv", Video)

///|
let avi : FileType = ft("avi", "video/x-msvideo", "avi", Video)

///|
let flv : FileType = ft("flv", "video/x-flv", "flv", Video)

///|
let mpeg : FileType = ft("mpeg", "video/mpeg", "mpg", Video)

///|
let asf : FileType = ft("asf", "video/x-ms-asf", "asf", Video)

///|
let wma : FileType = ft("wma", "audio/x-ms-wma", "wma", Audio)

///|
let wmv : FileType = ft("wmv", "video/x-ms-wmv", "wmv", Video)

///|
let ts : FileType = ft("ts", "video/mp2t", "ts", Video)

///|
let threegp : FileType = ft("3gp", "video/3gpp", "3gp", Video)

// ---------------------------------------------------------------------------
// 可执行与字节码
// ---------------------------------------------------------------------------

///|
let elf : FileType = ft("elf", "application/x-elf", "elf", Executable)

///|
let pe : FileType = ft(
  "pe",
  "application/vnd.microsoft.portable-executable",
  "exe",
  Executable,
)

///|
let macho : FileType = ft(
  "macho",
  "application/x-mach-binary",
  "macho",
  Executable,
)

///|
let java_class : FileType = ft(
  "class",
  "application/java-vm",
  "class",
  Executable,
)

///|
let wasm : FileType = ft("wasm", "application/wasm", "wasm", Wasm)

///|
let dex : FileType = ft("dex", "application/vnd.android.dex", "dex", Executable)

///|
let luac : FileType = ft(
  "luac",
  "application/x-lua-bytecode",
  "luac",
  Executable,
)

// ---------------------------------------------------------------------------
// 字体
// ---------------------------------------------------------------------------

///|
let ttf : FileType = ft("ttf", "font/ttf", "ttf", Font)

///|
let otf : FileType = ft("otf", "font/otf", "otf", Font)

///|
let woff : FileType = ft("woff", "font/woff", "woff", Font)

///|
let woff2 : FileType = ft("woff2", "font/woff2", "woff2", Font)

///|
let ttc : FileType = ft("ttc", "font/collection", "ttc", Font)

///|
let pcf : FileType = ft("pcf", "application/x-font-pcf", "pcf", Font)

///|
let bdf : FileType = ft("bdf", "application/x-font-bdf", "bdf", Font)

///|
let pfa : FileType = ft("pfa", "application/x-font-type1", "pfa", Font)

// ---------------------------------------------------------------------------
// 数据库与科学数据
// ---------------------------------------------------------------------------

///|
let sqlite : FileType = ft(
  "sqlite",
  "application/vnd.sqlite3",
  "sqlite",
  Database,
)

///|
let hdf5 : FileType = ft("hdf5", "application/x-hdf5", "h5", Scientific)

///|
let netcdf : FileType = ft("netcdf", "application/x-netcdf", "nc", Scientific)

///|
let fits : FileType = ft("fits", "application/fits", "fits", Scientific)

///|
let hdf4 : FileType = ft("hdf4", "application/x-hdf", "h4", Scientific)

///|
let grib : FileType = ft("grib", "application/x-grib", "grb", Scientific)

///|
let mat : FileType = ft("mat", "application/x-matlab-data", "mat", Scientific)

///|
let npy : FileType = ft("npy", "application/x-npy", "npy", Scientific)

///|
let parquet : FileType = ft(
  "parquet",
  "application/vnd.apache.parquet",
  "parquet",
  Database,
)

///|
let arrow : FileType = ft(
  "arrow",
  "application/vnd.apache.arrow.file",
  "arrow",
  Database,
)

///|
let avro : FileType = ft("avro", "application/avro", "avro", Database)

///|
let orc : FileType = ft("orc", "application/vnd.apache.orc", "orc", Database)

// ---------------------------------------------------------------------------
// 文本类（由启发式判定）
// ---------------------------------------------------------------------------

///|
let json : FileType = ft("json", "application/json", "json", Text)

///|
let xml : FileType = ft("xml", "application/xml", "xml", Text)

///|
let html : FileType = ft("html", "text/html", "html", Text)

///|
let csv : FileType = ft("csv", "text/csv", "csv", Text)

///|
let plain_text : FileType = ft("text", "text/plain", "txt", Text)

///|
let tsv : FileType = ft("tsv", "text/tab-separated-values", "tsv", Text)

// ---------------------------------------------------------------------------
// 通用容器（需要二次消歧）
// ---------------------------------------------------------------------------

///|
let riff : FileType = ft("riff", "application/octet-stream", "riff", Other)

///|
let ftyp : FileType = ft("ftyp", "application/octet-stream", "ftyp", Other)

///|
let cafebabe : FileType = ft(
  "cafebabe",
  "application/octet-stream",
  "bin",
  Other,
)

///|
let ttf_raw : FileType = ft("ttf-raw", "application/octet-stream", "bin", Other)

///|
let jks : FileType = ft("jks", "application/x-java-keystore", "jks", Other)

///|
let pcap : FileType = ft("pcap", "application/vnd.tcpdump.pcap", "pcap", Other)

// ---------------------------------------------------------------------------
// 签名表
// ---------------------------------------------------------------------------

///|
let signatures : Array[Signature] = [
  // 图片
  {
    offset: 0,
    magic: b"\x89PNG\r\n\x1a\n",
    file_type: png,
    label: "PNG signature",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\xff\xd8\xff",
    file_type: jpeg,
    label: "JPEG SOI marker",
    strong: true,
  },
  {
    offset: 0,
    magic: b"GIF87a",
    file_type: gif,
    label: "GIF87a header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"GIF89a",
    file_type: gif,
    label: "GIF89a header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"II\x2a\x00",
    file_type: tiff,
    label: "TIFF little-endian header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"MM\x00\x2a",
    file_type: tiff,
    label: "TIFF big-endian header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"8BPS",
    file_type: psd,
    label: "Photoshop document signature",
    strong: true,
  },
  {
    offset: 0,
    magic: b"gimp xcf ",
    file_type: xcf,
    label: "GIMP XCF header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x00\x00\x00\x0cjP  \r\n\x87\n",
    file_type: jp2,
    label: "JPEG 2000 JP2 signature box",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x00\x00\x00\x0cJXL \r\n\x87\n",
    file_type: jxl,
    label: "JPEG XL container signature",
    strong: true,
  },
  {
    offset: 0,
    magic: b"icns",
    file_type: icns,
    label: "Apple icon image header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x00\x00\x02\x00",
    file_type: cur,
    label: "Windows cursor header (weak)",
    strong: false,
  },
  {
    offset: 0,
    magic: b"DDS ",
    file_type: dds,
    label: "DirectDraw Surface header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\xabKTX 11\xbb\r\n\x1a\n",
    file_type: ktx,
    label: "KTX 1 texture header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\xabKTX 20\xbb\r\n\x1a\n",
    file_type: ktx2,
    label: "KTX 2 texture header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"v/1\x01",
    file_type: exr,
    label: "OpenEXR header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"#?RADIANCE\n",
    file_type: hdr,
    label: "Radiance HDR header",
    strong: true,
  },
  // 文档
  {
    offset: 0,
    magic: b"%PDF-",
    file_type: pdf,
    label: "PDF header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"%!PS",
    file_type: postscript,
    label: "PostScript header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"{\\rtf",
    file_type: rtf,
    label: "RTF header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"AT&TFORM",
    file_type: djvu,
    label: "DjVu FORM header",
    strong: true,
  },
  {
    offset: 60,
    magic: b"BOOKMOBI",
    file_type: mobi,
    label: "Mobipocket BOOKMOBI header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"ITSF",
    file_type: chm,
    label: "Microsoft Compiled HTML Help header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    file_type: ole2,
    label: "OLE2 compound document",
    strong: true,
  },
  // 归档
  {
    offset: 0,
    magic: b"PK\x03\x04",
    file_type: zip,
    label: "ZIP local file header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"PK\x05\x06",
    file_type: zip,
    label: "ZIP end of central directory",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x1f\x8b\x08",
    file_type: gzip,
    label: "Gzip header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"BZh",
    file_type: bzip2,
    label: "Bzip2 header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\xfd7zXZ\x00",
    file_type: xz,
    label: "XZ header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x28\xb5\x2f\xfd",
    file_type: zstd,
    label: "Zstandard frame magic",
    strong: true,
  },
  {
    offset: 0,
    magic: b"7z\xbc\xaf\x27\x1c",
    file_type: sevenz,
    label: "7-Zip signature",
    strong: true,
  },
  {
    offset: 0,
    magic: b"Rar!\x1a\x07\x00",
    file_type: rar,
    label: "RAR 4 signature",
    strong: true,
  },
  {
    offset: 0,
    magic: b"Rar!\x1a\x07\x01\x00",
    file_type: rar,
    label: "RAR 5 signature",
    strong: true,
  },
  {
    offset: 0,
    magic: b"MSCF",
    file_type: cab,
    label: "Microsoft Cabinet header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x04\x22\x4d\x18",
    file_type: lz4,
    label: "LZ4 frame magic",
    strong: true,
  },
  {
    offset: 0,
    magic: b"070701",
    file_type: cpio,
    label: "cpio newc header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"070702",
    file_type: cpio,
    label: "cpio crc header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"070707",
    file_type: cpio,
    label: "cpio odc header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\xed\xab\xee\xdb",
    file_type: rpm,
    label: "RPM package magic",
    strong: true,
  },
  {
    offset: 0,
    magic: b"!<arch>\ndebian-binary",
    file_type: deb,
    label: "Debian package archive",
    strong: true,
  },
  {
    offset: 0,
    magic: b"!<arch>\n",
    file_type: ar,
    label: "Unix ar archive",
    strong: true,
  },
  {
    offset: 0,
    magic: b"xar!",
    file_type: xar,
    label: "XAR archive header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"hsqs",
    file_type: squashfs,
    label: "SquashFS superblock",
    strong: true,
  },
  {
    offset: 0,
    magic: b"Cr24",
    file_type: crx,
    label: "Chrome extension header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x1f\x9d",
    file_type: compress_z,
    label: "Unix compress (.Z) magic",
    strong: true,
  },
  {
    offset: 32769,
    magic: b"CD001",
    file_type: iso,
    label: "ISO 9660 primary volume descriptor",
    strong: true,
  },
  {
    offset: 257,
    magic: b"ustar",
    file_type: tar,
    label: "POSIX tar ustar header",
    strong: true,
  },
  // 可执行与字节码
  {
    offset: 0,
    magic: b"\x7fELF",
    file_type: elf,
    label: "ELF header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x00asm\x01\x00\x00\x00",
    file_type: wasm,
    label: "WebAssembly 1.0 module header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"dex\n035\x00",
    file_type: dex,
    label: "Dalvik executable header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x1bLua",
    file_type: luac,
    label: "Lua bytecode header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\xcf\xfa\xed\xfe",
    file_type: macho,
    label: "Mach-O 64-bit header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\xce\xfa\xed\xfe",
    file_type: macho,
    label: "Mach-O 32-bit header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\xca\xfe\xba\xbe",
    file_type: cafebabe,
    label: "CAFEBABE header",
    strong: true,
  },
  // 数据库与科学数据
  {
    offset: 0,
    magic: b"SQLite format 3\x00",
    file_type: sqlite,
    label: "SQLite 3 database header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x89HDF\r\n\x1a\n",
    file_type: hdf5,
    label: "HDF5 signature",
    strong: true,
  },
  {
    offset: 0,
    magic: b"CDF\x01",
    file_type: netcdf,
    label: "NetCDF classic header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"CDF\x02",
    file_type: netcdf,
    label: "NetCDF 64-bit header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"SIMPLE  =",
    file_type: fits,
    label: "FITS header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x0e\x03\x13\x01",
    file_type: hdf4,
    label: "HDF4 magic number",
    strong: true,
  },
  {
    offset: 0,
    magic: b"GRIB",
    file_type: grib,
    label: "GRIB edition header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"MATLAB 5.0 MAT-file",
    file_type: mat,
    label: "MATLAB MAT-file header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x93NUMPY\x01\x00",
    file_type: npy,
    label: "NumPy array header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"PAR1",
    file_type: parquet,
    label: "Apache Parquet magic",
    strong: true,
  },
  {
    offset: 0,
    magic: b"ARROW1\x00\x00",
    file_type: arrow,
    label: "Apache Arrow IPC file header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"Obj\x01",
    file_type: avro,
    label: "Apache Avro object container header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"ORC",
    file_type: orc,
    label: "Apache ORC file header (weak)",
    strong: false,
  },
  // 音频
  {
    offset: 0,
    magic: b"fLaC",
    file_type: flac,
    label: "FLAC stream marker",
    strong: true,
  },
  {
    offset: 0,
    magic: b"OggS",
    file_type: ogg,
    label: "Ogg page header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"MThd",
    file_type: midi,
    label: "MIDI header chunk",
    strong: true,
  },
  {
    offset: 0,
    magic: b"ID3",
    file_type: mp3,
    label: "ID3v2 tag",
    strong: true,
  },
  {
    offset: 0,
    magic: b"FORM",
    file_type: iff,
    label: "IFF container",
    strong: true,
  },
  {
    offset: 0,
    magic: b".snd",
    file_type: au,
    label: "Sun/NeXT audio header (weak)",
    strong: false,
  },
  {
    offset: 0,
    magic: b"wvpk",
    file_type: wavpack,
    label: "WavPack block header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"MAC ",
    file_type: ape,
    label: "Monkey's Audio header (weak)",
    strong: false,
  },
  {
    offset: 0,
    magic: b"#!AMR\n",
    file_type: amr,
    label: "AMR audio header",
    strong: true,
  },
  // 视频
  {
    offset: 0,
    magic: b"\x1a\x45\xdf\xa3",
    file_type: ebml,
    label: "EBML container (Matroska/WebM)",
    strong: true,
  },
  {
    offset: 0,
    magic: b"FLV\x01",
    file_type: flv,
    label: "FLV header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x00\x00\x01\xba",
    file_type: mpeg,
    label: "MPEG program stream pack header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c",
    file_type: asf,
    label: "ASF/WMA/WMV container header",
    strong: true,
  },
  // 通用容器
  {
    offset: 0,
    magic: b"RIFF",
    file_type: riff,
    label: "RIFF container",
    strong: true,
  },
  {
    offset: 4,
    magic: b"ftyp",
    file_type: ftyp,
    label: "ISO base media file format",
    strong: true,
  },
  {
    offset: 0,
    magic: b"OTTO",
    file_type: otf,
    label: "OpenType CFF font header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"wOFF",
    file_type: woff,
    label: "WOFF font header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"wOF2",
    file_type: woff2,
    label: "WOFF2 font header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"ttcf",
    file_type: ttc,
    label: "TrueType collection header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x01fcp",
    file_type: pcf,
    label: "PCF font header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"STARTFONT ",
    file_type: bdf,
    label: "BDF font header",
    strong: true,
  },
  // 文本类中的结构化标记
  {
    offset: 0,
    magic: b"-----BEGIN PGP",
    file_type: pgp,
    label: "PGP armor header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"-----BEGIN ",
    file_type: pem,
    label: "PEM armor header",
    strong: true,
  },
  // 弱签名：只能给出 probable
  {
    offset: 0,
    magic: b"\x00\x00\x01\x00",
    file_type: ico,
    label: "ICO header (weak)",
    strong: false,
  },
  {
    offset: 0,
    magic: b"\x00\x01\x00\x00",
    file_type: ttf_raw,
    label: "TrueType sfnt version (weak)",
    strong: false,
  },
  {
    offset: 0,
    magic: b"BM",
    file_type: bmp,
    label: "BMP header (weak)",
    strong: false,
  },
  {
    offset: 0,
    magic: b"P4",
    file_type: pnm,
    label: "Portable bitmap header (weak)",
    strong: false,
  },
  {
    offset: 0,
    magic: b"P5",
    file_type: pnm,
    label: "Portable graymap header (weak)",
    strong: false,
  },
  {
    offset: 0,
    magic: b"P6",
    file_type: pnm,
    label: "Portable pixmap header (weak)",
    strong: false,
  },
  {
    offset: 0,
    magic: b"\xfe\xed\xfe\xed",
    file_type: jks,
    label: "Java KeyStore header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"\x0a\x0d\x0d\x0a",
    file_type: pcap,
    label: "pcap/pcapng block header",
    strong: true,
  },
  {
    offset: 0,
    magic: b"MZ",
    file_type: pe,
    label: "DOS/PE header (weak)",
    strong: false,
  },
  {
    offset: 0,
    magic: b"\xff\xfb",
    file_type: mp3,
    label: "MPEG audio frame sync (weak)",
    strong: false,
  },
  {
    offset: 0,
    magic: b"\xff\xf3",
    file_type: mp3,
    label: "MPEG audio frame sync (weak)",
    strong: false,
  },
  {
    offset: 0,
    magic: b"\xff\xf2",
    file_type: mp3,
    label: "MPEG audio frame sync (weak)",
    strong: false,
  },
  {
    offset: 0,
    magic: b"\xff\xf1",
    file_type: aac,
    label: "ADTS AAC frame sync (weak)",
    strong: false,
  },
  {
    offset: 0,
    magic: b"\xff\xf9",
    file_type: aac,
    label: "ADTS AAC frame sync (weak)",
    strong: false,
  },
]

///|
/// 由启发式判定的文本类型，用于 `--list-types`。
let text_types : Array[FileType] = [json, xml, html, csv, tsv, plain_text]
