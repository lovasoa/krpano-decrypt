//! Error type for the krpano decryption pipeline.
//!
//! Every decryption failure maps to one of these variants. The names mirror the
//! pipeline stages described in `PLAN.md` so that a failing fixture can be
//! triaged against the format documentation.

use thiserror::Error;

/// Structured failures from the modern `krp:`/`ptp:` wrapper unpacker.
#[derive(Debug, Error, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum ModernWrapperKeyError {
    #[error("startup IIFE has no opening brace")]
    MissingOpeningBrace,

    #[error("startup IIFE has no closing brace")]
    MissingClosingBrace,

    #[error("startup IIFE body has invalid brace order")]
    InvalidBraceOrder,

    #[error(
        "invalid startup arithmetic for checksum constant {startup_constant}: modulo base is zero"
    )]
    ZeroModuloBase { startup_constant: u32 },

    #[error(
        "wrapper key is too short for startup parameters: need byte index {needed_index}, length {key_len}"
    )]
    ShortStartupParameter { needed_index: usize, key_len: usize },

    #[error("startup browser-marker index {index} is outside the {len}-byte browser marker")]
    BrowserMarkerIndexOutOfRange { index: usize, len: usize },

    #[error("startup shuffle index {index} is outside the {len}-entry shuffle table")]
    ShuffleIndexOutOfRange { index: usize, len: usize },

    #[error(
        "wrapper key is too short for checksum tail: need byte index {needed_index}, length {key_len}"
    )]
    ShortChecksumTail { needed_index: usize, key_len: usize },

    #[error("wrapper key checksum mismatch: got {got}, expected {expected}")]
    ChecksumMismatch { got: i32, expected: i32 },
}

/// All errors produced by the krpano decryption pipeline.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum KrpanoDecryptError {
    #[error("encrypted krpano XML did not contain an <encrypted> payload")]
    MissingEncryptedPayload,

    #[error("krpano viewer JavaScript did not contain a decodable embedded payload")]
    MissingViewerJsPayload,

    #[error("encrypted krpano XML needs the krpano viewer JavaScript decryption key")]
    MissingKey,

    #[error(
        "encrypted krpano XML needs the matching viewer JS for this payload variant: cipher={cipher} mode={mode}"
    )]
    ViewerJsRequired { cipher: String, mode: String },

    #[error(
        "no krp: wrapper key found in viewer JS (scanned {candidates} string literals in {js_len}-byte file; krpano 1.20+ may embed keys differently)"
    )]
    MissingKrpKey { candidates: usize, js_len: usize },

    #[error("encrypted krpano payload is too short to contain a KENC header (length {len})")]
    HeaderTooShort { len: usize },

    #[error("encrypted krpano payload has an invalid KENC header: {header}")]
    InvalidHeader { header: String },

    #[error("encrypted krpano payload contains an invalid modified-base85 byte: {byte}")]
    InvalidBase85Byte { byte: u8 },

    #[error("encrypted krpano payload contains an invalid LZ4 block")]
    InvalidLz4Block,

    #[error("encrypted krpano payload cannot be byte-decrypted with the provided key")]
    InvalidByteCipherInput,

    #[error("decrypted krpano payload is not valid UTF-8")]
    InvalidUtf8,

    #[error("modern krpano wrapper key could not be unpacked: {0}")]
    InvalidModernWrapperKey(ModernWrapperKeyError),

    #[error("ClassicB Base64 alphabet has only {len} characters, must be >= 65")]
    ClassicBAlphabetTooShort { len: usize },

    #[error("character '{ch}' not found in ClassicB Base64 alphabet ({alphabet_len} chars)")]
    ClassicBCharNotFound { ch: char, alphabet_len: usize },

    #[error("encrypted krpano XML decryption is not implemented for this payload variant yet")]
    Unsupported,

    #[error("KENC combination not supported: cipher={cipher} mode={mode} engine={engine}")]
    UnsupportedCombination {
        cipher: String,
        mode: String,
        engine: String,
    },
}
