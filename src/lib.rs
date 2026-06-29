//! # krpano-decrypt
//!
//! A standalone Rust library for decrypting encrypted krpano tour XML and
//! obfuscated viewer JavaScript.
//!
//! krpano (<https://krpano.com>) is a panorama viewer that ships tours as an
//! encrypted XML file (`tour.xml`) together with an obfuscated JavaScript
//! engine (`tour.js`). This crate reverse-engineers the on-disk format and
//! decrypts the XML without executing any JavaScript.
//!
//! ## Quick start
//!
//! ```no_run
//! use krpano_decrypt::{decrypt_xml, inspect_with_viewer};
//!
//! let xml = std::fs::read("tour.xml").unwrap();
//! let js  = std::fs::read("tour.js").unwrap();
//! let info = inspect_with_viewer(&xml, Some(&js)).unwrap();
//! eprintln!("{:?}", info);
//! let plaintext = decrypt_xml(&xml, Some(&js)).unwrap();
//! std::fs::write("tour.decrypted.xml", plaintext).unwrap();
//! ```
//!
//! For public ClassicB, ClassicZ, and Subdiv payloads whose stable constants
//! are known, `viewer_data` may be `None`. Other payload variants return a structured
//! [`KrpanoDecryptError::ViewerJsRequired`] error.
//!
//! ## Format documentation
//!
//! The implementation-independent description of the encrypted format lives in
//! [`PLAN.md`](https://github.com/lovasoa/krpano-decrypt/blob/main/PLAN.md) at
//! the repository root. The architecture of this crate is documented in
//! [`AGENTS.md`](https://github.com/lovasoa/krpano-decrypt/blob/main/AGENTS.md).
//!
//! ## Design
//!
//! - **No JavaScript execution.** Keys are recovered by static analysis of the
//!   decoded engine source. The engine is never evaluated.
//! - **Value-based row identification.** Row extraction searches by stable
//!   semantic values (`"actions overflow"`, `"krpano"`) rather than hardcoded
//!   minified identifiers, so it generalises across engine builds.
//! - **Deterministic.** Decryption is a pure function of the two input files.

#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod branches;
mod codecs;
mod crypto;
mod engine;
pub mod error;
mod header;
mod modern_engine;
mod old_engine;
mod viewer;

pub use engine::{EngineFamily, decrypt_xml, detect_engine};
pub use error::KrpanoDecryptError;
pub use header::{BodyCipher, CipherMode, KencHeader};
pub use viewer::{
    encrypted_payload, extract_decoded_viewer_js, extract_key_from_viewer_js, is_encrypted_xml,
};

/// Decode the packed krpano viewer engine from a viewer JavaScript file.
///
/// This is the programmatic equivalent of the CLI's `decode-viewer` command.
/// It returns the decoded JavaScript source bytes without executing them.
pub fn decode_viewer_js(viewer_data: &[u8]) -> Result<Vec<u8>, KrpanoDecryptError> {
    extract_decoded_viewer_js(viewer_data)
}

/// Extract the `krp:` or `ptp:` wrapper key embedded in a viewer JavaScript file.
///
/// This is the programmatic equivalent of the CLI's `wrapper-key` command.
pub fn wrapper_key(viewer_data: &[u8]) -> Result<String, KrpanoDecryptError> {
    extract_key_from_viewer_js(viewer_data)
}

/// Convenience wrapper that returns the decrypted XML as a UTF-8 string.
///
/// This is equivalent to [`decrypt_xml`] but validates that the output is
/// valid UTF-8 and returns a [`String`].
pub fn decrypt_xml_to_string(
    contents: &[u8],
    viewer_data: Option<&[u8]>,
) -> Result<String, KrpanoDecryptError> {
    let bytes = decrypt_xml(contents, viewer_data)?;
    String::from_utf8(bytes).map_err(|_| KrpanoDecryptError::InvalidUtf8)
}

/// Information about an encrypted payload, returned by [`inspect`].
///
/// Useful for diagnostics and for the `inspect` subcommand of the CLI.
#[derive(Debug, Clone)]
pub struct PayloadInfo {
    /// The raw 8-byte `KENC....` header.
    pub header: String,
    /// The body cipher determined from byte 6 of the header.
    pub cipher: BodyCipher,
    /// Whether a license-derived key is required.
    pub mode: CipherMode,
    /// Length of the encrypted body (after the 8-byte header).
    pub body_len: usize,
    /// Whether the input looks like an encrypted krpano XML document.
    pub is_encrypted: bool,
}

/// Information recovered from a krpano viewer JavaScript file.
///
/// Returned by [`inspect_viewer`] and embedded in [`Inspection`].
#[derive(Debug, Clone)]
pub struct ViewerInfo {
    /// Length of the `krp:`/`ptp:` wrapper key string, when present.
    pub wrapper_key_len: Option<usize>,
    /// Length of the decoded engine JavaScript source, when the packed viewer
    /// payload can be decoded.
    pub decoded_engine_len: Option<usize>,
    /// Engine family detected from the decoded engine source.
    pub engine: Option<EngineFamily>,
}

/// Combined inspection result for an XML payload and an optional viewer file.
///
/// This is the programmatic equivalent of the CLI's `inspect` command.
#[derive(Debug, Clone)]
pub struct Inspection {
    /// Parsed encrypted XML payload information.
    pub payload: PayloadInfo,
    /// Viewer information, if viewer JavaScript was provided.
    pub viewer: Option<ViewerInfo>,
}

/// Inspect an encrypted krpano XML payload without decrypting it.
///
/// Returns the parsed header and body length. If the input is not an encrypted
/// krpano document, `is_encrypted` is `false` and the other fields reflect the
/// parse attempt.
pub fn inspect(contents: &[u8]) -> Result<PayloadInfo, KrpanoDecryptError> {
    if !is_encrypted_xml(contents) {
        return Ok(PayloadInfo {
            header: String::new(),
            cipher: BodyCipher::ClassicZ,
            mode: CipherMode::Public,
            body_len: 0,
            is_encrypted: false,
        });
    }
    let payload = encrypted_payload(contents)?;
    let header = KencHeader::parse(&payload)?;
    let body_len = payload.len().saturating_sub(KencHeader::LEN);
    Ok(PayloadInfo {
        header: header.raw.clone(),
        cipher: header.cipher,
        mode: header.mode,
        body_len,
        is_encrypted: true,
    })
}

/// Inspect a krpano viewer JavaScript file without decrypting an XML payload.
///
/// This scans for the wrapper key, decodes the packed engine when present, and
/// reports the detected engine family. Missing viewer components are reported
/// as `None` fields rather than errors so diagnostics can still be displayed
/// for partially supported viewer files.
pub fn inspect_viewer(viewer_data: &[u8]) -> ViewerInfo {
    let wrapper_key_len = extract_key_from_viewer_js(viewer_data)
        .ok()
        .map(|key| key.len());
    let decoded_engine = extract_decoded_viewer_js(viewer_data).ok();
    let decoded_engine_len = decoded_engine.as_ref().map(Vec::len);
    let engine = decoded_engine.as_deref().map(detect_engine);

    ViewerInfo {
        wrapper_key_len,
        decoded_engine_len,
        engine,
    }
}

/// Inspect an encrypted XML payload and, optionally, its matching viewer JS.
///
/// This is the easiest way to get the same metadata shown by the CLI `inspect`
/// command from Rust code.
pub fn inspect_with_viewer(
    contents: &[u8],
    viewer_data: Option<&[u8]>,
) -> Result<Inspection, KrpanoDecryptError> {
    let payload = inspect(contents)?;
    let viewer = viewer_data.map(inspect_viewer);
    Ok(Inspection { payload, viewer })
}
