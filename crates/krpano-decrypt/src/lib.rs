//! # krpano-decrypt
//!
//! A standalone Rust library for decrypting encrypted krpano tour XML and
//! obfuscated viewer JavaScript.
//!
//! krpano (https://krpano.com) is a panorama viewer that ships tours as an
//! encrypted XML file (`tour.xml`) together with an obfuscated JavaScript
//! engine (`tour.js`). This crate reverse-engineers the on-disk format and
//! decrypts the XML without executing any JavaScript.
//!
//! ## Quick start
//!
//! ```no_run
//! use krpano_decrypt::decrypt_xml;
//!
//! let xml = std::fs::read("tour.xml").unwrap();
//! let js  = std::fs::read("tour.js").unwrap();
//! let plaintext = decrypt_xml(&xml, Some(&js)).unwrap();
//! std::fs::write("tour.decrypted.xml", plaintext).unwrap();
//! ```
//!
//! For public ClassicB / ClassicZ payloads whose stable constants are known,
//! `viewer_data` may be `None`. Other payload variants return a structured
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

#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[allow(missing_docs)]
pub mod branches;
#[allow(missing_docs)]
pub mod codecs;
#[allow(missing_docs)]
pub mod crypto;
#[allow(missing_docs)]
pub mod engine;
pub mod error;
#[allow(missing_docs)]
pub mod header;
#[allow(missing_docs)]
pub mod modern_engine;
#[allow(missing_docs)]
pub mod old_engine;
#[allow(missing_docs)]
pub mod viewer;

pub use engine::{EngineFamily, decrypt_xml, detect_engine};
pub use error::KrpanoDecryptError;
pub use header::{BodyCipher, CipherMode, KencHeader};
pub use viewer::{
    encrypted_payload, extract_decoded_viewer_js, extract_key_from_viewer_js, is_encrypted_xml,
};

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
