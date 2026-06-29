use regex::bytes::Regex;
use std::sync::LazyLock;

use crate::codecs;
use crate::error::KrpanoDecryptError;

static ENCRYPTED_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)<encrypted>(?P<body>.*?)</encrypted>"#).unwrap());
static CDATA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)<!\[CDATA\[(?P<cdata>.*?)\]\]>"#).unwrap());

/// Return `true` if the input contains a krpano `<encrypted>` payload.
pub fn is_encrypted_xml(contents: &[u8]) -> bool {
    ENCRYPTED_RE.is_match(contents)
}

/// Extract the raw encrypted payload from a krpano XML document.
///
/// CDATA sections inside `<encrypted>` are concatenated. If there is no CDATA,
/// the trimmed element body is returned directly.
pub fn encrypted_payload(contents: &[u8]) -> Result<Vec<u8>, KrpanoDecryptError> {
    if !ENCRYPTED_RE.is_match(contents) {
        return Err(KrpanoDecryptError::MissingEncryptedPayload);
    }
    let body = ENCRYPTED_RE
        .captures(contents)
        .and_then(|caps| caps.name("body"))
        .ok_or(KrpanoDecryptError::MissingEncryptedPayload)?
        .as_bytes();
    let mut payload = Vec::new();
    for caps in CDATA_RE.captures_iter(body) {
        if let Some(cdata) = caps.name("cdata") {
            payload.extend_from_slice(cdata.as_bytes());
        }
    }
    if payload.is_empty() {
        payload.extend_from_slice(trim_ascii(body));
    }
    Ok(payload)
}

/// Known wrapper key prefixes used across krpano versions.
const WRAPPER_KEY_PREFIXES: &[&[u8]] = &[b"krp:", b"ptp:"];

/// Extract the `krp:` or `ptp:` wrapper key from krpano viewer JavaScript.
pub fn extract_key_from_viewer_js(contents: &[u8]) -> Result<String, KrpanoDecryptError> {
    log::debug!(
        "extract_key_from_viewer_js: scanning {} bytes for wrapper key",
        contents.len()
    );
    let mut candidates = 0usize;
    let mut idx = 0;
    while let Some((literal, next_idx)) = next_js_string_literal(contents, idx) {
        idx = next_idx;
        candidates += 1;
        for prefix in WRAPPER_KEY_PREFIXES {
            if literal.starts_with(prefix) {
                let literal =
                    String::from_utf8(literal).map_err(|_| KrpanoDecryptError::InvalidUtf8)?;
                log::debug!(
                    "extract_key_from_viewer_js: found {} key at offset {}, length {}",
                    String::from_utf8_lossy(prefix),
                    next_idx - literal.len() - 2,
                    literal.len()
                );
                return Ok(literal);
            }
        }
    }
    log::debug!("extract_key_from_viewer_js: no wrapper key found");
    Err(KrpanoDecryptError::MissingKrpKey {
        candidates,
        js_len: contents.len(),
    })
}

/// Decode the packed viewer engine embedded in krpano viewer JavaScript.
pub fn extract_decoded_viewer_js(contents: &[u8]) -> Result<Vec<u8>, KrpanoDecryptError> {
    log::debug!(
        "extract_decoded_viewer_js: scanning {} bytes for packed viewer",
        contents.len()
    );
    let mut idx = 0;
    let mut candidates = 0u32;
    while let Some((literal, next_idx)) = next_js_string_literal(contents, idx) {
        idx = next_idx;
        if !looks_like_modified_base85(&literal) {
            continue;
        }
        candidates += 1;
        match decode_packed_viewer_candidate(&literal) {
            Ok(decoded) if looks_like_decoded_viewer_js(&decoded) => {
                log::debug!(
                    "extract_decoded_viewer_js: decoded packed viewer (candidate #{candidates}, raw={} chars, decoded={} bytes)",
                    literal.len(),
                    decoded.len()
                );
                return Ok(decoded);
            }
            Ok(decoded) => {
                log::debug!(
                    "extract_decoded_viewer_js: candidate #{candidates} decoded but doesn't look like viewer JS ({} bytes, prefix: {})",
                    decoded.len(),
                    String::from_utf8_lossy(&decoded[..200.min(decoded.len())])
                );
            }
            Err(e) => {
                log::debug!(
                    "extract_decoded_viewer_js: candidate #{candidates} ({len} chars) decode failed: {e}",
                    len = literal.len()
                );
            }
        }
    }
    log::debug!(
        "extract_decoded_viewer_js: no valid packed viewer found ({candidates} modified-Base85 candidates scanned)"
    );
    Err(KrpanoDecryptError::MissingViewerJsPayload)
}

fn decode_packed_viewer_candidate(input: &[u8]) -> Result<Vec<u8>, KrpanoDecryptError> {
    match codecs::decode_packed_viewer_js_payload(input) {
        Ok(decoded) if looks_like_decoded_viewer_js(&decoded) => Ok(decoded),
        Ok(decoded) => match codecs::decode_packed_viewer_js_payload_little_endian(input) {
            Ok(little_endian) => Ok(little_endian),
            Err(_) => Ok(decoded),
        },
        Err(big_endian_error) => match codecs::decode_packed_viewer_js_payload_little_endian(input)
        {
            Ok(decoded) => Ok(decoded),
            Err(_) => Err(big_endian_error),
        },
    }
}

pub fn next_js_string_literal(bytes: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let mut idx = start;
    while idx < bytes.len() {
        let quote = bytes[idx];
        if quote != b'"' && quote != b'\'' {
            idx += 1;
            continue;
        }

        idx += 1;
        let mut literal = Vec::new();
        while idx < bytes.len() {
            let byte = bytes[idx];
            if byte == quote {
                return Some((literal, idx + 1));
            }
            if byte == b'\\' {
                idx += 1;
                if idx >= bytes.len() {
                    return None;
                }
                match bytes[idx] {
                    b'x' => {
                        if idx + 2 >= bytes.len() {
                            return None;
                        }
                        let value = (hex_digit(bytes[idx + 1])? << 4) | hex_digit(bytes[idx + 2])?;
                        literal.push(value);
                        idx += 3;
                    }
                    b'u' => {
                        if idx + 4 >= bytes.len() {
                            return None;
                        }
                        let value = (u32::from(hex_digit(bytes[idx + 1])?) << 12)
                            | (u32::from(hex_digit(bytes[idx + 2])?) << 8)
                            | (u32::from(hex_digit(bytes[idx + 3])?) << 4)
                            | u32::from(hex_digit(bytes[idx + 4])?);
                        let ch = char::from_u32(value)?;
                        let mut buf = [0; 4];
                        literal.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        idx += 5;
                    }
                    b'\r' => {
                        idx += 1;
                        if idx < bytes.len() && bytes[idx] == b'\n' {
                            idx += 1;
                        }
                    }
                    b'\n' => {
                        idx += 1;
                    }
                    b'b' => {
                        literal.push(0x08);
                        idx += 1;
                    }
                    b'f' => {
                        literal.push(0x0c);
                        idx += 1;
                    }
                    b'n' => {
                        literal.push(b'\n');
                        idx += 1;
                    }
                    b'r' => {
                        literal.push(b'\r');
                        idx += 1;
                    }
                    b't' => {
                        literal.push(b'\t');
                        idx += 1;
                    }
                    b'v' => {
                        literal.push(0x0b);
                        idx += 1;
                    }
                    escaped => {
                        literal.push(escaped);
                        idx += 1;
                    }
                }
                continue;
            }
            literal.push(byte);
            idx += 1;
        }
        return None;
    }
    None
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn looks_like_modified_base85(input: &[u8]) -> bool {
    input.len() >= codecs::MIN_PACKED_VIEWER_PAYLOAD_LEN
        && input.len() % 5 == 0
        && input.iter().copied().all(|byte| {
            byte.checked_sub(35)
                .map(|mut digit| {
                    if digit > 56 {
                        digit -= 1;
                    }
                    digit < 85
                })
                .unwrap_or(false)
        })
}

pub fn looks_like_decoded_viewer_js(input: &[u8]) -> bool {
    input.starts_with(b"function ")
        && (contains_bytes(input, b"loadpano")
            || contains_bytes(input, b"embedhtml5")
            || contains_bytes(input, b"krpano"))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |idx| idx + 1);
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_and_concatenates_encrypted_cdata() {
        let xml = br#"<encrypted><![CDATA[KENCR]]><![CDATA[URRpayload]]></encrypted>"#;
        assert!(is_encrypted_xml(xml));
        assert_eq!(encrypted_payload(xml).unwrap(), b"KENCRURRpayload");
    }

    #[test]
    fn extracts_krpano_decryption_key_from_viewer_js() {
        let js = br#"return function(t){r&&(h=r(),r=null);h(t,"krp:abc def")}"#;
        assert_eq!(
            extract_key_from_viewer_js(js).unwrap(),
            "krp:abc def".to_string()
        );
        let js2 = br"embedhtml5(e.params,'krp:xyz123')";
        assert_eq!(
            extract_key_from_viewer_js(js2).unwrap(),
            "krp:xyz123".to_string()
        );
    }
}
