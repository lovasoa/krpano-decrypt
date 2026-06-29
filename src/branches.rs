use crate::codecs;
use crate::crypto;
use crate::error::KrpanoDecryptError;

// ---------------------------------------------------------------------------
// Z branch (ClassicZ cipher) — Modified Base85 → RC4 → LZ4
// ---------------------------------------------------------------------------

/// Decrypt a ClassicZ-cipher encrypted body into raw bytes.
///
/// Pipeline: modified Base85 decode → byte decrypt (RC4-like) →
/// parse LZ4 block header → LZ4 decompress.
///
/// The first 128 bytes of the Base85-decoded data serve as the RC4
/// key-mixing prefix; the remainder is LZ4-compressed plaintext.
/// The LZ4 block carries an 8-byte header: 3-byte LE decompressed length,
/// then at offset 4 a 3-byte LE compressed length.
pub fn decrypt_z_branch(
    body: &[u8],
    key: &[u8],
    widened: bool,
) -> Result<Vec<u8>, KrpanoDecryptError> {
    let decoded = codecs::decode_modified_base85(body)?;
    let decrypted = crypto::decrypt_bytes(&decoded, key, widened)?;

    if decrypted.len() < codecs::PACKED_VIEWER_HEADER_LEN {
        return Err(KrpanoDecryptError::InvalidLz4Block);
    }

    let decompressed_len = read_u24_le(&decrypted[0..3]);
    if decompressed_len == 0 || decompressed_len > codecs::MAX_DECODED_VIEWER_JS_LEN {
        return Err(KrpanoDecryptError::InvalidLz4Block);
    }
    let compressed_end = codecs::PACKED_VIEWER_HEADER_LEN + read_u24_le(&decrypted[4..7]);
    if compressed_end > decrypted.len() {
        return Err(KrpanoDecryptError::InvalidLz4Block);
    }

    codecs::lz4_decompress_block(
        &decrypted[codecs::PACKED_VIEWER_HEADER_LEN..],
        decompressed_len,
        compressed_end - codecs::PACKED_VIEWER_HEADER_LEN,
    )
}

/// Decrypt a ClassicZ-cipher body into plaintext bytes.
pub fn z_branch_to_plaintext(
    body: &[u8],
    key: &[u8],
    widened: bool,
) -> Result<Vec<u8>, KrpanoDecryptError> {
    decrypt_z_branch(body, key, widened)
}

// ---------------------------------------------------------------------------
// B branch (ClassicB cipher) — Base64 → RC4
// ---------------------------------------------------------------------------

pub fn b_branch_to_plaintext_with_alphabet(
    body: &[u8],
    alphabet: &[u8],
    key: &[u8],
    widened: bool,
) -> Result<Vec<u8>, KrpanoDecryptError> {
    let decoded = decode_custom_base64(body, alphabet)?;
    crypto::decrypt_bytes(&decoded, key, widened)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn decode_custom_base64(input: &[u8], alphabet: &[u8]) -> Result<Vec<u8>, KrpanoDecryptError> {
    if alphabet.len() < 65 {
        return Err(KrpanoDecryptError::ClassicBAlphabetTooShort {
            len: alphabet.len(),
        });
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut chars = input.iter().copied();
    while let (Some(a), Some(b), Some(c), Some(d)) =
        (chars.next(), chars.next(), chars.next(), chars.next())
    {
        let a = alphabet.iter().position(|&ch| ch == a).ok_or(
            KrpanoDecryptError::ClassicBCharNotFound {
                ch: char::from(a),
                alphabet_len: alphabet.len(),
            },
        )?;
        let b = alphabet.iter().position(|&ch| ch == b).ok_or(
            KrpanoDecryptError::ClassicBCharNotFound {
                ch: char::from(b),
                alphabet_len: alphabet.len(),
            },
        )?;
        let c = alphabet.iter().position(|&ch| ch == c).ok_or(
            KrpanoDecryptError::ClassicBCharNotFound {
                ch: char::from(c),
                alphabet_len: alphabet.len(),
            },
        )?;
        let d = alphabet.iter().position(|&ch| ch == d).ok_or(
            KrpanoDecryptError::ClassicBCharNotFound {
                ch: char::from(d),
                alphabet_len: alphabet.len(),
            },
        )?;
        out.push(((a << 2) | (b >> 4)) as u8);
        if c != 64 {
            out.push((((b & 15) << 4) | (c >> 2)) as u8);
        }
        if d != 64 {
            out.push((((c & 3) << 6) | d) as u8);
        }
    }
    Ok(out)
}

fn read_u24_le(input: &[u8]) -> usize {
    usize::from(input[0]) | (usize::from(input[1]) << 8) | (usize::from(input[2]) << 16)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::viewer;
    use std::fs;
    use std::path::Path;

    fn trim_xml_start(bytes: &[u8]) -> &[u8] {
        let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
        let start = bytes
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .unwrap_or(bytes.len());
        &bytes[start..]
    }

    #[test]
    fn decrypts_2018_04_04_z_branch() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/encrypted/2018-04-04");
        let xml = fs::read_to_string(root.join("tour.xml")).unwrap();
        let payload = viewer::encrypted_payload(xml.as_bytes()).unwrap();
        let header = crate::header::KencHeader::parse(&payload).unwrap();
        let body = header.payload(&payload);

        let plaintext = z_branch_to_plaintext(body, b"actions overflow", false).unwrap();
        assert!(trim_xml_start(&plaintext).starts_with(b"<krpano"));
    }

    #[test]
    fn decrypts_old_z_branch() {
        for fixture in ["old", "2015-08-04", "2017-09-21"] {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("testdata/encrypted")
                .join(fixture);
            let xml = fs::read_to_string(root.join("tour.xml")).unwrap();
            let payload = viewer::encrypted_payload(xml.as_bytes()).unwrap();
            let header = crate::header::KencHeader::parse(&payload).unwrap();
            let body = header.payload(&payload);

            // Derive the old engine key
            let js = fs::read(
                ["tour.js", "krpano.js"]
                    .iter()
                    .map(|name| root.join(name))
                    .find(|p| p.exists())
                    .unwrap(),
            )
            .unwrap();
            let decoded = viewer::extract_decoded_viewer_js(&js).unwrap();
            let wrapper_key = viewer::extract_key_from_viewer_js(&js).unwrap();
            let ctx = crate::old_engine::derive_old_license_key(&decoded, &wrapper_key).unwrap();
            let key = ctx.protected_key.as_ref().unwrap();

            let plaintext = z_branch_to_plaintext(body, key, true).unwrap();
            let normalized = trim_xml_start(&plaintext);
            assert!(
                normalized.starts_with(b"<krpano"),
                "{fixture}: bad plaintext prefix: {:?}",
                String::from_utf8_lossy(normalized)
            );
        }
    }

    #[test]
    fn decrypts_old_b_branch() {
        for fixture in ["2013-06-05-B", "2013-08-09-B"] {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("testdata/encrypted")
                .join(fixture);
            let xml = fs::read_to_string(root.join("tour.xml")).unwrap();
            let payload = viewer::encrypted_payload(xml.as_bytes()).unwrap();
            let header = crate::header::KencHeader::parse(&payload).unwrap();
            let body = header.payload(&payload);

            let js = fs::read(
                ["tour.js", "krpano.js"]
                    .iter()
                    .map(|name| root.join(name))
                    .find(|p| p.exists())
                    .unwrap(),
            )
            .unwrap();
            let decoded = viewer::extract_decoded_viewer_js(&js).unwrap();
            let wrapper_key = viewer::extract_key_from_viewer_js(&js).unwrap();
            let ctx = crate::old_engine::derive_old_license_key(&decoded, &wrapper_key).unwrap();

            let key = &ctx.default_key;
            let plaintext = b_branch_to_plaintext_with_alphabet(
                body,
                ctx.base64_alphabet.as_bytes(),
                key,
                false,
            )
            .unwrap();
            assert!(
                trim_xml_start(&plaintext).starts_with(b"<krpano"),
                "{fixture}: bad plaintext prefix"
            );
        }
    }
}
