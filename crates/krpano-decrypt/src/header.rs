use crate::error::KrpanoDecryptError;

// ---------------------------------------------------------------------------
// Body cipher — what transform pipeline decrypts the body
// ---------------------------------------------------------------------------

/// How the encrypted body is encoded and decrypted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyCipher {
    /// Modified Base85 → RC4 byte-decrypt → LZ4 decompress.
    /// Used by headers with byte 6 = `Z` (charCode − 80 = 10).
    ClassicZ,
    /// Standard Base64 → RC4 byte-decrypt.
    /// Used by headers with byte 6 = `B` (charCode − 80 = −14).
    ClassicB,
    /// Token replacement (`z`→`\`) → `we.subdiv` branch 5 decompress.
    /// Used by headers with byte 6 = `P` or `R` (charCode − 80 = 0 or 2).
    Subdiv,
}

// ---------------------------------------------------------------------------
// Cipher mode — whether a license-derived key is required
// ---------------------------------------------------------------------------

/// Whether the body requires a license-derived key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherMode {
    /// No license key needed (header byte 4 = `P` or `U`, mode value 0).
    Public,
    /// License-derived key required (header byte 4 = `R`, mode value 1).
    Protected,
}

// ---------------------------------------------------------------------------
// KencHeader
// ---------------------------------------------------------------------------

/// Parsed eight-byte `KENC....` header that prefixes every encrypted payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KencHeader {
    /// The full eight-byte `KENC....` marker as it appears in the payload.
    pub raw: String,
    /// The body transform pipeline determined from byte 6.
    pub cipher: BodyCipher,
    /// Whether a license key is needed, determined from byte 4.
    pub mode: CipherMode,
    /// Raw byte 5 (encoding). Always `U` in observed fixtures.
    pub encoding: char,
    /// Raw byte 7 (flags). Always `R` in observed fixtures.
    pub flags: char,
}

impl KencHeader {
    pub const LEN: usize = 8;

    /// `k = (r << 4) + (r << 2)` where `r = 4` in the modern engine.
    const K: u32 = 80;

    pub fn parse(payload: &[u8]) -> Result<Self, KrpanoDecryptError> {
        let header = payload
            .get(..Self::LEN)
            .ok_or(KrpanoDecryptError::HeaderTooShort { len: payload.len() })?;
        if !header.starts_with(b"KENC") {
            return Err(KrpanoDecryptError::InvalidHeader {
                header: String::from_utf8_lossy(header).into_owned(),
            });
        }

        let raw = String::from_utf8_lossy(header).into_owned();
        let (mode_byte, enc_byte, src_byte, flags_byte) =
            (header[4], header[5], header[6], header[7]);

        let byte6_value = u32::from(src_byte).wrapping_sub(Self::K) as i32;
        let mode_value = (u32::from(mode_byte).wrapping_sub(Self::K) >> 1) as i32;

        let cipher = match byte6_value {
            10 => BodyCipher::ClassicZ,
            -14 => BodyCipher::ClassicB,
            0 | 2 => BodyCipher::Subdiv,
            _ => return Err(KrpanoDecryptError::InvalidHeader { header: raw }),
        };

        let mode = match mode_value {
            0 => CipherMode::Public,
            1 => CipherMode::Protected,
            _ => return Err(KrpanoDecryptError::InvalidHeader { header: raw }),
        };

        Ok(Self {
            raw,
            cipher,
            mode,
            encoding: char::from(enc_byte),
            flags: char::from(flags_byte),
        })
    }

    /// Return the payload bytes after the header.
    pub fn payload<'a>(&self, payload: &'a [u8]) -> &'a [u8] {
        &payload[Self::LEN..]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_kenc_headers() {
        let public_z = KencHeader::parse(b"KENCPUZRpayload").unwrap();
        assert_eq!(public_z.payload(b"KENCPUZRpayload"), b"payload");
        assert_eq!(public_z.cipher, BodyCipher::ClassicZ);
        assert_eq!(public_z.mode, CipherMode::Public);
        assert_eq!(public_z.encoding, 'U');
        assert_eq!(public_z.flags, 'R');

        let protected_subdiv = KencHeader::parse(b"KENCRURRpayload").unwrap();
        assert_eq!(protected_subdiv.cipher, BodyCipher::Subdiv);
        assert_eq!(protected_subdiv.mode, CipherMode::Protected);
    }

    #[test]
    fn classifies_all_observed_headers() {
        // Old Z: KENCRUZR → ClassicZ + Protected
        let h = KencHeader::parse(b"KENCRUZR....").unwrap();
        assert_eq!(h.cipher, BodyCipher::ClassicZ);
        assert_eq!(h.mode, CipherMode::Protected);

        // Modern Z: KENCPUZR → ClassicZ + Public
        let h = KencHeader::parse(b"KENCPUZR....").unwrap();
        assert_eq!(h.cipher, BodyCipher::ClassicZ);
        assert_eq!(h.mode, CipherMode::Public);

        // Protected subdiv: KENCRURR → Subdiv + Protected
        let h = KencHeader::parse(b"KENCRURR....").unwrap();
        assert_eq!(h.cipher, BodyCipher::Subdiv);
        assert_eq!(h.mode, CipherMode::Protected);

        // Public subdiv: KENCPUPR → Subdiv + Public
        let h = KencHeader::parse(b"KENCPUPR....").unwrap();
        assert_eq!(h.cipher, BodyCipher::Subdiv);
        assert_eq!(h.mode, CipherMode::Public);

        // Classic B: KENCPUBR → ClassicB + Public
        let h = KencHeader::parse(b"KENCPUBR....").unwrap();
        assert_eq!(h.cipher, BodyCipher::ClassicB);
        assert_eq!(h.mode, CipherMode::Public);
    }

    #[test]
    fn rejects_invalid_kenc_headers() {
        assert!(matches!(
            KencHeader::parse(b"short"),
            Err(KrpanoDecryptError::HeaderTooShort { len: 5 })
        ));
        assert!(matches!(
            KencHeader::parse(b"NOTKENC!payload"),
            Err(KrpanoDecryptError::InvalidHeader { .. })
        ));
        // Unknown byte 6 value
        assert!(matches!(
            KencHeader::parse(b"KENCXXXR...."),
            Err(KrpanoDecryptError::InvalidHeader { .. })
        ));
    }
}
