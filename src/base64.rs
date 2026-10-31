//! Standard base64, decoded strictly.
//!
//! Hand-written: the clients that use this crate carry no general-purpose base64
//! dependency, and the inputs are small and fixed in form.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decode standard base64 with padding and no whitespace. `None` for anything
/// else: a length that is not a multiple of four, a character outside the
/// alphabet, padding anywhere but the last two places, or data after it.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    let mut padding = 0usize;
    for (index, &ch) in bytes.iter().enumerate() {
        if ch == b'=' {
            if index + 2 < bytes.len() {
                return None;
            }
            padding += 1;
            buffer <<= 6;
        } else {
            if padding > 0 {
                return None;
            }
            let value = ALPHABET.iter().position(|b| *b == ch)? as u32;
            buffer = (buffer << 6) | value;
        }
        bits += 6;
        if bits == 24 {
            out.extend_from_slice(&[(buffer >> 16) as u8, (buffer >> 8) as u8, buffer as u8]);
            buffer = 0;
            bits = 0;
        }
    }
    // The bytes the padding stands for are zero in a canonical encoding: bits
    // set there are a second spelling of the same value.
    if out[out.len() - padding..].iter().any(|byte| *byte != 0) {
        return None;
    }
    out.truncate(out.len() - padding);
    Some(out)
}

/// Encode as standard base64 with padding. The inverse of [`decode`]; used to
/// write keys and signatures in the tests, and nowhere else.
#[cfg(test)]
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // TEST0001: decoding inverts encoding for every length modulo three, so
    // both padding forms and the unpadded form are read back exactly.
    #[test]
    fn test0001_decode_inverts_encode_for_every_padding() {
        for len in 0..12usize {
            let bytes: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37).wrapping_add(11)).collect();
            let text = encode(&bytes);
            if len == 0 {
                assert_eq!(decode(&text), None, "the empty string is not a value");
            } else {
                assert_eq!(decode(&text), Some(bytes), "length {len}");
            }
        }
    }

    // TEST0002: what is not strict base64 is refused, not read approximately:
    // a short length, a foreign character, padding in the middle or more than
    // two characters of it, whitespace.
    #[test]
    fn test0002_decode_refuses_what_is_not_strict_base64() {
        assert_eq!(decode("QUJ"), None);
        assert_eq!(decode("QU*D"), None);
        assert_eq!(decode("QQ==QUJD"), None);
        assert_eq!(decode("Q==="), None);
        assert_eq!(decode("===="), None);
        assert_eq!(decode("QR=="), None, "bits set where the padding says there are none");
        assert_eq!(decode("QUJ="), None, "bits set where the padding says there are none");
        assert_eq!(decode("QUI="), Some(b"AB".to_vec()));
        assert_eq!(decode("QQ=="), Some(b"A".to_vec()));
        assert_eq!(decode("QUJD "), None);
        assert_eq!(decode("QUJD"), Some(b"ABC".to_vec()));
    }
}
