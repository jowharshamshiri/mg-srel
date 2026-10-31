//! Keys and the two kinds of signature made with them.
//!
//! Every key is a minisign keypair, written as its base64 public key (the `RW…`
//! line of a `.pub` file). It signs two ways:
//!
//! * **raw ed25519 over exact bytes**, for certificates, manifests and charters
//!   ([`verify_raw`]);
//! * **minisign**, for artifacts, so stock `minisign -V` verifies them too
//!   ([`verify_minisign`]).

use std::fmt::Write as _;

use ed25519_dalek::Verifier;

/// Why a signature did not verify. A malformed key or signature is a broken
/// document; a signature that decodes and does not verify is tampering or the
/// wrong key. A caller tells them apart.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("malformed public key: {0}")]
    MalformedPublicKey(String),
    #[error("malformed signature: {0}")]
    MalformedSignature(String),
    #[error("the signature does not verify: {0}")]
    VerificationFailed(String),
}

/// Byte layout of a minisign public key: algorithm (2), key number (8), key (32).
const ALGORITHM_ED: &[u8; 2] = b"Ed";
const PUBLIC_KEY_BYTES: usize = 42;

/// A minisign public key, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// The base64 form it was read from, trimmed.
    pub text: String,
    /// The minisign key number as lowercase hex: which key signed something,
    /// in a form a person can search for.
    pub key_id: String,
    ed25519: [u8; 32],
}

impl PublicKey {
    /// Read a base64 minisign public key.
    pub fn parse(text: &str) -> Result<Self, SignatureError> {
        let text = text.trim();
        let bytes = crate::base64::decode(text)
            .ok_or_else(|| SignatureError::MalformedPublicKey("not valid base64".to_string()))?;
        if bytes.len() != PUBLIC_KEY_BYTES {
            return Err(SignatureError::MalformedPublicKey(format!(
                "expected {PUBLIC_KEY_BYTES} bytes, got {}",
                bytes.len()
            )));
        }
        if &bytes[0..2] != ALGORITHM_ED {
            return Err(SignatureError::MalformedPublicKey("not an ed25519 ('Ed') key".to_string()));
        }
        let mut ed25519 = [0u8; 32];
        ed25519.copy_from_slice(&bytes[10..42]);
        Ok(Self { text: text.to_string(), key_id: hex_lower(&bytes[2..10]), ed25519 })
    }

    /// Verify a base64 raw ed25519 signature over exactly `bytes`.
    pub fn verify(&self, signature: &str, bytes: &[u8]) -> Result<(), SignatureError> {
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&self.ed25519)
            .map_err(|e| SignatureError::MalformedPublicKey(e.to_string()))?;
        let raw = crate::base64::decode(signature.trim())
            .ok_or_else(|| SignatureError::MalformedSignature("not valid base64".to_string()))?;
        let raw: [u8; 64] = raw
            .try_into()
            .map_err(|v: Vec<u8>| SignatureError::MalformedSignature(format!("expected 64 bytes, got {}", v.len())))?;
        verifying_key
            .verify(bytes, &ed25519_dalek::Signature::from_bytes(&raw))
            .map_err(|e| SignatureError::VerificationFailed(e.to_string()))
    }
}

/// Verify a base64 raw ed25519 signature over exactly `bytes`, under the base64
/// minisign public key `public_key`.
pub fn verify_raw(public_key: &str, signature: &str, bytes: &[u8]) -> Result<(), SignatureError> {
    PublicKey::parse(public_key)?.verify(signature, bytes)
}

/// Verify a minisign signature document (a `.minisig` file's text) over
/// `bytes`. Its trusted comment is signed too, and is checked with it.
pub fn verify_minisign(public_key: &str, signature: &str, bytes: &[u8]) -> Result<(), SignatureError> {
    let public_key = minisign_verify::PublicKey::from_base64(public_key.trim())
        .map_err(|e| SignatureError::MalformedPublicKey(e.to_string()))?;
    let signature = minisign_verify::Signature::decode(signature.trim())
        .map_err(|e| SignatureError::MalformedSignature(e.to_string()))?;
    public_key
        .verify(bytes, &signature, false)
        .map_err(|e| SignatureError::VerificationFailed(e.to_string()))
}

/// The keys of a baked list: base64 public keys separated by commas, as a
/// build bakes them. Blank entries are not keys and are dropped; whether a
/// list has enough keys is the build's to refuse.
pub fn split_roots(baked: &str) -> Vec<&str> {
    baked.split(',').map(str::trim).filter(|key| !key.is_empty()).collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Key;

    // TEST0003: a key reads back as the key that was written, its id the
    // minisign key number, and it verifies what its secret half signed and
    // nothing else.
    #[test]
    fn test0003_a_parsed_key_verifies_its_own_signature_only() {
        let key = Key::new(7);
        let other = Key::new(8);
        let parsed = PublicKey::parse(&key.public()).expect("a generated key parses");
        assert_eq!(parsed.key_id, key.id());
        assert_eq!(parsed.verify(&key.sign(b"bytes"), b"bytes"), Ok(()));
        assert!(matches!(parsed.verify(&key.sign(b"bytes"), b"bytez"), Err(SignatureError::VerificationFailed(_))));
        assert!(matches!(parsed.verify(&other.sign(b"bytes"), b"bytes"), Err(SignatureError::VerificationFailed(_))));
    }

    // TEST0004: a key of the wrong length or algorithm, and a signature of the
    // wrong length, are malformed rather than merely failing to verify.
    #[test]
    fn test0004_malformed_keys_and_signatures_are_named_as_such() {
        let key = Key::new(9);
        let mut wrong_algorithm = crate::base64::decode(&key.public()).unwrap();
        wrong_algorithm[0] = b'X';
        assert!(matches!(
            PublicKey::parse(&crate::base64::encode(&wrong_algorithm)),
            Err(SignatureError::MalformedPublicKey(_))
        ));
        assert!(matches!(PublicKey::parse("QUJD"), Err(SignatureError::MalformedPublicKey(_))));
        assert!(matches!(
            verify_raw(&key.public(), &crate::base64::encode(&[0u8; 63]), b"x"),
            Err(SignatureError::MalformedSignature(_))
        ));
    }

    // TEST0005: a baked list splits into its keys, whatever spacing and stray
    // separators it was written with.
    #[test]
    fn test0005_a_baked_list_splits_into_its_keys() {
        assert_eq!(split_roots(" RWa , RWb,,RWc ,"), vec!["RWa", "RWb", "RWc"]);
        assert!(split_roots(" , ").is_empty());
    }
}
