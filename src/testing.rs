//! Real keys and signed documents for the tests. Every chain a test verifies is
//! signed here with ed25519, exactly as a publisher signs one.

use ed25519_dalek::Signer;

use crate::base64::encode;
use crate::chain::{CertificateEntry, RootSignature};

/// A minisign keypair, made from a seed so a test is the same on every run.
pub(crate) struct Key {
    signing: ed25519_dalek::SigningKey,
    number: [u8; 8],
}

impl Key {
    pub(crate) fn new(seed: u8) -> Self {
        Self {
            signing: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            number: [seed, 0xa5, seed ^ 0x5a, 1, 2, 3, 4, seed.wrapping_add(1)],
        }
    }

    /// The base64 minisign public key.
    pub(crate) fn public(&self) -> String {
        let mut bytes = b"Ed".to_vec();
        bytes.extend_from_slice(&self.number);
        bytes.extend_from_slice(self.signing.verifying_key().as_bytes());
        encode(&bytes)
    }

    /// The minisign key number, as lowercase hex.
    pub(crate) fn id(&self) -> String {
        self.number.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A base64 raw ed25519 signature over `bytes`.
    pub(crate) fn sign(&self, bytes: &[u8]) -> String {
        encode(&self.signing.sign(bytes).to_bytes())
    }
}

/// The words the tests' documents are written in.
pub(crate) const CERTIFICATE: &str = "example-release-key-cert/1";
pub(crate) const ENVELOPE: &str = "example-manifest-sig/1";
pub(crate) const CHARTER: &str = "example-registry-charter/1";
pub(crate) const CHARTER_ENVELOPE: &str = "example-charter-sig/1";

/// Issue and expiry of every certificate the tests make, unless one says other.
pub(crate) const ISSUED_AT: u64 = 1_700_000_000;
pub(crate) const NOT_AFTER: u64 = 1_800_000_000;
pub(crate) const NOW: u64 = 1_750_000_000;

/// A certificate for `release` under `label`, as its exact JSON.
pub(crate) fn certificate(format: &str, release: &Key, label: &str, issued_at: u64, not_after: u64) -> String {
    serde_json::json!({
        "format": format,
        "release_pubkey": release.public(),
        "key_id": release.id(),
        "environment": label,
        "issued_at": issued_at,
        "not_after": not_after,
    })
    .to_string()
}

/// `certificate`, signed by each of `roots`.
pub(crate) fn entry(certificate: String, roots: &[&Key]) -> CertificateEntry {
    let root_signatures = roots
        .iter()
        .map(|root| RootSignature { root_key_id: root.id(), signature: root.sign(certificate.as_bytes()) })
        .collect();
    CertificateEntry { certificate, root_signatures }
}

/// An envelope of `format` over `bytes`, the signature under `signature_field`,
/// signed by `signer` and carrying `certificates`.
pub(crate) fn envelope(
    format: &str,
    signature_field: &str,
    certificates: &[CertificateEntry],
    signer: &Key,
    bytes: &[u8],
) -> String {
    let mut document = serde_json::json!({
        "format": format,
        "certificates": certificates,
    });
    document[signature_field] = serde_json::json!({ "key_id": signer.id(), "signature": signer.sign(bytes) });
    document.to_string()
}
