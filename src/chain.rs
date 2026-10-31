//! The chain from baked roots to a signed document.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::key::{PublicKey, SignatureError};
use crate::reason::Reason;

/// Two of three: a certificate is trusted only when at least this many distinct
/// baked roots have signed its exact bytes.
pub const REQUIRED_ROOT_SIGNATURES: usize = 2;

/// The words a project's documents declare themselves with. Each project has
/// its own, so no document of one can be read as a document of another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Formats {
    /// The `format` of a release-key certificate.
    pub certificate: String,
    /// The `format` of the signature envelope beside a signed document.
    pub envelope: String,
}

/// What a client verifies a document's chain against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trust {
    /// The root public keys this client was built with.
    pub roots: Vec<PublicKey>,
    /// The label a certificate must bear: the environment this client reads.
    pub label: String,
    pub formats: Formats,
}

impl Trust {
    /// A trust from base64 root keys, refused when any of them is not a key or
    /// when there are too few of them to ever reach two of three.
    pub fn new(roots: &[&str], label: &str, formats: Formats) -> Result<Self, SignatureError> {
        let roots = roots.iter().map(|root| PublicKey::parse(root)).collect::<Result<Vec<_>, _>>()?;
        // A root listed twice would count twice towards two of three.
        if let Some((index, root)) =
            roots.iter().enumerate().find(|(index, root)| roots[..*index].iter().any(|earlier| earlier.key_id == root.key_id))
        {
            return Err(SignatureError::MalformedPublicKey(format!(
                "root {} repeats key {}: each root must be a different key",
                index + 1,
                root.key_id
            )));
        }
        if roots.len() < REQUIRED_ROOT_SIGNATURES {
            return Err(SignatureError::MalformedPublicKey(format!(
                "{} root key(s) given; a certificate needs {REQUIRED_ROOT_SIGNATURES} distinct roots",
                roots.len()
            )));
        }
        Ok(Self { roots, label: label.to_string(), formats })
    }
}

/// A release-key certificate's body. Its wire form is the exact JSON string a
/// [`CertificateEntry`] carries, which is what the roots signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub format: String,
    /// The base64 minisign public key of the release key it authorizes.
    pub release_pubkey: String,
    /// That key's minisign key number, lowercase hex.
    pub key_id: String,
    /// The label it is bound to.
    pub environment: String,
    /// Unix seconds at issue.
    pub issued_at: u64,
    /// Unix seconds after which it is void.
    pub not_after: u64,
}

/// One root's signature over a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootSignature {
    /// The root's key number, for a person reading the document. Verification
    /// tries every baked root whatever this says.
    pub root_key_id: String,
    /// Base64 raw ed25519 over the certificate's exact bytes.
    pub signature: String,
}

/// A certificate as an envelope carries it: its exact JSON, and the roots'
/// signatures over that JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateEntry {
    pub certificate: String,
    pub root_signatures: Vec<RootSignature>,
}

/// A release key's signature over a document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentSignature {
    /// The signing key's id: a valid certificate in the same envelope must
    /// authorize it.
    pub key_id: String,
    /// Base64 raw ed25519 over the document's exact bytes.
    pub signature: String,
}

/// The sidecar beside a manifest (`<manifest>.sig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEnvelope {
    pub format: String,
    pub certificates: Vec<CertificateEntry>,
    pub manifest_signature: DocumentSignature,
}

/// The release keys a verified envelope's certificates authorize. An artifact
/// the document lists is held to one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    pub release_keys: Vec<PublicKey>,
}

impl VerifiedChain {
    /// The authorized release key with this id.
    pub fn release_key(&self, key_id: &str) -> Option<&PublicKey> {
        self.release_keys.iter().find(|key| key.key_id == key_id)
    }
}

/// Why a chain was refused. Every one is a hard failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("the signature envelope is malformed: {0}")]
    MalformedEnvelope(String),
    #[error("the signature envelope declares format '{found}' (expected '{expected}')")]
    UnsupportedEnvelopeFormat { found: String, expected: String },
    #[error("the signature envelope carries no certificates")]
    EmptyCertificateList,
    #[error("a release-key certificate is malformed: {0}")]
    MalformedCertificate(String),
    #[error("a release-key certificate declares format '{found}' (expected '{expected}')")]
    UnsupportedCertificateFormat { found: String, expected: String },
    #[error("a certificate states key_id '{stated}', and its release key's number is '{actual}'")]
    KeyIdMismatch { stated: String, actual: String },
    #[error("the certificate for key {key_id} is signed by {have} trusted root(s); {need} are required")]
    InsufficientRootSignatures { key_id: String, have: usize, need: usize },
    #[error("the certificate for key {key_id} is for '{certificate}', and this client trusts '{trusted}'")]
    LabelMismatch { key_id: String, certificate: String, trusted: String },
    #[error("the certificate for key {key_id} expired at unix {not_after} (now {now})")]
    ExpiredCertificate { key_id: String, not_after: u64, now: u64 },
    #[error("the certificate for key {key_id} is not valid until unix {issued_at} (now {now})")]
    NotYetValidCertificate { key_id: String, issued_at: u64, now: u64 },
    #[error("no valid certificate in the envelope authorizes key {key_id}, which signed the document")]
    NoAuthorizingCertificate { key_id: String },
    #[error("the signature does not verify over the document's bytes: {0}")]
    SignatureInvalid(SignatureError),
}

impl ChainError {
    /// The closed reason, for a chain over a manifest.
    pub fn reason(&self) -> Reason {
        match self {
            Self::MalformedEnvelope(_) => Reason::MalformedEnvelope,
            Self::UnsupportedEnvelopeFormat { .. } => Reason::UnsupportedEnvelopeFormat,
            Self::EmptyCertificateList => Reason::EmptyCertificateList,
            Self::MalformedCertificate(_) => Reason::MalformedCertificate,
            Self::UnsupportedCertificateFormat { .. } => Reason::UnsupportedCertificateFormat,
            Self::KeyIdMismatch { .. } => Reason::KeyIdMismatch,
            Self::InsufficientRootSignatures { .. } => Reason::InsufficientRootSignatures,
            Self::LabelMismatch { .. } => Reason::EnvironmentMismatch,
            Self::ExpiredCertificate { .. } => Reason::ExpiredCertificate,
            Self::NotYetValidCertificate { .. } => Reason::NotYetValidCertificate,
            Self::NoAuthorizingCertificate { .. } => Reason::NoAuthorizingCertificate,
            Self::SignatureInvalid(_) => Reason::ManifestSignatureInvalid,
        }
    }
}

/// The clock, as unix seconds.
pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("the system clock is before 1970").as_secs()
}

/// Verify a manifest's envelope over the manifest's exact bytes, and return the
/// release keys it authorizes.
///
/// Every certificate in the envelope must be valid. One that is not means a
/// publishing mistake or tampering, and a verifier that read past it would hide
/// either.
pub fn verify_manifest(envelope: &[u8], manifest: &[u8], trust: &Trust, now: u64) -> Result<VerifiedChain, ChainError> {
    let envelope: ManifestEnvelope = read_envelope(envelope, &trust.formats.envelope)?;
    authorize(&envelope.certificates, &envelope.manifest_signature, manifest, trust, now)
}

/// Read an envelope: its declared format first, so a signature document of
/// another kind is refused for what it is rather than as a malformed one of
/// this kind; then its shape.
pub(crate) fn read_envelope<T: serde::de::DeserializeOwned>(bytes: &[u8], expected: &str) -> Result<T, ChainError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| ChainError::MalformedEnvelope(e.to_string()))?;
    match value.get("format").and_then(serde_json::Value::as_str) {
        Some(found) if found == expected => {}
        Some(found) => {
            return Err(ChainError::UnsupportedEnvelopeFormat {
                found: found.to_string(),
                expected: expected.to_string(),
            })
        }
        None => return Err(ChainError::MalformedEnvelope("it declares no format".to_string())),
    }
    serde_json::from_value(value).map_err(|e| ChainError::MalformedEnvelope(e.to_string()))
}

/// Every certificate valid, and the document's signature by a key one of them
/// authorizes, over exactly `document`.
pub(crate) fn authorize(
    certificates: &[CertificateEntry],
    signature: &DocumentSignature,
    document: &[u8],
    trust: &Trust,
    now: u64,
) -> Result<VerifiedChain, ChainError> {
    if certificates.is_empty() {
        return Err(ChainError::EmptyCertificateList);
    }
    let release_keys =
        certificates.iter().map(|entry| verify_certificate(entry, trust, now)).collect::<Result<Vec<_>, _>>()?;
    let signer = release_keys
        .iter()
        .find(|key| key.key_id == signature.key_id)
        .ok_or_else(|| ChainError::NoAuthorizingCertificate { key_id: signature.key_id.clone() })?;
    signer.verify(&signature.signature, document).map_err(ChainError::SignatureInvalid)?;
    Ok(VerifiedChain { release_keys })
}

/// One certificate against the roots, the label and the clock, and the release
/// key it authorizes.
fn verify_certificate(entry: &CertificateEntry, trust: &Trust, now: u64) -> Result<PublicKey, ChainError> {
    let certificate: Certificate =
        serde_json::from_str(&entry.certificate).map_err(|e| ChainError::MalformedCertificate(e.to_string()))?;
    if certificate.format != trust.formats.certificate {
        return Err(ChainError::UnsupportedCertificateFormat {
            found: certificate.format,
            expected: trust.formats.certificate.clone(),
        });
    }
    let release_key = PublicKey::parse(&certificate.release_pubkey)
        .map_err(|e| ChainError::MalformedCertificate(format!("its release_pubkey: {e}")))?;
    if release_key.key_id != certificate.key_id {
        return Err(ChainError::KeyIdMismatch { stated: certificate.key_id, actual: release_key.key_id });
    }
    // Distinct by baked position: a key no root is contributes nothing, and two
    // signatures by one root count once.
    let signers = trust
        .roots
        .iter()
        .filter(|root| {
            entry.root_signatures.iter().any(|signed| root.verify(&signed.signature, entry.certificate.as_bytes()).is_ok())
        })
        .count();
    if signers < REQUIRED_ROOT_SIGNATURES {
        return Err(ChainError::InsufficientRootSignatures {
            key_id: certificate.key_id,
            have: signers,
            need: REQUIRED_ROOT_SIGNATURES,
        });
    }
    if certificate.environment != trust.label {
        return Err(ChainError::LabelMismatch {
            key_id: certificate.key_id,
            certificate: certificate.environment,
            trusted: trust.label.clone(),
        });
    }
    if now > certificate.not_after {
        return Err(ChainError::ExpiredCertificate { key_id: certificate.key_id, not_after: certificate.not_after, now });
    }
    if certificate.issued_at > now {
        return Err(ChainError::NotYetValidCertificate {
            key_id: certificate.key_id,
            issued_at: certificate.issued_at,
            now,
        });
    }
    Ok(release_key)
}

#[cfg(test)]
#[path = "chain_tests.rs"]
mod tests;
