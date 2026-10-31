//! Why a document was refused, as a closed vocabulary.
//!
//! A verifier's message may say as much as it likes; the reason is what a
//! client decides by. Most of all it decides whether the publisher was judged
//! and refused, or could not be judged at all, and every client of a project
//! has to make that decision the same way. The wire names are the vocabulary
//! the clients already report.

/// One reason a chain or a charter was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    MalformedEnvelope,
    UnsupportedEnvelopeFormat,
    MalformedCertificate,
    UnsupportedCertificateFormat,
    EmptyCertificateList,
    InsufficientRootSignatures,
    ExpiredCertificate,
    NotYetValidCertificate,
    EnvironmentMismatch,
    KeyIdMismatch,
    NoAuthorizingCertificate,
    ManifestSignatureInvalid,
    CharterMalformed,
    CharterUnsupportedFormat,
    CharterSignatureInvalid,
    CharterAnchorMismatch,
    CharterKindMismatch,
    CharterEnvironmentMismatch,
    CharterNotYetValid,
    CharterExpired,
    CharterFolderMismatch,
}

impl Reason {
    /// The reason's name on the wire.
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::MalformedEnvelope => "malformed_envelope",
            Self::UnsupportedEnvelopeFormat => "unsupported_envelope_format",
            Self::MalformedCertificate => "malformed_certificate",
            Self::UnsupportedCertificateFormat => "unsupported_certificate_format",
            Self::EmptyCertificateList => "empty_certificate_list",
            Self::InsufficientRootSignatures => "insufficient_root_signatures",
            Self::ExpiredCertificate => "expired_certificate",
            Self::NotYetValidCertificate => "not_yet_valid_certificate",
            Self::EnvironmentMismatch => "environment_mismatch",
            Self::KeyIdMismatch => "key_id_mismatch",
            Self::NoAuthorizingCertificate => "no_authorizing_certificate",
            Self::ManifestSignatureInvalid => "manifest_signature_invalid",
            Self::CharterMalformed => "charter_malformed",
            Self::CharterUnsupportedFormat => "charter_unsupported_format",
            Self::CharterSignatureInvalid => "charter_signature_invalid",
            Self::CharterAnchorMismatch => "charter_anchor_mismatch",
            Self::CharterKindMismatch => "charter_kind_mismatch",
            Self::CharterEnvironmentMismatch => "charter_environment_mismatch",
            Self::CharterNotYetValid => "charter_not_yet_valid",
            Self::CharterExpired => "charter_expired",
            Self::CharterFolderMismatch => "charter_folder_mismatch",
        }
    }
}
