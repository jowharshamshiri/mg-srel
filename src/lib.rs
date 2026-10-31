//! Verifying what a publisher signed, against the root keys a client was built with.
//!
//! A project that publishes releases signs them through a chain that starts at
//! root keys its clients bake in, and whose every step is checked here:
//!
//! 1. **Root keys** are minisign keypairs. Their public keys are baked into the
//!    client. They sign nothing but release-key certificates, and a certificate
//!    is trusted only when [`REQUIRED_ROOT_SIGNATURES`] distinct baked roots
//!    have each signed its exact bytes: two of three.
//! 2. **A release-key certificate** authorizes one release key under one
//!    **label** (an environment: `prod`, `staging`, …), between its issue and
//!    its expiry. A client accepts only certificates bearing its own label.
//! 3. **A release key** signs the exact bytes of a document: a manifest, or a
//!    registry's charter. The signature and the certificates that authorize
//!    its key travel together in a sidecar envelope, so a verifier needs one
//!    extra fetch and nothing else.
//!
//! **A charter** declares a registry: the URL it is named by (its anchor), its
//! kind, the label its contents are signed under, where its manifests are, and
//! its name on disk. A registry exists only because its project chartered it,
//! and a charter is verified against the project's **charter trust**, kept
//! apart from the **content trust** manifests are verified against, so neither
//! can stand in for the other.
//!
//! Nothing here belongs to any one project. The words that name each document
//! format, the label a charter is signed under, and the rules for each kind of
//! registry are given by the caller: a project declares them once and every one
//! of its clients and its publisher use the same declaration. Two projects with
//! different roots cannot verify each other's documents whatever their formats
//! are; with different format words they cannot even mistake one for the other.
//!
//! Every check is a hard failure. A document is believed only once its
//! signature verifies; before that, not even the format it claims is read as
//! anything but a reason to refuse it.

mod base64;
mod chain;
mod charter;
mod key;
mod reason;

pub use chain::{
    unix_now, verify_manifest, Certificate, CertificateEntry, ChainError, DocumentSignature, Formats,
    ManifestEnvelope, RootSignature, Trust, VerifiedChain, REQUIRED_ROOT_SIGNATURES,
};
pub use charter::{
    is_experiment_id, is_slug, placeholders_in, store, verify_charter, verify_stored, Charter, CharterEnvelope,
    CharterError, CharterExpectation, CharterRules, CharterTrust, KindRule, LocationRule,
    StoredCharterError, VerifiedCharter, CHARTER_FILE, CHARTER_SIG_FILE,
};
pub use key::{split_roots, verify_minisign, verify_raw, PublicKey, SignatureError};
pub use reason::Reason;

#[cfg(test)]
mod testing;
