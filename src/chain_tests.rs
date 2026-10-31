use super::*;
use crate::testing::{certificate, entry, envelope, Key, CERTIFICATE, ENVELOPE, ISSUED_AT, NOT_AFTER, NOW};

const MANIFEST: &[u8] = br#"{"versions":["1.0.0"]}"#;

struct Fixture {
    roots: [Key; 3],
    release: Key,
}

impl Fixture {
    fn new() -> Self {
        Self { roots: [Key::new(1), Key::new(2), Key::new(3)], release: Key::new(10) }
    }

    fn trust(&self, label: &str) -> Trust {
        let roots: Vec<String> = self.roots.iter().map(Key::public).collect();
        let roots: Vec<&str> = roots.iter().map(String::as_str).collect();
        Trust::new(&roots, label, formats()).expect("three distinct roots make a trust")
    }

    /// The release key certified for `label` by roots A and B, signing `bytes`.
    fn envelope(&self, label: &str, bytes: &[u8]) -> String {
        let cert = certificate(CERTIFICATE, &self.release, label, ISSUED_AT, NOT_AFTER);
        let certs = [entry(cert, &[&self.roots[0], &self.roots[1]])];
        envelope(ENVELOPE, "manifest_signature", &certs, &self.release, bytes)
    }
}

fn formats() -> Formats {
    Formats { certificate: CERTIFICATE.to_string(), envelope: ENVELOPE.to_string() }
}

// TEST0006: a manifest signed by a release key that two of the three roots
// certified for this label verifies, and the chain gives back that key.
#[test]
fn test0006_two_of_three_roots_authorize_the_manifest() {
    let fx = Fixture::new();
    let chain = verify_manifest(fx.envelope("prod", MANIFEST).as_bytes(), MANIFEST, &fx.trust("prod"), NOW)
        .expect("the chain verifies");
    assert_eq!(chain.release_keys.len(), 1);
    assert_eq!(chain.release_key(&fx.release.id()).map(|k| k.text.clone()), Some(fx.release.public()));
}

// TEST0007: the signature binds the exact bytes: one bit changed in the
// manifest and it no longer verifies.
#[test]
fn test0007_a_changed_manifest_does_not_verify() {
    let fx = Fixture::new();
    let mut changed = MANIFEST.to_vec();
    changed[3] ^= 1;
    let error = verify_manifest(fx.envelope("prod", MANIFEST).as_bytes(), &changed, &fx.trust("prod"), NOW).unwrap_err();
    assert!(matches!(error, ChainError::SignatureInvalid(_)), "{error}");
    assert_eq!(error.reason(), Reason::ManifestSignatureInvalid);
}

// TEST0008: one root is not enough, and a root counts once however many times
// it signed; a key that is no root counts for nothing.
#[test]
fn test0008_one_root_is_not_two_of_three() {
    let fx = Fixture::new();
    let stranger = Key::new(99);
    let cert = certificate(CERTIFICATE, &fx.release, "prod", ISSUED_AT, NOT_AFTER);
    for signers in [vec![&fx.roots[0]], vec![&fx.roots[0], &fx.roots[0]], vec![&fx.roots[2], &stranger]] {
        let certs = [entry(cert.clone(), &signers)];
        let sig = envelope(ENVELOPE, "manifest_signature", &certs, &fx.release, MANIFEST);
        let error = verify_manifest(sig.as_bytes(), MANIFEST, &fx.trust("prod"), NOW).unwrap_err();
        assert_eq!(
            error,
            ChainError::InsufficientRootSignatures { key_id: fx.release.id(), have: 1, need: 2 },
            "signed by {} key(s)",
            signers.len()
        );
    }
}

// TEST0009: a certificate is valid from its issue to its expiry and at no
// other time.
#[test]
fn test0009_a_certificate_holds_only_inside_its_validity() {
    let fx = Fixture::new();
    let sig = fx.envelope("prod", MANIFEST);
    let trust = fx.trust("prod");
    assert!(verify_manifest(sig.as_bytes(), MANIFEST, &trust, NOT_AFTER).is_ok());
    assert!(verify_manifest(sig.as_bytes(), MANIFEST, &trust, ISSUED_AT).is_ok());
    assert!(matches!(
        verify_manifest(sig.as_bytes(), MANIFEST, &trust, NOT_AFTER + 1),
        Err(ChainError::ExpiredCertificate { .. })
    ));
    assert!(matches!(
        verify_manifest(sig.as_bytes(), MANIFEST, &trust, ISSUED_AT - 1),
        Err(ChainError::NotYetValidCertificate { .. })
    ));
}

// TEST0010: a certificate for another label is refused under the same roots,
// so one environment's key cannot stand in for another's.
#[test]
fn test0010_a_certificate_for_another_label_is_refused() {
    let fx = Fixture::new();
    let error = verify_manifest(fx.envelope("staging", MANIFEST).as_bytes(), MANIFEST, &fx.trust("prod"), NOW).unwrap_err();
    assert_eq!(
        error,
        ChainError::LabelMismatch { key_id: fx.release.id(), certificate: "staging".into(), trusted: "prod".into() }
    );
    assert_eq!(error.reason(), Reason::EnvironmentMismatch);
}

// TEST0011: documents in another project's words are refused for their
// format, the envelope's and the certificate's, even when the keys would
// verify them.
#[test]
fn test0011_another_projects_formats_are_refused() {
    let fx = Fixture::new();
    let foreign = envelope(
        "other-manifest-sig/1",
        "manifest_signature",
        &[entry(certificate(CERTIFICATE, &fx.release, "prod", ISSUED_AT, NOT_AFTER), &[&fx.roots[0], &fx.roots[1]])],
        &fx.release,
        MANIFEST,
    );
    assert_eq!(
        verify_manifest(foreign.as_bytes(), MANIFEST, &fx.trust("prod"), NOW).unwrap_err(),
        ChainError::UnsupportedEnvelopeFormat { found: "other-manifest-sig/1".into(), expected: ENVELOPE.into() }
    );
    let foreign_cert = envelope(
        ENVELOPE,
        "manifest_signature",
        &[entry(
            certificate("other-release-key-cert/1", &fx.release, "prod", ISSUED_AT, NOT_AFTER),
            &[&fx.roots[0], &fx.roots[1]],
        )],
        &fx.release,
        MANIFEST,
    );
    assert_eq!(
        verify_manifest(foreign_cert.as_bytes(), MANIFEST, &fx.trust("prod"), NOW).unwrap_err(),
        ChainError::UnsupportedCertificateFormat { found: "other-release-key-cert/1".into(), expected: CERTIFICATE.into() }
    );
}

// TEST0012: an envelope is refused whole when any certificate in it is bad,
// even when another one authorizes the signer.
#[test]
fn test0012_one_bad_certificate_refuses_the_envelope() {
    let fx = Fixture::new();
    let good = entry(certificate(CERTIFICATE, &fx.release, "prod", ISSUED_AT, NOT_AFTER), &[&fx.roots[0], &fx.roots[1]]);
    let expired = entry(certificate(CERTIFICATE, &Key::new(11), "prod", 1, 2), &[&fx.roots[0], &fx.roots[1]]);
    let sig = envelope(ENVELOPE, "manifest_signature", &[good, expired], &fx.release, MANIFEST);
    assert!(matches!(
        verify_manifest(sig.as_bytes(), MANIFEST, &fx.trust("prod"), NOW),
        Err(ChainError::ExpiredCertificate { .. })
    ));
}

// TEST0013: a signature by a key no certificate in the envelope authorizes is
// refused, however well it verifies.
#[test]
fn test0013_an_unauthorized_signer_is_refused() {
    let fx = Fixture::new();
    let other = Key::new(12);
    let certs = [entry(certificate(CERTIFICATE, &fx.release, "prod", ISSUED_AT, NOT_AFTER), &[&fx.roots[0], &fx.roots[1]])];
    let sig = envelope(ENVELOPE, "manifest_signature", &certs, &other, MANIFEST);
    assert_eq!(
        verify_manifest(sig.as_bytes(), MANIFEST, &fx.trust("prod"), NOW).unwrap_err(),
        ChainError::NoAuthorizingCertificate { key_id: other.id() }
    );
}

// TEST0014: a certificate whose stated key id is not its key's number is a
// hand-edited one, and an envelope with no certificates authorizes nothing.
#[test]
fn test0014_edited_certificates_and_empty_envelopes_are_refused() {
    let fx = Fixture::new();
    let edited = certificate(CERTIFICATE, &fx.release, "prod", ISSUED_AT, NOT_AFTER).replace(&fx.release.id(), "0000000000000000");
    let certs = [entry(edited, &[&fx.roots[0], &fx.roots[1]])];
    let sig = envelope(ENVELOPE, "manifest_signature", &certs, &fx.release, MANIFEST);
    assert_eq!(
        verify_manifest(sig.as_bytes(), MANIFEST, &fx.trust("prod"), NOW).unwrap_err(),
        ChainError::KeyIdMismatch { stated: "0000000000000000".into(), actual: fx.release.id() }
    );
    let empty = envelope(ENVELOPE, "manifest_signature", &[], &fx.release, MANIFEST);
    assert_eq!(
        verify_manifest(empty.as_bytes(), MANIFEST, &fx.trust("prod"), NOW).unwrap_err(),
        ChainError::EmptyCertificateList
    );
}

// TEST0015: a trust needs at least two distinct roots, since nothing could
// ever be signed by two of fewer.
#[test]
fn test0015_a_trust_needs_two_distinct_roots() {
    let a = Key::new(1).public();
    let b = Key::new(2).public();
    assert!(Trust::new(&[&a, &b], "prod", formats()).is_ok());
    assert!(Trust::new(&[&a], "prod", formats()).is_err());
    assert!(Trust::new(&[&a, &a], "prod", formats()).is_err());
    assert!(Trust::new(&[&a, "not a key"], "prod", formats()).is_err());
}

// TEST0024: a certificate verifies on its own, before any document is signed
// under it, and is held to the same roots, label and clock an envelope's are.
#[test]
fn test0024_a_certificate_verifies_on_its_own() {
    let fx = Fixture::new();
    let cert = certificate(CERTIFICATE, &fx.release, "prod", ISSUED_AT, NOT_AFTER);
    let verified = verify_certificate(&entry(cert.clone(), &[&fx.roots[1], &fx.roots[2]]), &fx.trust("prod"), NOW)
        .expect("a certificate two roots signed verifies");
    assert_eq!(verified.certificate.key_id, fx.release.id());
    assert_eq!(verified.certificate.not_after, NOT_AFTER);
    assert_eq!(verified.release_key.text, fx.release.public());
    assert!(matches!(
        verify_certificate(&entry(cert.clone(), &[&fx.roots[1], &fx.roots[2]]), &fx.trust("staging"), NOW),
        Err(ChainError::LabelMismatch { .. })
    ));
    assert!(matches!(
        verify_certificate(&entry(cert.clone(), &[&fx.roots[1]]), &fx.trust("prod"), NOW),
        Err(ChainError::InsufficientRootSignatures { have: 1, .. })
    ));
    assert!(matches!(
        verify_certificate(&entry(cert, &[&fx.roots[1], &fx.roots[2]]), &fx.trust("prod"), NOT_AFTER + 1),
        Err(ChainError::ExpiredCertificate { .. })
    ));
}
