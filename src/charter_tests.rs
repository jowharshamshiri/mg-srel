use super::*;
use crate::chain::Formats;
use crate::testing::{
    certificate, entry, envelope, Key, CERTIFICATE, CHARTER, CHARTER_ENVELOPE, ENVELOPE, ISSUED_AT, NOT_AFTER, NOW,
};

const ANCHOR: &str = "https://example.com/mirror";

fn rules() -> CharterRules {
    CharterRules {
        format: CHARTER.to_string(),
        fields: vec!["upstream".to_string()],
        kinds: vec![
            KindRule {
                name: "releases".to_string(),
                locations: vec![LocationRule { name: "manifest".into(), placeholders: vec!["app_id".into()] }],
                urls: vec![],
            },
            KindRule {
                name: "mirror".to_string(),
                locations: vec![
                    LocationRule { name: "index".into(), placeholders: vec!["version".into()] },
                    LocationRule { name: "latest".into(), placeholders: vec![] },
                ],
                urls: vec!["upstream".to_string()],
            },
        ],
        reserved_slugs: vec!["dev".to_string()],
    }
}

fn mirror() -> Charter {
    Charter {
        format: CHARTER.to_string(),
        anchor: ANCHOR.to_string(),
        kind: "mirror".to_string(),
        slug: "example.com-mirror".to_string(),
        environment: "prod".to_string(),
        experiment: None,
        locations: BTreeMap::from([
            ("index".to_string(), format!("{ANCHOR}/index/{{version}}.json")),
            ("latest".to_string(), format!("{ANCHOR}/latest.json")),
        ]),
        fields: BTreeMap::from([("upstream".to_string(), Some("https://upstream.example.com".to_string()))]),
        issued_at: ISSUED_AT,
        not_after: None,
    }
}

struct Fixture {
    roots: [Key; 3],
    charter_key: Key,
}

impl Fixture {
    fn new() -> Self {
        Self { roots: [Key::new(1), Key::new(2), Key::new(3)], charter_key: Key::new(20) }
    }

    fn trust(&self) -> CharterTrust {
        let roots: Vec<String> = self.roots.iter().map(Key::public).collect();
        let roots: Vec<&str> = roots.iter().map(String::as_str).collect();
        let formats = Formats { certificate: CERTIFICATE.to_string(), envelope: CHARTER_ENVELOPE.to_string() };
        CharterTrust { trust: Trust::new(&roots, "prod", formats).unwrap() }
    }

    /// `body` signed by the charter key, certified for `label`.
    fn sign_as(&self, label: &str, body: &[u8]) -> Vec<u8> {
        let certs = [entry(
            certificate(CERTIFICATE, &self.charter_key, label, ISSUED_AT, NOT_AFTER),
            &[&self.roots[0], &self.roots[2]],
        )];
        envelope(CHARTER_ENVELOPE, "charter_signature", &certs, &self.charter_key, body).into_bytes()
    }

    fn sign(&self, body: &[u8]) -> Vec<u8> {
        self.sign_as("prod", body)
    }
}

fn expect<'a>(anchor: &'a str, kind: &'a str, environment: Option<&'a str>) -> CharterExpectation<'a> {
    CharterExpectation { anchor: Some(anchor), kind, environment }
}

// TEST0016: a charter the project signed verifies, reads back as the charter
// it was written from, and writes back to the very bytes that were signed.
#[test]
fn test0016_a_signed_charter_verifies_and_round_trips_its_bytes() {
    let fx = Fixture::new();
    let body = mirror().to_bytes(&rules());
    let verified =
        verify_charter(&body, &fx.sign(&body), &fx.trust(), &rules(), &expect(ANCHOR, "mirror", Some("prod")), NOW)
            .expect("the charter verifies");
    assert_eq!(verified.charter, mirror());
    assert_eq!(verified.charter.to_bytes(&rules()), body);
    assert_eq!(verified.charter.field("upstream"), Some("https://upstream.example.com"));
    let text = String::from_utf8(body).unwrap();
    let order: Vec<usize> = ["\"format\"", "\"locations\"", "\"upstream\"", "\"issued_at\"", "\"not_after\""]
        .iter()
        .map(|key| text.find(key).unwrap_or_else(|| panic!("{key} is written")))
        .collect();
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "fields are written in declared order:\n{text}");
}

// TEST0017: the signature binds the exact bytes: a charter changed after it
// was signed does not verify, however valid the change would be.
#[test]
fn test0017_a_charter_changed_after_signing_is_refused() {
    let fx = Fixture::new();
    let body = mirror().to_bytes(&rules());
    let signature = fx.sign(&body);
    let mut changed = mirror();
    changed.slug = "elsewhere".to_string();
    let error = verify_charter(
        &changed.to_bytes(&rules()),
        &signature,
        &fx.trust(),
        &rules(),
        &expect(ANCHOR, "mirror", None),
        NOW,
    )
    .unwrap_err();
    assert!(matches!(error, CharterError::SignatureInvalid(_)), "{error}");
    assert_eq!(error.reason(), Reason::CharterSignatureInvalid);
}

// TEST0018: the charter must be the one the client asked for: the anchor it
// was given, the kind it wants, and contents signed under its own label.
#[test]
fn test0018_anchor_kind_and_environment_must_be_the_ones_asked() {
    let fx = Fixture::new();
    let body = mirror().to_bytes(&rules());
    let sig = fx.sign(&body);
    let refused = |expectation: CharterExpectation<'_>| {
        verify_charter(&body, &sig, &fx.trust(), &rules(), &expectation, NOW).unwrap_err().reason()
    };
    assert_eq!(refused(expect("https://example.com/other", "mirror", None)), Reason::CharterAnchorMismatch);
    assert_eq!(refused(expect(ANCHOR, "releases", None)), Reason::CharterKindMismatch);
    assert_eq!(refused(expect(ANCHOR, "mirror", Some("staging"))), Reason::CharterEnvironmentMismatch);
}

// TEST0019: a charter holds from its issue until its own expiry.
#[test]
fn test0019_a_charter_holds_only_inside_its_own_validity() {
    let fx = Fixture::new();
    let mut charter = mirror();
    charter.not_after = Some(NOW + 10);
    let body = charter.to_bytes(&rules());
    let sig = fx.sign(&body);
    let at = |now| verify_charter(&body, &sig, &fx.trust(), &rules(), &expect(ANCHOR, "mirror", None), now);
    assert!(at(NOW + 10).is_ok());
    assert_eq!(at(NOW + 11).unwrap_err(), CharterError::Expired { not_after: NOW + 10, now: NOW + 11 });
    assert_eq!(at(ISSUED_AT - 1).unwrap_err().reason(), Reason::NotYetValidCertificate);
}

// TEST0020: only the charter trust charters. A charter signed by a key
// certified for a content label is refused, and a manifest envelope over the
// same bytes, signed by the same key, is not a charter's signature.
#[test]
fn test0020_content_signatures_cannot_charter_a_registry() {
    let fx = Fixture::new();
    let body = mirror().to_bytes(&rules());
    let as_staging = fx.sign_as("staging", &body);
    assert_eq!(
        verify_charter(&body, &as_staging, &fx.trust(), &rules(), &expect(ANCHOR, "mirror", None), NOW)
            .unwrap_err()
            .reason(),
        Reason::EnvironmentMismatch
    );
    let certs = [entry(
        certificate(CERTIFICATE, &fx.charter_key, "prod", ISSUED_AT, NOT_AFTER),
        &[&fx.roots[0], &fx.roots[1]],
    )];
    let manifest_envelope = envelope(ENVELOPE, "manifest_signature", &certs, &fx.charter_key, &body);
    assert_eq!(
        verify_charter(&body, manifest_envelope.as_bytes(), &fx.trust(), &rules(), &expect(ANCHOR, "mirror", None), NOW)
            .unwrap_err()
            .reason(),
        Reason::UnsupportedEnvelopeFormat
    );
}

// TEST0021: a signed charter of the wrong shape is refused as malformed: a
// location missing or with a stray placeholder, a required URL missing or
// given where the kind takes none, a field the format does not have, a
// reserved slug, a kind the project does not charter.
#[test]
fn test0021_a_signed_charter_of_the_wrong_shape_is_malformed() {
    let fx = Fixture::new();
    let shapes: Vec<(&str, Box<dyn Fn(&mut serde_json::Value)>)> = vec![
        ("missing location", Box::new(|c| { c["locations"].as_object_mut().unwrap().remove("latest"); })),
        ("stray placeholder", Box::new(|c| c["locations"]["latest"] = format!("{ANCHOR}/{{app_id}}.json").into())),
        ("missing placeholder", Box::new(|c| c["locations"]["index"] = format!("{ANCHOR}/index.json").into())),
        ("missing required url", Box::new(|c| c["upstream"] = serde_json::Value::Null)),
        ("unknown field", Box::new(|c| c["extra"] = "x".into())),
        ("reserved slug", Box::new(|c| c["slug"] = "dev".into())),
        ("unknown kind", Box::new(|c| c["kind"] = "parcels".into())),
        ("http anchor", Box::new(|c| c["anchor"] = "http://example.com/mirror".into())),
    ];
    for (what, edit) in shapes {
        let mut value: serde_json::Value = serde_json::from_slice(&mirror().to_bytes(&rules())).unwrap();
        edit(&mut value);
        let body = serde_json::to_vec_pretty(&value).unwrap();
        let anchor = value["anchor"].as_str().unwrap().to_string();
        let error = verify_charter(&body, &fx.sign(&body), &fx.trust(), &rules(), &expect(&anchor, "mirror", None), NOW)
            .unwrap_err();
        assert_eq!(error.reason(), Reason::CharterMalformed, "{what}: {error}");
    }
    // Plain http is admitted to the loopback interface alone, which a request never leaves.
    for host in ["127.0.0.1:8080", "localhost:8080", "[::1]:8080", "127.0.0.1"] {
        let mut local = mirror();
        local.anchor = format!("http://{host}");
        local.locations = BTreeMap::from([
            ("index".to_string(), format!("http://{host}/index/{{version}}.json")),
            ("latest".to_string(), format!("http://{host}/latest.json")),
        ]);
        assert_eq!(local.validate(&rules()), Ok(()), "{host}");
    }
    for host in ["example.com", "127.0.0.1.example.com", "10.0.0.1:80", "[::2]:80", "localhost.example"] {
        let mut remote = mirror();
        remote.anchor = format!("http://{host}");
        assert!(remote.validate(&rules()).unwrap_err().contains("is not an https URL"), "{host}");
    }

    let mut releases = mirror();
    releases.kind = "releases".to_string();
    releases.locations = BTreeMap::from([("manifest".to_string(), format!("{ANCHOR}/{{app_id}}/manifest"))]);
    assert!(releases.validate(&rules()).unwrap_err().contains("names no upstream"));
    releases.fields.insert("upstream".to_string(), None);
    assert_eq!(releases.validate(&rules()), Ok(()));
}

// TEST0022: a charter stored in its registry's folder verifies offline, and
// only in a folder named for its slug; edited on disk it verifies no more.
#[test]
fn test0022_a_stored_charter_verifies_only_in_its_own_folder() {
    let fx = Fixture::new();
    let body = mirror().to_bytes(&rules());
    let verified =
        verify_charter(&body, &fx.sign(&body), &fx.trust(), &rules(), &expect(ANCHOR, "mirror", None), NOW).unwrap();
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join("example.com-mirror");
    store(&verified, &folder).unwrap();
    assert_eq!(verify_stored(&folder, &fx.trust(), &rules(), "mirror", None, NOW).unwrap(), verified);

    let renamed = root.path().join("renamed");
    std::fs::rename(&folder, &renamed).unwrap();
    assert!(matches!(
        verify_stored(&renamed, &fx.trust(), &rules(), "mirror", None, NOW),
        Err(StoredCharterError::Refused(CharterError::FolderMismatch { .. }))
    ));

    std::fs::rename(&renamed, &folder).unwrap();
    let edited = String::from_utf8(body).unwrap().replace("upstream.example.com", "elsewhere.example.com");
    std::fs::write(folder.join(CHARTER_FILE), edited).unwrap();
    assert!(matches!(
        verify_stored(&folder, &fx.trust(), &rules(), "mirror", None, NOW),
        Err(StoredCharterError::Refused(CharterError::SignatureInvalid(_)))
    ));
}

// TEST0023: a location is filled with exactly the values its template takes.
#[test]
fn test0023_a_location_takes_exactly_its_placeholders() {
    let charter = mirror();
    assert_eq!(charter.location("index", &[("version", "4")]), Ok(format!("{ANCHOR}/index/4.json")));
    assert!(charter.location("index", &[]).unwrap_err().contains("needs 'version'"));
    assert!(charter.location("index", &[("version", "4"), ("app_id", "x")]).unwrap_err().contains("does not take"));
    assert!(charter.location("nowhere", &[]).is_err());
}
