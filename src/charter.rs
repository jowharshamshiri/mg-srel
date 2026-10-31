//! Registry charters: what makes a URL a project's registry.
//!
//! A registry is named by its **anchor**, which may be any URL: a domain, a
//! subdomain, a sub-path. The one convention is that `<anchor>/charter.json`
//! and `<anchor>/charter.json.sig` exist. Everything else a client needs is
//! read from the charter, never derived from the shape of a URL:
//!
//! * the registry's **slug**, its name on disk;
//! * its **kind**, and the **environment** its contents are signed under;
//! * the **locations** of its documents, as templates;
//! * any other field the project's charters carry for a kind (a registry that
//!   resolves against another names it, say).
//!
//! A charter is signed under the project's **charter label**, whatever the
//! registry's own environment, and verified against the **charter trust**: a
//! registry exists because its project chartered it. The charter trust and the
//! content trust are distinct types, so a charter can never vouch for an
//! artifact and a content key can never charter a registry.
//!
//! The charter is not the manifest. A manifest lists a registry's contents and
//! is signed under the registry's own environment; a charter declares the
//! registry, and is signed once, and again whenever the key that signed it is
//! rotated.

use std::collections::BTreeMap;
use std::path::Path;

use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};

use crate::chain::{authorize, read_envelope, CertificateEntry, ChainError, DocumentSignature, Trust};
use crate::reason::Reason;

/// The charter's file name, under its anchor and in a registry's folder.
pub const CHARTER_FILE: &str = "charter.json";
/// The charter signature's file name, under its anchor and in a registry's
/// folder.
pub const CHARTER_SIG_FILE: &str = "charter.json.sig";

/// What a project's charters are: the format word of the body, the fields its
/// bodies carry beyond the common ones, the kinds of registry it charters, and
/// the slugs no charter may claim. Declared once by the project; its publisher
/// issues by it and its clients verify by it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharterRules {
    /// The `format` of a charter body.
    pub format: String,
    /// Fields every body of this format carries, after `locations`, in this
    /// order. A kind that requires one gives it a URL; every other kind
    /// writes it as `null`.
    pub fields: Vec<String>,
    pub kinds: Vec<KindRule>,
    /// Names no registry may have on disk, because something else already
    /// does.
    pub reserved_slugs: Vec<String>,
}

/// One kind of registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KindRule {
    pub name: String,
    /// The locations a charter of this kind declares: all of them, and no
    /// others.
    pub locations: Vec<LocationRule>,
    /// The [`CharterRules::fields`] this kind requires, each an https URL with
    /// no trailing `/`.
    pub urls: Vec<String>,
}

/// One location a kind declares, and the placeholders its template must use:
/// all of them, and no others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationRule {
    pub name: String,
    pub placeholders: Vec<String>,
}

/// The roots charters are verified against, under the charter label, and the
/// envelope format a charter's signature comes in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharterTrust {
    pub trust: Trust,
}

/// What a client expects of the charter it is about to trust.
#[derive(Debug, Clone, Copy)]
pub struct CharterExpectation<'a> {
    /// The anchor the client was asked to use. `None` only for a charter read
    /// from a registry's folder, whose anchor the caller then holds the
    /// folder's contents to.
    pub anchor: Option<&'a str>,
    pub kind: &'a str,
    /// The client's content label: a registry signed under another environment
    /// is refused at its charter rather than at its first signature. `None`
    /// for a client with no content trust, and for a kind whose contents are
    /// not signed.
    pub environment: Option<&'a str>,
}

/// A charter body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Charter {
    pub format: String,
    /// The URL the registry is named by.
    pub anchor: String,
    pub kind: String,
    /// The registry's name on disk, unique across the project's charters.
    pub slug: String,
    /// The label the registry's contents are signed under.
    pub environment: String,
    /// The experiment this registry belongs to, for an environment of
    /// experiments.
    pub experiment: Option<String>,
    /// Location templates, by name.
    pub locations: BTreeMap<String, String>,
    /// The [`CharterRules::fields`], each with its value or `None`.
    pub fields: BTreeMap<String, Option<String>>,
    /// Unix seconds at issue.
    pub issued_at: u64,
    /// Unix seconds after which the charter is void; `None` while the key that
    /// signed it is trusted.
    pub not_after: Option<u64>,
}

/// The `charter.json.sig` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CharterEnvelope {
    pub format: String,
    pub certificates: Vec<CertificateEntry>,
    pub charter_signature: DocumentSignature,
}

/// A charter that verified, with its exact bytes and envelope, kept so it can
/// be stored beside what it vouches for and verified again offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCharter {
    pub charter: Charter,
    pub body: Vec<u8>,
    pub envelope: Vec<u8>,
}

/// Why a charter was refused. Every one is a hard failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CharterError {
    #[error("the charter is not a charter: {0}")]
    Malformed(String),
    #[error("the charter declares format '{found}' (expected '{expected}')")]
    UnsupportedFormat { found: String, expected: String },
    #[error("the charter's signature does not chain to the charter roots: {0}")]
    Chain(ChainError),
    #[error("the charter's signature does not verify over its bytes: {0}")]
    SignatureInvalid(String),
    #[error("the charter is for '{charter}', not for '{asked}'")]
    AnchorMismatch { charter: String, asked: String },
    #[error("the charter is for a {charter} registry, not a {expected} one")]
    KindMismatch { charter: String, expected: String },
    #[error("the charter's registry is signed under '{charter}', and this client reads '{client}'")]
    EnvironmentMismatch { charter: String, client: String },
    #[error("the charter is not valid until unix {issued_at} (now {now})")]
    NotYetValid { issued_at: u64, now: u64 },
    #[error("the charter expired at unix {not_after} (now {now})")]
    Expired { not_after: u64, now: u64 },
    #[error("the charter for '{anchor}' names slug '{slug}', and it is stored in a folder named '{folder}'")]
    FolderMismatch { anchor: String, slug: String, folder: String },
}

impl CharterError {
    /// The closed reason. A certificate failure keeps its own; everything about
    /// the charter itself has a `charter_` one.
    pub fn reason(&self) -> Reason {
        match self {
            Self::Malformed(_) => Reason::CharterMalformed,
            Self::UnsupportedFormat { .. } => Reason::CharterUnsupportedFormat,
            Self::Chain(error) => error.reason(),
            Self::SignatureInvalid(_) => Reason::CharterSignatureInvalid,
            Self::AnchorMismatch { .. } => Reason::CharterAnchorMismatch,
            Self::KindMismatch { .. } => Reason::CharterKindMismatch,
            Self::EnvironmentMismatch { .. } => Reason::CharterEnvironmentMismatch,
            Self::NotYetValid { .. } => Reason::CharterNotYetValid,
            Self::Expired { .. } => Reason::CharterExpired,
            Self::FolderMismatch { .. } => Reason::CharterFolderMismatch,
        }
    }
}

/// Verify a charter's exact bytes and its envelope, then hold the body to the
/// project's rules and to what the client expects. In this order, each a hard
/// failure:
///
/// 1. the envelope, and every certificate in it, against the charter trust;
/// 2. the signature, by a key one of those certificates authorizes, over the
///    exact bytes;
/// 3. the body: its format, then its shape ([`Charter::validate`]);
/// 4. the expectation: anchor, kind, content environment;
/// 5. the clock.
pub fn verify_charter(
    body: &[u8],
    envelope: &[u8],
    trust: &CharterTrust,
    rules: &CharterRules,
    expect: &CharterExpectation<'_>,
    now: u64,
) -> Result<VerifiedCharter, CharterError> {
    let signed: CharterEnvelope = read_envelope(envelope, &trust.trust.formats.envelope).map_err(CharterError::Chain)?;
    authorize(&signed.certificates, &signed.charter_signature, body, &trust.trust, now).map_err(|error| match error {
        ChainError::SignatureInvalid(error) => CharterError::SignatureInvalid(error.to_string()),
        other => CharterError::Chain(other),
    })?;

    // Only now is the body read: nothing an unsigned document says is
    // believed, its format included.
    let charter = Charter::parse(body, rules)?;
    if let Some(asked) = expect.anchor {
        if charter.anchor != asked {
            return Err(CharterError::AnchorMismatch { charter: charter.anchor, asked: asked.to_string() });
        }
    }
    if charter.kind != expect.kind {
        return Err(CharterError::KindMismatch { charter: charter.kind, expected: expect.kind.to_string() });
    }
    if let Some(client) = expect.environment {
        if charter.environment != client {
            return Err(CharterError::EnvironmentMismatch { charter: charter.environment, client: client.to_string() });
        }
    }
    if charter.issued_at > now {
        return Err(CharterError::NotYetValid { issued_at: charter.issued_at, now });
    }
    if let Some(not_after) = charter.not_after {
        if now > not_after {
            return Err(CharterError::Expired { not_after, now });
        }
    }
    Ok(VerifiedCharter { charter, body: body.to_vec(), envelope: envelope.to_vec() })
}

/// The body's fields every charter has, in the order they are written.
const COMMON_BEFORE: [&str; 7] = ["format", "anchor", "kind", "slug", "environment", "experiment", "locations"];
const COMMON_AFTER: [&str; 2] = ["issued_at", "not_after"];

impl Charter {
    /// Read a body: its format, then every field, then its shape. A field the
    /// rules do not declare is refused, not ignored.
    pub fn parse(body: &[u8], rules: &CharterRules) -> Result<Self, CharterError> {
        let value: serde_json::Value = serde_json::from_slice(body).map_err(|e| CharterError::Malformed(e.to_string()))?;
        let serde_json::Value::Object(mut object) = value else {
            return Err(CharterError::Malformed("it is not a JSON object".to_string()));
        };
        match object.get("format").and_then(serde_json::Value::as_str) {
            Some(found) if found == rules.format => {}
            Some(found) => {
                return Err(CharterError::UnsupportedFormat { found: found.to_string(), expected: rules.format.clone() })
            }
            None => return Err(CharterError::Malformed("it declares no format".to_string())),
        }
        let mut take = |name: &str| object.remove(name).unwrap_or(serde_json::Value::Null);
        let string = |name: &str, value: serde_json::Value| -> Result<String, CharterError> {
            match value {
                serde_json::Value::String(s) => Ok(s),
                other => Err(CharterError::Malformed(format!("'{name}' is {other}, not a string"))),
            }
        };
        let optional = |name: &str, value: serde_json::Value| -> Result<Option<String>, CharterError> {
            match value {
                serde_json::Value::Null => Ok(None),
                serde_json::Value::String(s) => Ok(Some(s)),
                other => Err(CharterError::Malformed(format!("'{name}' is {other}, not a string or null"))),
            }
        };
        let format = string("format", take("format"))?;
        let anchor = string("anchor", take("anchor"))?;
        let kind = string("kind", take("kind"))?;
        let slug = string("slug", take("slug"))?;
        let environment = string("environment", take("environment"))?;
        let experiment = optional("experiment", take("experiment"))?;
        let locations: BTreeMap<String, String> = serde_json::from_value(take("locations"))
            .map_err(|e| CharterError::Malformed(format!("'locations': {e}")))?;
        let mut fields = BTreeMap::new();
        for name in &rules.fields {
            fields.insert(name.clone(), optional(name, take(name))?);
        }
        let issued_at = take("issued_at")
            .as_u64()
            .ok_or_else(|| CharterError::Malformed("'issued_at' is not unix seconds".to_string()))?;
        let not_after = match take("not_after") {
            serde_json::Value::Null => None,
            other => Some(
                other.as_u64().ok_or_else(|| CharterError::Malformed("'not_after' is not unix seconds or null".to_string()))?,
            ),
        };
        if let Some(unknown) = object.keys().next() {
            return Err(CharterError::Malformed(format!("'{unknown}' is not a field of '{}'", rules.format)));
        }
        let charter = Self { format, anchor, kind, slug, environment, experiment, locations, fields, issued_at, not_after };
        charter.validate(rules).map_err(CharterError::Malformed)?;
        Ok(charter)
    }

    /// The bytes a charter is signed and published as: pretty JSON in the
    /// order the fields are declared, with a trailing newline.
    pub fn to_bytes(&self, rules: &CharterRules) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(&Ordered { charter: self, rules }).expect("a charter serializes");
        bytes.push(b'\n');
        bytes
    }

    /// The shape every charter must have, whoever signed it. Meeting one that
    /// lacks it means the issuer is broken, and nothing in it is used.
    pub fn validate(&self, rules: &CharterRules) -> Result<(), String> {
        if self.format != rules.format {
            return Err(format!("format '{}' is not '{}'", self.format, rules.format));
        }
        check_url("anchor", &self.anchor)?;
        if !is_slug(&self.slug) {
            return Err(format!("slug '{}' is not a registry slug ([a-z0-9][a-z0-9.-]{{0,62}})", self.slug));
        }
        if rules.reserved_slugs.contains(&self.slug) {
            return Err(format!("slug '{}' is reserved", self.slug));
        }
        if self.environment.is_empty()
            || !self.environment.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(format!("environment '{}' is not a label ([a-z0-9-]+)", self.environment));
        }
        if let Some(experiment) = &self.experiment {
            if !is_experiment_id(experiment) {
                return Err(format!("experiment '{experiment}' is not an experiment id ([a-z0-9][a-z0-9-]{{0,39}})"));
            }
        }
        let kind = rules
            .kinds
            .iter()
            .find(|kind| kind.name == self.kind)
            .ok_or_else(|| format!("'{}' is not a kind of registry '{}' charters", self.kind, rules.format))?;
        for name in self.locations.keys() {
            if !kind.locations.iter().any(|location| &location.name == name) {
                return Err(format!("location '{name}' is not one a {} registry has", kind.name));
            }
        }
        for location in &kind.locations {
            let template = self
                .locations
                .get(&location.name)
                .ok_or_else(|| format!("a {} registry must declare location '{}'", kind.name, location.name))?;
            check_scheme(&format!("location '{}'", location.name), template)?;
            let used = placeholders_in(template).map_err(|e| format!("location '{}': {e}", location.name))?;
            if let Some(stray) = used.iter().find(|used| !location.placeholders.contains(used)) {
                return Err(format!("location '{}' uses '{{{stray}}}', which it does not take", location.name));
            }
            if let Some(missing) = location.placeholders.iter().find(|wanted| !used.contains(wanted)) {
                return Err(format!("location '{}' must use '{{{missing}}}'", location.name));
            }
        }
        for name in &rules.fields {
            let value = self.fields.get(name).ok_or_else(|| format!("'{name}' is missing"))?;
            match (kind.urls.contains(name), value) {
                (true, Some(url)) => check_url(name, url)?,
                (true, None) => return Err(format!("a {} registry must name its {name}", kind.name)),
                (false, Some(_)) => return Err(format!("a {} registry names no {name}", kind.name)),
                (false, None) => {}
            }
        }
        if let Some(extra) = self.fields.keys().find(|name| !rules.fields.contains(name)) {
            return Err(format!("'{extra}' is not a field of '{}'", rules.format));
        }
        if let Some(not_after) = self.not_after {
            if not_after <= self.issued_at {
                return Err(format!("not_after {not_after} is not after issued_at {}", self.issued_at));
            }
        }
        Ok(())
    }

    /// One location with its placeholders filled. Every placeholder the
    /// template uses must be given, and nothing else may be: a value nobody
    /// substitutes is a caller asking for a different location than it gets.
    pub fn location(&self, name: &str, values: &[(&str, &str)]) -> Result<String, String> {
        let template = self
            .locations
            .get(name)
            .ok_or_else(|| format!("the {} registry at {} has no location '{name}'", self.kind, self.anchor))?;
        let used = placeholders_in(template)?;
        if let Some((key, _)) = values.iter().find(|(key, _)| !used.iter().any(|u| u == key)) {
            return Err(format!("location '{name}' does not take '{key}'"));
        }
        let mut out = template.clone();
        for placeholder in &used {
            let value = values
                .iter()
                .find(|(key, _)| key == placeholder)
                .map(|(_, value)| *value)
                .ok_or_else(|| format!("location '{name}' needs '{placeholder}'"))?;
            out = out.replace(&format!("{{{placeholder}}}"), value);
        }
        Ok(out)
    }

    /// A [`CharterRules::fields`] value: `None` when the charter gives none.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).and_then(Option::as_deref)
    }
}

/// A charter serialized in its declared order.
struct Ordered<'a> {
    charter: &'a Charter,
    rules: &'a CharterRules,
}

impl Serialize for Ordered<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let c = self.charter;
        let mut map = serializer.serialize_map(Some(COMMON_BEFORE.len() + self.rules.fields.len() + COMMON_AFTER.len()))?;
        map.serialize_entry("format", &c.format)?;
        map.serialize_entry("anchor", &c.anchor)?;
        map.serialize_entry("kind", &c.kind)?;
        map.serialize_entry("slug", &c.slug)?;
        map.serialize_entry("environment", &c.environment)?;
        map.serialize_entry("experiment", &c.experiment)?;
        map.serialize_entry("locations", &c.locations)?;
        for name in &self.rules.fields {
            map.serialize_entry(name, &c.fields.get(name).cloned().flatten())?;
        }
        map.serialize_entry("issued_at", &c.issued_at)?;
        map.serialize_entry("not_after", &c.not_after)?;
        map.end()
    }
}

/// Whether `s` has a registry slug's shape: `[a-z0-9][a-z0-9.-]{0,62}`. Whether
/// a project reserves it is its rules'.
pub fn is_slug(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'.' || *b == b'-')
}

/// Whether `s` is an experiment id: `[a-z0-9][a-z0-9-]{0,39}`.
pub fn is_experiment_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 40
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// A URL naming a place: see [`check_scheme`], and no trailing `/`.
fn check_url(what: &str, url: &str) -> Result<(), String> {
    check_scheme(what, url)?;
    if url.ends_with('/') {
        return Err(format!("{what} '{url}' ends with '/'"));
    }
    Ok(())
}

/// An https URL with a host and no query or fragment — or an http one to the
/// loopback interface, which never leaves the machine it is read on: a
/// registry served there for a test of a whole client is held to its
/// signatures like any other.
fn check_scheme(what: &str, url: &str) -> Result<(), String> {
    let refused = || Err(format!("{what} '{url}' is not an https URL"));
    let Some((scheme, rest)) = url.split_once("://") else {
        return refused();
    };
    if rest.is_empty() || rest.starts_with('/') {
        return refused();
    }
    if url.contains(['?', '#']) {
        return Err(format!("{what} '{url}' carries a query or fragment"));
    }
    match scheme {
        "https" => Ok(()),
        "http" if is_loopback(rest) => Ok(()),
        _ => refused(),
    }
}

/// Whether the authority at the start of `rest` (`host[:port]/…`) is the
/// loopback interface.
fn is_loopback(rest: &str) -> bool {
    let authority = rest.split('/').next().unwrap_or_default();
    let host = match authority.strip_prefix('[') {
        Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
        None => authority.rsplit_once(':').map_or(authority, |(host, _)| host),
    };
    host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The `{name}` placeholders a template uses, in order of first use. A stray
/// brace is an error rather than literal text: templates are written by a
/// project's tooling, and a brace it did not mean is a defect.
pub fn placeholders_in(template: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find(['{', '}']) {
        if rest.as_bytes()[open] == b'}' {
            return Err(format!("'{template}' has an unmatched '}}'"));
        }
        let after = &rest[open + 1..];
        let close = after.find('}').ok_or_else(|| format!("'{template}' has an unclosed '{{'"))?;
        let name = &after[..close];
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            return Err(format!("'{template}' has a placeholder '{{{name}}}' that is not a name"));
        }
        if !out.iter().any(|n| n == name) {
            out.push(name.to_string());
        }
        rest = &after[close + 1..];
    }
    Ok(out)
}

/// Store a verified charter in a registry's folder, so what it vouches for can
/// be verified again with no network. Each file is replaced whole.
pub fn store(verified: &VerifiedCharter, folder: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(folder)?;
    write_whole(&folder.join(CHARTER_FILE), &verified.body)?;
    write_whole(&folder.join(CHARTER_SIG_FILE), &verified.envelope)
}

fn write_whole(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let partial = path.with_extension(format!("partial-{}", std::process::id()));
    std::fs::write(&partial, bytes)?;
    std::fs::rename(&partial, path)
}

/// Why a stored charter could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoredCharterError {
    #[error("cannot read {path}: {error}")]
    Unreadable { path: String, error: String },
    #[error(transparent)]
    Refused(CharterError),
}

/// Read and verify the charter stored in a registry's folder, and require the
/// folder to be named for it. The anchor is not known here: the caller holds
/// what the folder contains to the charter's anchor.
pub fn verify_stored(
    folder: &Path,
    trust: &CharterTrust,
    rules: &CharterRules,
    kind: &str,
    environment: Option<&str>,
    now: u64,
) -> Result<VerifiedCharter, StoredCharterError> {
    let read = |name: &str| {
        let path = folder.join(name);
        std::fs::read(&path)
            .map_err(|e| StoredCharterError::Unreadable { path: path.display().to_string(), error: e.to_string() })
    };
    let body = read(CHARTER_FILE)?;
    let envelope = read(CHARTER_SIG_FILE)?;
    let expect = CharterExpectation { anchor: None, kind, environment };
    let verified = verify_charter(&body, &envelope, trust, rules, &expect, now).map_err(StoredCharterError::Refused)?;
    let folder_name = folder.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    if folder_name != verified.charter.slug {
        return Err(StoredCharterError::Refused(CharterError::FolderMismatch {
            anchor: verified.charter.anchor.clone(),
            slug: verified.charter.slug.clone(),
            folder: folder_name.to_string(),
        }));
    }
    Ok(verified)
}

#[cfg(test)]
#[path = "charter_tests.rs"]
mod tests;
