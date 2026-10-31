# signed-release

Verifies what a publisher signed, against the root keys a client was built with.

A project that publishes releases signs every manifest through a chain that starts at root
keys its clients bake in:

1. **Root keys** sign release-key certificates. A certificate is trusted only when two
   distinct baked roots have each signed its exact bytes.
2. **A release-key certificate** authorizes one release key under one label, the environment a
   client reads (`prod`, `staging`, …), between its issue and its expiry.
3. **A release key** signs the exact bytes of a document. The signature and the certificates
   that authorize the key travel in an envelope beside the document.

**A charter** declares a registry: the URL it is named by, its kind, the label its contents are
signed under, where its documents are, and its name on disk. It is verified against the
project's charter trust, which is a different type from the content trust manifests are
verified against, so neither can stand in for the other.

Nothing here belongs to one project. The words that name each document format, the label
charters are signed under, and the kinds of registry a project charters are given by the
caller, from the project's own declaration.

```rust
use signed_release::{verify_manifest, Formats, Trust};

let trust = Trust::new(
    &[ROOT_A, ROOT_B, ROOT_C],
    "prod",
    Formats {
        certificate: "example-release-key-cert/1".into(),
        envelope: "example-manifest-sig/1".into(),
    },
)?;
let chain = verify_manifest(&envelope_bytes, &manifest_bytes, &trust, signed_release::unix_now())?;
```

Every check is a hard failure, and a refusal carries a [`Reason`] from a closed vocabulary, so
every client of a project decides the same way.

## Licence

MIT.
