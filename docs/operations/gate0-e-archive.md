# Gate0 E private archive mechanism

This source slice packages a finalization owner's complete private collection and
canonical inner manifest. It creates no readiness decision, signature, publisher,
ReleaseEvidence authority, recipient, or B custody claim. Constructing a profile
or producing ciphertext does not qualify any supplied pin or accept Gate0 E.
Current D1 remains open; actual E closure depends on accepted B/C1/C2/D and the
protected campaign, authenticated cleanup, immutable release readback, actual B
custody decrypt/proof verification and the canonical acceptance owner.

`package_private_collection(inner_manifest, proof_files, profile, deadline=...)`
returns ciphertext bytes and bare lowercase SHA-256 hashes of ciphertext,
plaintext archive and inner manifest. Its caller supplies the original finite
monotonic packaging deadline. Every real GPG child shares that deadline; pipe I/O
and process waits reserve its final second for group cancellation and reaping.
Failure, interruption and excess output signal the still-owned, unreaped process
group and reap the actual child. Already reaped PID/PGID numbers are never
signaled. A signal, stream-close or wait error is sticky; remaining cleanup steps
and one bounded reap retry still run against the same absolute deadline. A cleanup deadline failure refuses the result. Root runner
containment remains necessary against a process stuck in an uninterruptible OS
state; this module cannot turn such a failure into acceptance.

The archive is an uncompressed USTAR byte string, at most 16 MiB. Its exact sorted
flat roster is `collection.json`, `manifest.json`, `prerequisites.json`,
`producer.json`, `receipt.json`. All entries are regular files with mode 0600,
UID/GID/mtime zero, empty owner names, no extended headers and no paths or links.
The four payloads retain the finalizer's exact bytes. They include the complete
private collection and its retained exact proof/root-record bytes; no A/B proof
is reconstructed from a public projection. The packager validates archive format
and member hashes; the finalizer and actual B verifier own semantic completeness.

The manifest is ASCII canonical JSON (`sort_keys=True`, separators `,` and `:`,
`ensure_ascii=True`, no trailing newline). It has exactly this shape:

```json
{"files":{"collection.json":{"length":1,"sha256":"..."},"prerequisites.json":{"length":1,"sha256":"..."},"producer.json":{"length":1,"sha256":"..."},"receipt.json":{"length":1,"sha256":"..."}},"schema":"Gate0EArchiveManifest.v1"}
```

Actual lengths are positive integers and hashes are exact lowercase SHA-256;
`...` above is documentation only. The manifest excludes itself. Its digest is
returned separately. Ciphertext hashes and the allowlisted public projection are
built after encryption to avoid a hash cycle. `unpack_private_archive` is the
bounded byte-only inverse for the B holder: it never invokes a generic tar
reader or extracts to disk. It checks the five physical USTAR headers in fixed
order, exact metadata and octal sizes before reading bounded payload slices,
then checks zero padding and the exact writer trailer. GNU/PAX extensions, sparse
files, links, duplicate names, trailing bytes and noncanonical headers are refused
before generic extension processing or sparse expansion can occur. It checks all
member lengths and hashes and returns unchanged bytes. It does not decrypt or accept E.

The operational qualification owner must provide the existing B public
certificate as binary OpenPGP packets, its SHA-256, primary fingerprint, exact
encryption-key fingerprint, a pinned absolute GPG executable/hash and exact
`gpg (GnuPG) 2.x.y` version line. No version or recipient is chosen by this source.
The executable and every ancestor must be root owned, nonsymlinked and not group
or world writable; the executable must be a regular executable file no larger
than 64 MiB. The protected runner's qualified installation must cover its runtime
libraries, system configuration and private staging boundary as well. Root is
part of that installation's existing trust boundary. The profile's current key
bytes must incorporate the B owner's qualified revocation/expiry view; this
module deliberately performs no keyserver or network refresh.

Before import, bounded packet framing rejects secret-key/subkey packets,
additional primary certificates, armored/opaque data and partial certificate
lengths. A fresh 0700 temporary GNUPGHOME holds only the public keyring. Actual
GPG colon output binds the sole primary and the exact pinned encryption key,
checks effective encryption capability, creation/expiry times and
revoked/expired/disabled/invalid status, and confirms no secret keys were imported.
No B private key belongs on the protected producer/publisher runner.

GPG receives only an explicit minimal environment. `--no-options`, a fresh home,
explicit public keyring, `--no-default-keyring`, `--no-encrypt-to`, disabled auto
key lookup/import/retrieval and `--no-autostart` prevent ambient user options,
additional recipients or agent use. The fixed invocation uses AES256, no
compression, an empty embedded filename and the exact fingerprint with `!` to
prevent subkey substitution. Input plaintext travels only through stdin;
plaintext is never placed in argv, a plaintext temporary file, logs or diagnostics.
Stderr is discarded. Output is bounded and parsed to require exactly one pinned
recipient packet followed by integrity-protected encrypted data. Encryption runs
once; failure never retries or returns a partial ciphertext. Process/parser errors
become fixed refusal codes without raw diagnostic text. In-memory Python bytes
are not a secure-erasure mechanism.

Flag behavior was checked against the primary GnuPG manual:
[operational commands](https://www.gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html),
[configuration options](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html),
and [esoteric options](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Esoteric-Options.html).
The qualified host/version still requires the actual compatibility lane: this
profile deliberately refuses unsupported packet forms rather than broadening to
an unqualified format.

Focused unit source exercises canonical packing, inverse parsing, private key
and wrong/expired/revoked recipient refusals, output framing, real subprocess
full-duplex I/O, early EOF, bounded output, timeout, cancellation and owned process reaping; no signal after reap, independent
cleanup attempts after signal/close/wait failures, physical longname/PAX/sparse
refusals, invalid sizes, duplicates and unqualified-tool execution refusal.
`conformance/test_gate0_e_archive_gpg.py` is a separately invoked hosted mechanism
lane with mandatory `GATE0_TEST_QUALIFIED_GPG`,
`GATE0_TEST_QUALIFIED_GPG_SHA256`, `GATE0_TEST_QUALIFIED_GPG_VERSION` and
`GATE0_TEST_QUALIFIED_GPGCONF`, `GATE0_TEST_QUALIFIED_GPGCONF_SHA256` and
`GATE0_TEST_QUALIFIED_GPGCONF_VERSION` installation inputs.
`qualify_gnupg_tools` validates both tools' absolute root-protected paths and
hashes before either tool executes, then checks each actual exact version. All
of these checks complete before any synthetic key generation or cleanup command;
qualification failure enters no synthetic key-operation/agent-cleanup scope. It generates only an ephemeral
synthetic key, proves actual encryption/decryption byte equality and hostile
inherited-config isolation, and shuts down its own synthetic agent in `finally`.
The hosting owner qualifies both tools. Absent tool pins fail this lane; no skip
stands in for acceptance. This is one format/process compatibility test, not
another synthetic Gate0 campaign or actual existing B custody verification.

This preparation was limited to source, AST parsing and Ruff 0.6.9. Unit and
conformance tests, local project imports, mypy, builds, installs, Docker, host
operations, publication and custody operations were not executed here.
