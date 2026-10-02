# Disposable OpenBao SSH policy proof

This is a preparation fixture for the proposed Gate-0 controller SSH CA role.
It does not provision or approve a deployed OpenBao role, principal, CA,
source-address range, GitHub OIDC binding, runner, or certificate lifetime.
The fixture uses documentation-only addresses (`192.0.2.0/24` and
`198.51.100.0/24`) and an isolated, generated key.

Run only on Michael's named disposable testserver, with Docker and
`ssh-keygen` installed. Install the exact OpenBao 2.5.3 image by immutable
digest first, then run from a clean copy of this repository:

```sh
python3 -m openbao_policy_conformance.proof \
  --image 'openbao/openbao@sha256:fdc6da21ca6963560c32336fd7feb9cf2d5e52668f1a1647205a4b41171f0806'
```

The digest above was read from the registry on the named testserver on
2026-10-02; the driver requires a caller-supplied immutable digest and
independently checks the running `/sys/health` version is exactly `2.5.3`.
An absent image, Docker, SSH tool, API, or expected refusal fails the command;
there are no skips or fake OpenBao responses in the live proof.

The driver starts one uniquely named container on a uniquely named internal
Docker network with tmpfs storage and no published port. It checks the
container's exact instance label and sole network, then uses only that
network's RFC1918 IPv4 address on port 8200 from the test host. If host access
to that internal address fails, the proof fails; there is no external-network
fallback. The HTTP client ignores inherited proxies and refuses redirects.
It initializes and unseals a normal server,
generates an SSH CA inside that disposable server, writes only random fixture
private records to its KV engine, and creates short-lived scoped tokens. Its
strict token can update exactly `ssh-fixture/sign/controller`, with a closed
allowlist of request parameters and exact principal, certificate type and key
ID values. A separate issuer fixture token can read only the public trust
record and cannot sign. Neither token can read the signer or attester private
KV records; root reads each record after writing it as a positive control.
The key ID allowlist is a fixture constant only: this proof does not establish
an authenticated production run-ID binding.

OpenBao 2.5.3's SSH backend returns `default_critical_options` for both an
omitted and an empty `critical_options` request map. A nonempty request map
replaces the default rather than merging with it. The driver parses the
actual returned OpenSSH certificate with `ssh-keygen -Lf` in all three cases:
strict positive, backend omitted/empty, and a sensitivity case. The latter
changes only the policy's `critical_options` allowlist entry and proves that
the alternative `source-address` is then present in a signed certificate.
The strict policy refuses that request. These are distinct backend and ACL
claims; the role's `allowed_critical_options=source-address` permits the
backend sensitivity case, and the scoped ACL is what closes the override.

The public JSON report contains the immutable image coordinates, server
version, fixed case names and count. It contains no token, unseal share,
private key, signed certificate, API response body or container log. On
failure, the driver emits a fixed diagnostic without response bodies and
stops only its own labelled container. Temporary key and certificate files
live in a `0700` directory outside the checkout and are removed on exit.

The local, runtime-free checks are:

```sh
python3 -m unittest discover -s tests/unit -p 'test_openbao_policy_conformance*.py'
```

OpenBao source coordinates used to define the conformance cases:

- `v2.5.3/builtin/logical/ssh/path_roles.go`, `default_critical_options`,
  `allowed_critical_options`, `allowed_user_key_lengths`, certificate-type
  and principal role fields.
- `v2.5.3/builtin/logical/ssh/path_issue_sign.go`,
  `calculateCriticalOptions`, `calculateExtensions`,
  `calculateValidPrincipals`, `calculateCertificateType` and `sign`.

This fixture does not test real GitHub OIDC claims, actual target SSH login,
runner isolation, a production policy, or measured run-duration/TTL selection.
