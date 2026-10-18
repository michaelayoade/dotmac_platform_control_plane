# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through
[GitHub Security Advisories](https://github.com/michaelayoade/dotmac_vendor_control_plane/security/advisories/new).

**Do not open a public issue for a suspected vulnerability**, and do not include
credentials, tokens or customer data in a report. If you believe a secret has
been exposed, say so without quoting its value.

Expect an acknowledgement within five working days.

## What this repository is

The Dotmac Vendor Control Plane is a vendor-side assembly: it owns vendor
accounts, commercial contracts, provisioning and licence issuance. It is **not**
a product data plane and holds no operator or subscriber data.

## What is deliberately visible here

This repository is public so that its composition and boundaries can be read.
Some things that look sensitive are published on purpose, because they are
identifiers rather than secrets:

- **OpenBao paths** such as `secret/dotmac/licensing/signing-key`. A path names
  where material lives; it does not grant access to it. Every read is
  authenticated and authorised at the vault, and knowing a path confers nothing.
- **Hostnames and IP addresses.** `vendor.dotmac.io` resolves publicly. Treating
  a DNS record as a secret would be security theatre.
- **Deployment topology** — nginx configuration, container ports, the shape of
  the production host.

No key, token, password or certificate is published here, and none ever should
be. The repository's history has been audited for secret material across every
ref, blob, commit message, pull-request surface and retained Actions log.

## What is genuinely secret

Everything that grants access lives in OpenBao and is never committed:

- the licence signing key,
- the deployment SSH private key,
- database credentials,
- runtime application secrets,
- the Forgejo read token used by CI.

A change that would place any of these in the repository — including in a test
fixture, an example file or a comment — is a defect, not a convenience.

## Forks and CI

Workflows run on GitHub-hosted runners. Pull requests from forks do not receive
repository secrets, and workflow runs from outside contributors require
approval before they execute.

**Self-hosted runners are not used for pull-request workflows.** A persistent
self-hosted runner executing fork-supplied code would let an untrusted pull
request run on infrastructure we own, which is why that configuration is not
permitted here regardless of which branch proposes it.

## Supported versions

Pre-1.0 and under active development. Only `main` is supported; there are no
backports, and prior alpha releases receive no fixes.
