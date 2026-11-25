# Reviewed private artifact producer — source draft

`private-artifact-produce.yml` is a source-only draft, not activation authority.
No dispatch or acquisition profile is approved. Hosted test acceptance remains
held on qualified bootstrap; no local tests, package installation or acquisition
qualifies this source. The fleet token identity/capability map, reachability
repair, protected environment configuration, alternate-ref refusal evidence and
remaining secret-free consumers remain open. Existing workflows, repository
secrets, environments, production and stores are unchanged by this draft.

The only new workflow is a main-only `workflow_dispatch` producer using the literal
`dependency-bundle` environment. Its Forgejo credential is exclusively
`FORGEJO_BUNDLE_READ_TOKEN` in the acquisition step; there is no repository-secret
fallback. The environment must separately enforce a main-only branch policy
before activation. Workflow guards and SHA pins do not provide that boundary.

The adapter executes trusted CP main tooling and imports Workspace's binder from
`michaelayoade/dotmac_workspace` at
`baa69b8291d77897553694c359bd8bb9906915ea`, checking the exact helper source hash
before import. It reuses that helper's dispatch admission, fixed-ref GitHub blob
binding and before/after PR head confirmation; it adds no API transport. Only
`pyproject.toml` and `poetry.lock` are read from the reviewed candidate as data.
No candidate checkout, build backend, resolver, package import or install runs.

This baseline accepts the actual protected-base manifest digest
`57eb78949f1b652614ba0670a09a9d6814d4149d2f61c4e403d1a6b50d3d9e78`
or the explicitly reviewed combined-candidate manifest digest
`22311a7d1927cac7c4ebdef1490a977063c1fed616dedc6672a500c2b61c280c`,
each paired only with lock digest
`92a147efe3c1cd5c7997d2eb5e982342b40ac3e0e604e1d4837829f8fc0a9301`.
Both must describe the same seven fixed private package pins and fourteen unique
wheel/sdist identities and hashes. This is not a general dependency upgrade path;
an a18 candidate requires a separate qualified artifact decision.

`kernel_lock.acquire` owns transfer and the existing `files/`, `simple/`,
`pages/`, `digests.json` layout. Its optional exact-set path rejects duplicate
index entries, changed hashes, missing/extra files and replacement bytes. Sdists
remain opaque data. The credential lives in a temporary private HOME's mode-0600
netrc, never argv; curl subprocesses do not inherit the credential variable.
Every bundle file, including downloaded pages and binary artifacts, is scanned
for the owner's known credential encodings before the upload step can run.
That scan checks raw bytes, not archive contents or every possible encoding, and
is defence in depth rather than proof of credential absence. A nonsecret receipt
binds repository, reviewed PR/head, tooling revision/hash, actual pair hashes,
trusted main revision and run/attempt. The actual `GITHUB_WORKFLOW_REF` must
name this exact producer path at `refs/heads/main`, and `GITHUB_WORKFLOW_SHA`
must equal the trusted checkout's `GITHUB_SHA`. The receipt also carries that
workflow ref/revision and the SHA256 of the workflow file read from the trusted
CP checkout. Retention is fourteen days; no consumer
cutover, cache protocol or new envelope protocol is introduced.
