# Pre-rename GHCR package state

The "before" half of the repository rename to `dotmac_platform_control_plane`.
Its whole value is that it was taken BEFORE the rename: a capture taken
afterwards proves nothing, because there is nothing left to compare it with.

- **Structured evidence:** `pre-rename-ghcr-package-state.json`, in this
  directory. That file is the authority; this page explains it.
- **Checker:** `scripts/verify_ghcr_package_state.py`, which re-measures and
  diffs against the frozen file.
- **Captured:** 2026-08-30T14:21:11Z, by `michaelayoade` (id `32591929`), with
  a credential holding `read:packages`.

The token that made the capture possible is short-lived and is removed
afterwards. Removal is part of the task, not tidying: the last step is proving
`GET /user/packages/container/dotmac_vendor_control_plane` answers `403` again.

## What was measured

The package is `dotmac_vendor_control_plane`, a **private** container package
owned by the user `michaelayoade`, linked to
`michaelayoade/dotmac_vendor_control_plane`, repository id **`1317527604`**,
with **23 versions** and 23 distinct digests. Every version is tagged with a
full 40-hex commit SHA; the newest is
`sha256:e77323f09c0a7d94bd4d27e53ddc9f3a030edc90b6d237a0c71e393e20e3ca2e`
tagged `36ff215be5a80bd84d31b6642b68f52097e9aeec`, and the oldest is
`sha256:514daef2d89b3bb1d208527b84a4aef4387943060e7e860452a66fa2c12e0ae0` at
`2026-08-14T09:59:41Z`.

**A private package under a public repository.** That split is unusual enough
to be worth stating on its own line, because it is the thing most likely to
change silently: a rename that flipped the package to public would be a real
security change wearing a bookkeeping disguise. `repository.private` is `false`
and `package.visibility` is `private`, and BOTH are checked afterwards.

## Two traps, both hit before this file existed

**1. The list endpoint omits private packages.**
`GET /user/packages?package_type=container` returns only public ones. Paged to
exhaustion it lists twelve, none linked to `1317527604` — from which the
obvious and wrong conclusion is that this repository has no package. The direct
`GET /user/packages/container/dotmac_vendor_control_plane` returns it at once.

Generalised: **any check concluding "no package exists" must first prove it
could have seen a private one.** A listing that cannot observe the thing it is
reporting absent is not evidence of absence.

**2. `platform-core` is a decoy.** An unlinked container package with that
name exists, 3 versions, newest created `2025-03-31` — over a year before this
repository was created (`2026-07-30`). Matching on a name that merely looks
right would have found it and been wrong in the other direction. Identify by
**linkage** (`repository.id`), never by name.

## What the REST API does not carry

The package object exposes `name`, `id`, `owner`, `package_type`,
`repository`, `visibility`, `version_count`, `created_at`, `updated_at`,
`url`, `html_url` — and nothing else. In particular the **permission
inheritance** setting and the **Actions access** setting are not present, and
`repository.permissions`, `repository.visibility` and `repository.archived`
are all `null` on this payload.

They are recorded in the JSON under `not_observable_via_rest` rather than
omitted, because an absent field in an evidence file otherwise reads as a
measurement that came back empty. If those two settings must be part of the
comparison, they have to be read from the package's web settings page by a
package administrator, before and after.

The before observation was completed by `michaelayoade` in the authenticated
package settings UI on 2026-08-30:

- **2026-08-30T16:30:17Z — permission inheritance ENABLED.** The checked
  control reads “Inherit access from source repository” and names
  `michaelayoade/dotmac_vendor_control_plane` as the source.
- **2026-08-30T16:30:30Z — Actions access is exactly one repository.** The
  only row is `michaelayoade/dotmac_vendor_control_plane`, role `Admin`.

The structured record keeps a distinct `post_rename_observation` for each
setting. Both were deliberately `null` before the rename, keeping the checker
red until the settings page was read again. The after observation was completed
by `michaelayoade` in the authenticated package settings UI on 2026-08-30:

- **2026-08-30T16:44:55Z — Actions access is exactly one repository.** The
  only row is `michaelayoade/dotmac_platform_control_plane`, role `Admin`.
- **2026-08-30T16:45:09Z — permission inheritance ENABLED.** The checked
  control names `michaelayoade/dotmac_platform_control_plane` as the source.

The before and after observations therefore match the desired access while
naming the canonical repository on their respective side of the rename.
Acknowledging that REST cannot see the settings is not a passing substitute.

## The image coordinate is a literal, and nothing enforces it

`ghcr.io/michaelayoade/dotmac_vendor_control_plane` appears at
`.github/workflows/production-image.yml:18` and
`.github/workflows/production-deploy.yml:75`. Because it is a literal rather
than something derived from `${{ github.repository }}`, a repository rename
does not change it — which is exactly what "preserve the image coordinate"
requires.

Stated honestly, and weaker than it may sound: this is a property of how the
workflows happen to be written, not a guarantee. Nothing checks that the
literal and the package still correspond. Recorded as an observation; not
changed here.

## The post-rename equality checks

Run `scripts/verify_ghcr_package_state.py` after the rename. It fails on any of:

1. **Repository id** is no longer `1317527604`.
2. **Linkage** is lost, or points at a different repository.
3. **Versions and digests** differ — compared as a set of digests, not as a
   count. A count alone would pass if one version were replaced by another.
4. **Visibility** changed on either side of the split: the package must still
   be `private` and the repository must still be public.
5. **Permission inheritance** is not observed enabled on both sides of the
   rename.
6. **Actions access** is not observed as the source repository alone, role
   `Admin`, on both sides of the rename.

And one whose API half is easy to get wrong:

7. **A redirect is not a canonical URL.** GitHub redirects the old repository
   URL after a rename, so any check that merely *resolves* the old coordinate
   passes while the canonical name is stale. The checker requires the NEW name
   from the linked package payload; proving the old coordinate still answers
   is refused.

If linkage is lost, reconnect it **without renaming or republishing the
package**. The first post-rename image workflow must prove package access
BEFORE it creates any release tag.
