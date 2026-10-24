#!/usr/bin/env bash
# Disposable validation input, rebuilt from immutable historical source.
# This is neither the previous accepted artifact's bytes nor a release image.
set -euo pipefail
SOURCE_REVISION=348c31315efaaca9ea23ea7c025d137a3afaad74
SOURCE_IMAGE=dotmac-native-source-fixture:348c31315efaaca9ea23ea7c025d137a3afaad74
: "${FORGEJO_READ_TOKEN:?the existing read-only BuildKit dependency secret is required}"
fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT
# A new bare repository carries no checkout credentials, hooks or remotes.
git init --bare "$fixture_root/objects" >/dev/null
git -C "$fixture_root/objects" -c credential.helper= -c core.hooksPath=/dev/null \
    fetch --no-tags \
    https://github.com/michaelayoade/dotmac_platform_control_plane.git "$SOURCE_REVISION"
test "$(git -C "$fixture_root/objects" rev-parse FETCH_HEAD)" = "$SOURCE_REVISION"
git -C "$fixture_root/objects" update-ref refs/heads/source-fixture "$SOURCE_REVISION"
git -C "$fixture_root/objects" bundle create "$PWD/native-source.bundle" source-fixture
mkdir "$fixture_root/build"
git -C "$fixture_root/objects" archive "$SOURCE_REVISION" | tar -x -C "$fixture_root/build"
docker build --secret id=forgejo_token,env=FORGEJO_READ_TOKEN \
    --build-arg "SOURCE_REVISION=$SOURCE_REVISION" \
    --tag "$SOURCE_IMAGE" "$fixture_root/build"
# Public source declarations remain historical; never rewrite them as observations.
git -C "$fixture_root/objects" show "$SOURCE_REVISION:deploy/product.toml" \
    > native-source-descriptor.toml
if test -n "${GITHUB_ENV:-}"; then
    printf 'NATIVE_SOURCE_IMAGE=%s\n' "$SOURCE_IMAGE" >> "$GITHUB_ENV"
fi
