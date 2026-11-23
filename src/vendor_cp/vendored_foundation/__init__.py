"""Vendored Foundation attestation verifier (CP #266, H1; PROVISIONAL pending E5).

Step 8 (`lane3_e10 record-destruction`) parses an installed attestation I(D) and
digests it. That must run from the image, and the image must not contain
`dotmac-deployment-foundation` (CI acceptance step 17 asserts its absence). So the
three Foundation source files that closure needs are carried here BYTE FOR BYTE:

    errors.py, digest.py, trusted_host_source.py

and pinned by `PINS.json` (source path -> sha256) to the Starter Foundation source
tree 940cdf344b49d1b2bce16383978a7ee9ebc21460 at commit e4f9a072. E5 is NOT yet
certified, so the pin is provisional: if E5 changes a Foundation byte, re-vendor and
regenerate `PINS.json`; do not hand-edit these files. `tests/unit/
test_vendored_foundation_pins.py` fails on any drift, and the hosted differential
test compares this code with a Foundation wheel built from the pinned commit.

This `__init__` is CP's own (Foundation's would import the whole facility). The
files are relative-import only, so they work unchanged in this package.
"""
