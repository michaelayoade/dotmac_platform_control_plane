"""Run the step-8 verifier surface over a JSON corpus, with whichever package is named.

Usage: `python foundation_runner.py <package> < corpus.json > results.json`, where
`<package>` is `dotmac_deployment_foundation` (the wheel, in its own venv) or
`vendor_cp.vendored_foundation` (the vendored copy). Standard library only, so it
runs in the wheel venv without CP. Output per case: accept/refuse, error class
name, stable code, message, and the sha256 of `signed_bytes()` and of the envelope
digest. Nothing here is a secret: the corpus uses synthetic keys.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import sys


def run(package: str, corpus: dict[str, object]) -> dict[str, dict[str, object]]:
    thm = importlib.import_module(f"{package}.trusted_host_source")
    results: dict[str, dict[str, object]] = {}
    for name, mapping in corpus.items():
        try:
            envelope = thm.AttestationEnvelopeV2.from_mapping(mapping)
            results[name] = {
                "outcome": "accepted",
                "signed_bytes_sha256": hashlib.sha256(
                    envelope.signed_bytes()
                ).hexdigest(),
                "envelope_digest": str(thm.attestation_envelope_digest(envelope)),
            }
        except Exception as exc:  # noqa: BLE001 - the class name is the datum
            results[name] = {
                "outcome": "refused",
                "error": type(exc).__name__,
                "code": getattr(exc, "code", None),
                "message": str(exc),
            }
    return results


if __name__ == "__main__":
    json.dump(run(sys.argv[1], json.load(sys.stdin)), sys.stdout, sort_keys=True)
