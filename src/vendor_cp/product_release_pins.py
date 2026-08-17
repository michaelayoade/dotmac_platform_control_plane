"""Exact, canonical product-release pin declarations.

The runtime settings loader and the production operator both consume this
module. Keeping parsing and rendering here means a host update cannot accept a
shape that the application later refuses (or silently reinterpret one the
application accepts).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class ProductReleasePin:
    """Exact artifact and product-manifest identities selected by an operator."""

    artifact_digest: str
    product_manifest_digest: str

    def __post_init__(self) -> None:
        if _SHA256_RE.fullmatch(self.artifact_digest) is None:
            raise ValueError(
                "artifact_digest must be 'sha256:' plus 64 lowercase hex digits"
            )
        if _SHA256_RE.fullmatch(self.product_manifest_digest) is None:
            raise ValueError(
                "product_manifest_digest must be 'sha256:' plus 64 lowercase "
                "hex digits"
            )


def _validate_product_code(product_code: object) -> str:
    if (
        not isinstance(product_code, str)
        or not product_code
        or product_code != product_code.strip()
    ):
        raise ValueError("product release pin keys must be non-blank strings")
    return product_code


def parse_product_release_pins(
    raw: str,
) -> tuple[tuple[str, ProductReleasePin], ...]:
    """Parse the one accepted JSON shape and return it in canonical key order."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("VENDOR_PRODUCT_RELEASE_PINS_JSON must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("VENDOR_PRODUCT_RELEASE_PINS_JSON must be an object")

    pins: list[tuple[str, ProductReleasePin]] = []
    for raw_product_code, document in parsed.items():
        product_code = _validate_product_code(raw_product_code)
        if not isinstance(document, dict) or set(document) != {
            "artifact_digest",
            "product_manifest_digest",
        }:
            raise ValueError(
                f"release pin for product {product_code!r} must contain exactly "
                "artifact_digest and product_manifest_digest"
            )
        if not all(isinstance(value, str) for value in document.values()):
            raise ValueError(
                f"release pin digests for product {product_code!r} must be strings"
            )
        pins.append(
            (
                product_code,
                ProductReleasePin(
                    artifact_digest=document["artifact_digest"],
                    product_manifest_digest=document["product_manifest_digest"],
                ),
            )
        )
    return tuple(sorted(pins))


def render_product_release_pins(
    pins: Mapping[str, ProductReleasePin],
) -> str:
    """Render validated pins as deterministic, single-line JSON for dotenv."""
    document: dict[str, dict[str, str]] = {}
    for raw_product_code, pin in pins.items():
        product_code = _validate_product_code(raw_product_code)
        if not isinstance(pin, ProductReleasePin):
            raise ValueError("product release pins must be ProductReleasePin values")
        document[product_code] = {
            "artifact_digest": pin.artifact_digest,
            "product_manifest_digest": pin.product_manifest_digest,
        }
    rendered = json.dumps(document, sort_keys=True, separators=(",", ":"))
    # Rendering must never become a second schema implementation.
    parse_product_release_pins(rendered)
    return rendered


__all__ = [
    "ProductReleasePin",
    "parse_product_release_pins",
    "render_product_release_pins",
]
