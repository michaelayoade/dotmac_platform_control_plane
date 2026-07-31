"""Immutable priced offer versions (vendor lane slice 1).

An `OfferVersion` is a frozen, priced statement of what an offer grants — the
thing a commercial contract line pins (ContractService design). Versions are
**immutable**: once published, `(offer_code, version)` never changes; a new price
or capability set is a NEW version. Prices are exact `Money` (never float);
capability codes must be **declared** (WS1 catalogue). Platform-level, owned by
the vendor control plane. See `docs/design/contract-service.md`.
"""
