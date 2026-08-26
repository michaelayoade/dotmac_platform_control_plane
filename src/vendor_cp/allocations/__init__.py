"""Vendor adapters over authoritative entitlement-allocation state.

ADR-0006 and migration ``v014`` retired the local allocation writer. Contract
activation stages an immutable module allocation through the typed adapter;
licensing reads the same authority. No product data-plane grant is written here.
"""
