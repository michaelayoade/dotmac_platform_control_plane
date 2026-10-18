"""Finite installed E readback after the publication workflow has completed."""

import sys

from vendor_cp.deployment.gate0_e_github import (
    InstalledGate0GitHubReads,
    ProducerStage,
)
from vendor_cp.deployment.gate0_e_writer import InstalledEWriter


def run_installed_verify_e_published() -> int:
    """Read three independently qualified slots and use the existing E verifier.

    The concrete readers retain their one-use phases, absolute phase deadlines,
    exchange and byte caps. Original readers and their original issued objects
    remain paired through the writer's joins and direct official verifier call.
    No output artifact or acceptance state is written by this adapter.
    """
    try:
        publication_reads = (
            InstalledGate0GitHubReads.from_installed_publication_completion()
        )
        publication = publication_reads.publication_complete_snapshot()
        producer_reads = InstalledGate0GitHubReads.from_installed_producer_completion()
        producer = producer_reads.producer_snapshot(ProducerStage.PRODUCER_RUN_COMPLETE)
        release_reads = InstalledGate0GitHubReads.from_installed_published_release()
        release = release_reads.published_snapshot()
        InstalledEWriter.from_installed().verify_published(
            release_reads,
            release,
            publication_reads,
            publication,
            producer_reads,
            producer,
        )
    except Exception:
        print("GATE0_E_UNAVAILABLE", file=sys.stderr)
        return 3
    print("E_PUBLISHED_VERIFIED")
    return 0
