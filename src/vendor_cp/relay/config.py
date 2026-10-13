"""Pure relay configuration acceptance, shared by startup and material probes."""

from vendor_cp.config import VendorSettings, vendor_settings


class RelayNotConfiguredError(RuntimeError):
    """No dispatcher credential, so there is nothing to drain WITH.

    Distinct from "nothing to drain": one is a deployment that cannot run the
    relay, the other is a relay with an empty queue, and they are the two states
    this package exists to keep apart.
    """


def require_dispatcher_dsn(settings: VendorSettings = vendor_settings) -> str:
    """The configured dispatcher DSN, or a refusal naming what is missing."""
    dsn = settings.relay_dispatcher_database_url.strip()
    if not dsn:
        raise RelayNotConfiguredError(
            "VENDOR_RELAY_DISPATCHER_DATABASE_URL is unset, so the platform "
            "outbox relay has no dispatcher credential and cannot claim a "
            "batch. Set it to the `platform_outbox_dispatcher` role's DSN "
            "against the one control-plane database."
        )
    return dsn
