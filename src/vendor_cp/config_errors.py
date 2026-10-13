"""Typed configuration refusal available before environment settings load."""


class ProductionConfigurationError(RuntimeError):
    """The process would start with a production-unsafe identity or mode."""
