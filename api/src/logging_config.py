"""Structured JSON logging configuration for the FastAPI control plane."""

from __future__ import annotations

import logging

from remediation.src.logging_config import (
    STANDARD_RECORD_ATTRS,
    JsonFormatter as BaseJsonFormatter,
    configure_logging as base_configure_logging,
)

__all__ = ["STANDARD_RECORD_ATTRS", "JsonFormatter", "configure_logging"]


class JsonFormatter(BaseJsonFormatter):
    """Formats API logs as single-line JSON."""

    def __init__(self, component: str = "control-plane-api") -> None:
        super().__init__(component=component)


def configure_logging(level: str = "INFO") -> logging.Logger:
    """Configure root JSON logging for the API service."""
    return base_configure_logging(component="control-plane-api", level=level)
