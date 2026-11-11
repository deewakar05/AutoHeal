"""Entrypoint for the AutoHeal Python monitoring engine."""

from __future__ import annotations

import asyncio
import signal

from .config import get_settings
from .logging_config import configure_logging
from .monitor import MonitoringEngine


async def _run() -> None:
    settings = get_settings()
    logger = configure_logging(component="monitoring-engine", level=settings.log_level)

    engine = MonitoringEngine(settings=settings)
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _request_shutdown(sig_name: str) -> None:
        logger.info(
            "Received shutdown signal",
            extra={"event": "shutdown_signal", "signal": sig_name},
        )
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_shutdown, sig.name)
        except NotImplementedError:
            pass

    try:
        await engine.run_forever(stop_event)
    finally:
        await engine.shutdown()


def main() -> None:
    """Start the asynchronous monitoring service."""
    asyncio.run(_run())


if __name__ == "__main__":
    main()

