"""Standalone entry point for the AutoHeal monitoring service."""

from __future__ import annotations

import asyncio
import logging
import signal

from .logging_config import configure_logging
from .monitor import MonitoringEngine
from .monitor_config import get_settings


async def _run() -> None:
    settings = get_settings()
    configure_logging("monitor", settings.log_level)

    logger = logging.getLogger("monitor")
    engine = MonitoringEngine(settings)
    stop_event = asyncio.Event()

    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    logger.info(
        "AutoHeal monitoring service initialized",
        extra={"event": "monitor_service_initialized"},
    )

    try:
        await engine.run_forever(stop_event)
    finally:
        await engine.shutdown()


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
