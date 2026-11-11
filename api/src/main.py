"""FastAPI control plane entrypoint for AutoHeal."""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from .config import get_settings
from .database import ensure_database
from .logging_config import configure_logging
from .routes import health, incidents, metrics, status
from .routes.metrics import API_REQUESTS_TOTAL

logger = logging.getLogger("control-plane-api")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Initialize logging and SQLite database on startup."""
    settings = get_settings()
    configure_logging(level=settings.log_level)
    ensure_database(settings.autoheal_db_path)
    logger.info(
        "AutoHeal control plane API started",
        extra={
            "event": "api_started",
            "api_port": settings.api_port,
            "db_path": settings.autoheal_db_path,
        },
    )
    yield
    logger.info("AutoHeal control plane API stopped", extra={"event": "api_stopped"})


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="AutoHeal Control Plane API",
        description="Read-only observability, service status, and incident history API for AutoHeal.",
        version="0.2.0",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def track_requests(request: Request, call_next):
        started = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        route = request.scope.get("route")
        route_path = route.path if route is not None else request.url.path
        API_REQUESTS_TOTAL.labels(
            method=request.method,
            path=route_path,
            status_code=str(response.status_code),
        ).inc()
        logger.info(
            "HTTP request processed",
            extra={
                "event": "api_request",
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        return response

    app.include_router(health.router)
    app.include_router(status.router)
    app.include_router(incidents.router)
    app.include_router(metrics.router)
    return app


app = create_app()

