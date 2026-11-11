"""Health endpoint response schema."""

from __future__ import annotations

from pydantic import BaseModel


class ApiHealthResponse(BaseModel):
    """Control plane health check response."""

    status: str
    service: str
    database: str

