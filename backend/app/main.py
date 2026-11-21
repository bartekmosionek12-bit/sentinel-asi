"""Punkt wejścia API."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.agent import router as agent_router
from app.api.assistant import router as assistant_router
from app.api.auth import router as auth_router
from app.api.explain import router as explain_router
from app.api.iam import router as iam_router
from app.api.reports import router as reports_router
from app.api.routes import router
from app.api.scans import router as scans_router
from app.api.threats import router as threats_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.request_context import RequestContextMiddleware


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    app = FastAPI(
        title="Sentinel ASI",
        version=__version__,
        description=(
            "Attack Surface Intelligence: centralny inwentarz, dopasowanie zagrożeń "
            "do zasobów, deterministyczny scoring ryzyka."
        ),
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )
    # Ostatni dodany działa jako pierwszy: identyfikator żądania obejmuje też odpowiedzi CORS.
    app.add_middleware(RequestContextMiddleware)
    app.include_router(auth_router)
    app.include_router(threats_router)
    app.include_router(explain_router)
    app.include_router(scans_router)
    app.include_router(reports_router)
    app.include_router(agent_router)
    app.include_router(assistant_router)
    app.include_router(iam_router)
    app.include_router(router)
    return app


app = create_app()
