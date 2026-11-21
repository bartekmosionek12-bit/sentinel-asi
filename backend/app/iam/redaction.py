"""Redakcja danych wrażliwych w odpowiedziach API.

Kto nie ma uprawnienia `secrets:redacted:view` (np. rola własna utworzona bez niego), dostaje
te same odpowiedzi bez adresów IP i bez surowych danych technicznych (banery, dowody, parametry
skanów). Redakcja działa w warstwie serializacji odpowiedzi, więc nie zależy od tego, co pokaże
interfejs.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.routing import APIRoute

REDACTED_ADDRESS = "[adres ukryty]"
VIEW_PERMISSION = "secrets:redacted:view"

# Klucze, których wartości są w całości danymi technicznymi. `inputs` wpisów audytu zostają
# (widać, na podstawie czego zapadła decyzja), ale z zamaskowanymi adresami.
_EMPTY_DICT_KEYS = frozenset({"attributes", "evidence", "params", "payload"})
_NULL_KEYS = frozenset({"raw_banner", "banner", "detail_raw", "resolved", "cpe"})

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.])")
# Kandydaci na IPv6 (także skrócone `::`); o tym, czy to adres, rozstrzyga `ipaddress`.
_IPV6_CANDIDATE = re.compile(
    r"(?<![0-9A-Fa-f:.])[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(?:/\d{1,3})?"
)


def _mask_ipv6(match: re.Match[str]) -> str:
    text = match.group(0)
    try:
        ipaddress.ip_interface(text)
    except ValueError:
        return text
    return REDACTED_ADDRESS


def redact_text(value: str) -> str:
    return _IPV6_CANDIDATE.sub(_mask_ipv6, _IPV4.sub(REDACTED_ADDRESS, value))


def redact(value: Any, *, technical: bool = True) -> Any:
    """Kopia odpowiedzi bez danych technicznych (`technical=False` zwraca ją bez zmian)."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if technical and key in _EMPTY_DICT_KEYS:
                out[key] = {} if isinstance(item, dict) else None
            elif technical and key in _NULL_KEYS:
                out[key] = None
            else:
                out[key] = redact(item, technical=technical)
        return out
    if isinstance(value, list):
        return [redact(item, technical=technical) for item in value]
    if technical and isinstance(value, str):
        return redact_text(value)
    return value


def _is_json(response: Response) -> bool:
    # FastAPI serializuje modele odpowiedzi do zwykłego `Response` z typem JSON.
    if isinstance(response, StreamingResponse):
        return False
    content_type = response.headers.get("content-type", "")
    return content_type.startswith("application/json") and bool(getattr(response, "body", b""))


class RedactingRoute(APIRoute):
    """Trasa, która redaguje odpowiedź JSON dla wywołującego bez pełnego wglądu."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            response = await original(request)
            principal = getattr(request.state, "principal", None)
            if principal is None or not _is_json(response):
                return response
            if principal.can(VIEW_PERMISSION):
                return response
            body = redact(json.loads(bytes(response.body)), technical=True)
            headers = {k: v for k, v in response.headers.items() if k.lower() != "content-length"}
            return JSONResponse(body, status_code=response.status_code, headers=headers)

        return handler
