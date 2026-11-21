"""Macierz rola × endpoint × akcja do docs/ROLES.md, wyliczana z kodu i `rules/roles.yaml`.

    python -m app.iam.roles_doc        # wypisuje część generowaną
    python -m app.iam.roles_doc --write  # podmienia ją w docs/ROLES.md

Test `tests/test_roles_doc.py` pilnuje, żeby dokument zgadzał się z kodem: nowy endpoint albo
zmiana w pliku ról bez aktualizacji dokumentu nie przejdzie CI.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.routing import APIRoute

from app.iam.deps import AUTHENTICATED, PERMISSION_ATTR, PUBLIC
from app.iam.rbac import RoleCatalog

BEGIN = "<!-- roles_doc:begin (generowane: python -m app.iam.roles_doc --write) -->"
END = "<!-- roles_doc:end -->"
HUMAN_ROLES = ("administrator", "editor", "modifier", "viewer")
DOC = Path(__file__).resolve().parents[3] / "docs" / "ROLES.md"


def declarations(route: Any) -> list[str]:
    found: list[str] = []

    def walk(dependant: Any) -> None:
        marker = getattr(dependant.call, PERMISSION_ATTR, None)
        if marker is not None:
            found.append(marker)
        for sub in dependant.dependencies:
            walk(sub)

    walk(route.dependant)
    return found


def api_routes(app: FastAPI) -> list[Any]:
    """Trasy API z zależnościami w postaci, w jakiej obsługuje je aplikacja (z routerów)."""
    routes: list[Any] = []
    for route in app.routes:
        if isinstance(route, APIRoute):
            routes.append(route)
        elif hasattr(route, "effective_route_contexts"):  # router dołączony (FastAPI ≥ 0.160)
            routes.extend(route.effective_route_contexts())
    return routes


def _mark(catalog: RoleCatalog, role: str, permission: str) -> str:
    if permission in (AUTHENTICATED, PUBLIC):
        return "✓"
    return "✓" if permission in catalog.roles[role].permissions else "·"


def render(catalog: RoleCatalog, app: FastAPI) -> str:
    lines = [BEGIN, "", "### Uprawnienia ról", ""]
    lines.append("| Uprawnienie | MFA | " + " | ".join(HUMAN_ROLES) + " | Opis |")
    lines.append("|---|---|" + "---|" * len(HUMAN_ROLES) + "---|")
    for item in sorted(catalog.permissions.values(), key=lambda p: p.name):
        marks = " | ".join(_mark(catalog, role, item.name) for role in HUMAN_ROLES)
        mfa = "tak" if item.mfa else ""
        lines.append(f"| `{item.name}` | {mfa} | {marks} | {item.description} |")
    lines += ["", "### Endpointy", ""]
    lines.append("| Metoda | Ścieżka | Wymaga | " + " | ".join(HUMAN_ROLES) + " |")
    lines.append("|---|---|---|" + "---|" * len(HUMAN_ROLES))
    rows = []
    for route in api_routes(app):
        found = declarations(route)
        permission = found[0] if found else "BRAK"
        for method in sorted(route.methods):
            rows.append((route.path, method, permission))
    for path, method, permission in sorted(rows):
        label = {AUTHENTICATED: "zalogowany", PUBLIC: "publiczny"}.get(
            permission, f"`{permission}`"
        )
        marks = " | ".join(
            _mark(catalog, role, permission) if permission != "BRAK" else "·"
            for role in HUMAN_ROLES
        )
        lines.append(f"| {method} | `{path}` | {label} | {marks} |")
    lines += ["", END]
    return "\n".join(lines)


def replace_section(document: str, section: str) -> str:
    start = document.index(BEGIN)
    end = document.index(END) + len(END)
    return document[:start] + section + document[end:]


def current_section(document: str) -> str:
    return document[document.index(BEGIN) : document.index(END) + len(END)]


def main() -> int:
    from app.iam.deps import get_role_catalog
    from app.main import create_app

    section = render(get_role_catalog(), create_app())
    if "--write" in sys.argv:
        DOC.write_text(replace_section(DOC.read_text(encoding="utf-8"), section), encoding="utf-8")
    else:
        sys.stdout.write(section + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
