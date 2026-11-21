"""PDF raportu: ta sama struktura co w konsoli (Jinja2 + WeasyPrint, ARCHITECTURE §12.3).

Do szablonu trafia wyłącznie widok raportu już po redakcji dla odbiorcy (ta sama funkcja co
w odpowiedziach API), więc PDF „W skrócie” nie zawiera adresów IP ani danych technicznych,
których odbiorca bez `secrets:redacted:view` nie widzi w konsoli. WeasyPrint nie pobiera niczego
z sieci: `url_fetcher` odmawia każdego adresu, a szablon nie ma zasobów zewnętrznych (czcionki
systemowe, style w pliku).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.iam.redaction import redact
from app.models import Report
from app.reports.service import present

TEMPLATES = Path(__file__).resolve().parent / "templates"
LIGHT_LABELS = {"red": "Czerwone", "yellow": "Żółte", "green": "Zielone"}
LIGHT_MEANING = {
    "red": "wymaga pilnych działań",
    "yellow": "wymaga zaplanowanych działań",
    "green": "bez pilnych działań",
}
KIND_LABELS = {
    "assessment": "Ocena stanu bezpieczeństwa",
    "zero_day": "Zero-day",
    "digest": "Podsumowanie zbiorcze",
    "ai_test": "Test bezpieczeństwa agenta AI",
}

_env = Environment(
    loader=FileSystemLoader(TEMPLATES),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


class PdfError(Exception):
    """PDF nie powstał (brak bibliotek systemowych WeasyPrint albo błąd renderowania)."""


def _no_fetch(url: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
    raise PdfError(f"PDF nie pobiera zasobów zewnętrznych ({url[:60]})")


def render_html(view: dict[str, Any], *, generated_at: datetime, audience: str) -> str:
    return _env.get_template("report.html.j2").render(
        report=view,
        light_label=LIGHT_LABELS.get(view.get("light", ""), view.get("light", "")),
        light_meaning=LIGHT_MEANING.get(view.get("light", ""), ""),
        kind_label=KIND_LABELS.get(view.get("kind", ""), view.get("kind", "")),
        generated_at=generated_at,
        audience=audience,
    )


def render_pdf(view: dict[str, Any], *, generated_at: datetime, audience: str) -> bytes:
    html = render_html(view, generated_at=generated_at, audience=audience)
    try:
        from weasyprint import HTML  # type: ignore[import-untyped]
    except (ImportError, OSError) as error:  # pragma: no cover - zależy od obrazu
        raise PdfError(f"WeasyPrint niedostępny ({error.__class__.__name__})") from error
    document = HTML(string=html, base_url=None, url_fetcher=_no_fetch)
    pdf = document.write_pdf()
    if not pdf:  # pragma: no cover
        raise PdfError("WeasyPrint zwrócił pusty dokument")
    return bytes(pdf)


def filename(view: dict[str, Any]) -> str:
    created = str(view.get("created_at", ""))[:10] or "raport"
    kind = str(view.get("kind", "raport")).replace("_", "-")
    return f"sentinel-{kind}-{created}.pdf"


def report_view(report: Report, *, technical: bool, personal: bool) -> dict[str, Any]:
    """Widok raportu po redakcji: ten sam dla PDF w API i w załączniku e-maila."""
    shown = present(report, personal=not personal)
    view = {
        "id": str(report.id),
        "kind": report.kind,
        "title": report.title,
        "light": report.light,
        "light_reason": report.light_reason,
        "summary_source": report.summary_source,
        "created_at": report.created_at.isoformat(),
        "created_by": report.created_by,
        "summary": shown["summary"],
        "facts": shown["facts"],
        "technical": shown["technical"],
    }
    if not technical:
        return view
    return dict(redact(view, technical=True))
