"""Odpowiedzi Sentka. Każdą buduje kod z danych w bazie, bez modelu językowego.

Odpowiedź to kilka krótkich zdań, linki do widoków konsoli zespołu IT i propozycje kolejnych
pytań. Sentek niczego nie uruchamia: prośbę o skan zamienia w propozycję zadania agenta, które
człowiek sam zleca i zatwierdza. Terminy to wewnętrzne terminy naprawy z `rules/reports.yaml`.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assistant.classify import Intent
from app.explainer.service import KIND as EXPLANATION_KIND
from app.iam.tokens import Principal
from app.matching.engine import ACTIVE_STATUSES
from app.models import Asset, AssetSource, Finding, LLMCache, Software, Vulnerability
from app.reports.config import ReportsConfig
from app.reports.facts import Item, deadline, open_items
from app.reports.freshness import freshness

DISCLAIMER = "Sentek pomaga czytać dane. Nie skanuje sieci i nie zmienia ustawień."
# Typy zasobów, które nie są hostem ani urządzeniem (nie liczą się w „ile mamy urządzeń”).
NON_DEVICE_TYPES = ("domain", "ip", "service", "application")
SOURCE_LABELS = {"scan": "skan sieci", "csv": "import CSV", "dns": "DNS", "dhcp": "DHCP"}
SUGGESTIONS = (
    "Co jest teraz najgroźniejsze?",
    "Ile mamy nowych hostów?",
    "Do kiedy trzeba naprawić zagrożenia?",
    "Co to jest KEV?",
    "Przeskanuj ponownie zakres",
)
# Uprawnienie potrzebne do odpowiedzi (poza samym `assistant:use`).
NEEDS: dict[str, str | None] = {
    "top_risks": "findings:read",
    "exposure_check": "findings:read",
    "deadlines": "findings:read",
    "devices": "inventory:read",
    "device_story": "inventory:read",
    "scan_request": "agent:task",
    "explain": None,
    "tour": None,
    "out_of_scope": None,
}
TYPE_LABELS = {
    "host": "host",
    "server": "serwer",
    "workstation": "stacja robocza",
    "laptop": "laptop",
    "network": "urządzenie sieciowe",
    "printer": "drukarka",
    "iot": "urządzenie IoT",
    "cloud": "zasób w chmurze",
    "ai_system": "system AI",
}
LEVEL_ORDER = ("krytyczny", "wysoki", "średni", "niski")


@dataclass
class Answer:
    intent: str
    source: str
    text: list[str]
    links: list[dict[str, str]] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    # Propozycja dla interfejsu: {"kind": "agent_task", "command": ...}. Sentek sam niczego
    # nie uruchamia; zadanie zleca człowiek, a plan agenta zatwierdza administrator albo editor.
    action: dict[str, Any] | None = None
    pose: str = "talk"
    freshness: str | None = None


def plural(count: int, one: str, few: str, many: str) -> str:
    if count == 1:
        return one
    if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return few
    return many


def count(n: int, one: str, few: str, many: str) -> str:
    """„1 urządzenie”, „3 urządzenia”, „5 urządzeń”."""
    return f"{n} {plural(n, one, few, many)}"


ITEMS = ("otwarte zagrożenie", "otwarte zagrożenia", "otwartych zagrożeń")
UNKNOWN = ("nowy host", "nowe hosty", "nowych hostów")


def _suggest(*exclude: str) -> list[str]:
    return [s for s in SUGGESTIONS if s not in exclude][:3]


def _label(item: Item) -> str:
    if item.vuln is not None:
        return item.vuln.cve_id
    if item.finding.type == "exposure":
        return "nowy host w sieci"
    return item.finding.type


def _fresh(session: Session, config: ReportsConfig) -> str:
    return freshness(session, config).label()


def no_permission(intent: Intent, permission: str) -> Answer:
    return Answer(
        intent.name,
        intent.source,
        [
            "Twoje konto nie ma dostępu do tych danych, więc nie mogę na to odpowiedzieć.",
            f"Potrzebne uprawnienie: {permission}. O dostęp poproś administratora.",
        ],
        suggestions=_suggest(),
        pose="surprised",
    )


def out_of_scope(intent: Intent) -> Answer:
    if intent.reason == "action":
        text = [
            "Tego nie zrobię: Sentek tylko czyta dane. Nie skanuje sieci i nie zmienia ustawień.",
            "Zmiany wprowadza zespół bezpieczeństwa w konsoli operacyjnej. Mogę pokazać, co "
            "jest najpilniejsze, albo przygotować prośbę o nowe skanowanie do zatwierdzenia.",
        ]
    else:
        text = [
            "Nie umiem jeszcze odpowiedzieć na to pytanie.",
            "Znam się na zagrożeniach, urządzeniach i działach, terminach naprawy, "
            "znaczeniu skrótów i prośbach o nowe skanowanie. Spróbuj na przykład:",
        ]
    return Answer(
        intent.name, intent.source, text, suggestions=list(SUGGESTIONS[:4]), pose="surprised"
    )


def top_risks(session: Session, intent: Intent, config: ReportsConfig, today: date) -> Answer:
    items = open_items(session)
    fresh = _fresh(session, config)
    if not items:
        return Answer(
            intent.name,
            intent.source,
            [
                "Nie ma teraz otwartych zagrożeń. To dobra wiadomość, "
                "ale zależy od świeżości danych."
            ],
            links=[{"label": "Stan bezpieczeństwa", "to": "/"}],
            suggestions=_suggest(),
            pose="thumbs_up",
            freshness=fresh,
        )
    critical = sum(1 for i in items if i.finding.risk_level == "krytyczny")
    kev = sum(1 for i in items if i.vuln is not None and i.vuln.in_kev)
    head = (
        f"Mamy {count(len(items), *ITEMS)}"
        + (
            f", w tym {critical} {plural(critical, 'krytyczne', 'krytyczne', 'krytycznych')}"
            if critical
            else ""
        )
        + "."
    )
    lines = [head]
    if kev:
        lines.append(
            f"{kev} {plural(kev, 'dotyczy', 'dotyczą', 'dotyczy')} podatności "
            "z katalogu KEV, czyli już wykorzystywanych w atakach."
        )
    lines.append("Najpilniejsze:")
    for index, item in enumerate(items[:3], start=1):
        due = deadline(item, config, today)
        lines.append(
            f"{index}. {item.asset.name}: {_label(item)}, ryzyko: {item.finding.risk_level}, "
            f"{item.finding.risk_score:.0f}/100, naprawić do {due.strftime('%d.%m.%Y')}."
        )
    return Answer(
        intent.name,
        intent.source,
        lines,
        links=[{"label": "Wszystkie zagrożenia", "to": "/zagrozenia"}],
        suggestions=_suggest("Co jest teraz najgroźniejsze?"),
        pose="point_right",
        freshness=fresh,
    )


def _device_scope(session: Session) -> Any:
    return select(Asset).where(
        Asset.type.not_in(NON_DEVICE_TYPES), Asset.status.in_(("active", "shadow", "missing"))
    )


def devices(session: Session, intent: Intent, config: ReportsConfig) -> Answer:
    assets = session.scalars(_device_scope(session)).all()
    unknown = [a for a in assets if a.status == "shadow"]
    fresh = _fresh(session, config)
    if intent.unknown:
        if not unknown:
            text = ["Nie widzę nowych hostów: każdy host z sieci jest już w inwentarzu."]
            pose = "thumbs_up"
        else:
            names = ", ".join(a.name for a in unknown[:4])
            text = [
                f"Widzę {count(len(unknown), *UNKNOWN)}: {names}.",
                "Odpowiadają w sieci, a nie było ich w inwentarzu ani w imporcie. "
                "Warto sprawdzić, czyje są, i oznaczyć je w karcie hosta.",
            ]
            pose = "surprised"
        return Answer(
            intent.name,
            intent.source,
            text,
            links=[{"label": "Zasoby", "to": "/zasoby"}],
            suggestions=_suggest("Ile mamy nowych hostów?"),
            pose=pose,
            freshness=fresh,
        )
    by_type: dict[str, int] = defaultdict(int)
    for asset in assets:
        by_type[TYPE_LABELS.get(asset.type, asset.type)] += 1
    kinds = ", ".join(
        f"{label}: {count}" for label, count in sorted(by_type.items(), key=lambda kv: -kv[1])
    )
    text = [
        f"Mamy {len(assets)} {plural(len(assets), 'host', 'hosty', 'hostów')}"
        + (f" ({kinds})." if kinds else ".")
    ]
    if unknown:
        text.append(
            f"{len(unknown)} z nich {plural(len(unknown), 'jest nowy', 'są nowe', 'jest nowych')}: "
            "odpowiadają w sieci, a nie było ich w inwentarzu."
        )
    return Answer(
        intent.name,
        intent.source,
        text,
        links=[{"label": "Zasoby", "to": "/zasoby"}],
        suggestions=_suggest(),
        pose="point_right",
        freshness=fresh,
    )


def device_story(session: Session, intent: Intent, config: ReportsConfig, today: date) -> Answer:
    if intent.device is None:
        return out_of_scope(intent)
    asset = session.get(Asset, uuid.UUID(intent.device.key))
    if asset is None:
        return out_of_scope(intent)
    kind = TYPE_LABELS.get(asset.type, asset.type)
    first = f"{asset.name} to {kind}"
    if asset.owner:
        first += f". Właściciel w inwentarzu: {asset.owner}"
    text = [first + "."]
    if asset.status == "shadow":
        sources = sorted(
            SOURCE_LABELS.get(s, s)
            for s in session.scalars(
                select(AssetSource.source).where(AssetSource.asset_id == asset.id)
            )
        )
        text.append(
            "To nowy host: widać go w sieci (" + ", ".join(sources) + "), "
            "a nie było go w inwentarzu."
        )
    items = [i for i in open_items(session) if i.asset.id == asset.id]
    if items:
        worst = items[0]
        text.append(
            f"Ma {count(len(items), *ITEMS)}. "
            f"Najpoważniejsze: {_label(worst)}, ryzyko: {worst.finding.risk_level}, "
            f"naprawić do {deadline(worst, config, today).strftime('%d.%m.%Y')}."
        )
        pose = "point_right"
    else:
        text.append("Nie ma otwartych zagrożeń.")
        pose = "thumbs_up"
    return Answer(
        intent.name,
        intent.source,
        text,
        links=[{"label": f"Karta hosta {asset.name}", "to": f"/zasoby/{asset.id}"}],
        suggestions=[f"Przeskanuj ponownie {asset.name}", *_suggest()[:2]],
        pose=pose,
        freshness=_fresh(session, config),
    )


def _cached_explanation(session: Session, cve_id: str) -> str | None:
    row = session.scalar(
        select(LLMCache)
        .where(
            LLMCache.kind == EXPLANATION_KIND,
            LLMCache.cache_key.like(f"{EXPLANATION_KIND}:{cve_id}:executive:%"),
            LLMCache.validation == "passed",
        )
        .order_by(LLMCache.prompt_version.desc())
        .limit(1)
    )
    return row.content.strip() if row is not None and row.content.strip() else None


def _cve_facts(vuln: Vulnerability) -> list[str]:
    parts = []
    if vuln.cvss_score is not None:
        parts.append(f"ocena powagi CVSS {vuln.cvss_score:.1f} na 10")
    if vuln.in_kev:
        parts.append("jest w katalogu KEV, czyli przestępcy już ją wykorzystują")
    if vuln.epss is not None:
        parts.append(f"szansa wykorzystania w 30 dni według EPSS: {vuln.epss * 100:.0f}%")
    return parts


def explain(
    session: Session, intent: Intent, config: ReportsConfig, principal: Principal
) -> Answer:
    if intent.cve is not None:
        if not principal.can("findings:read"):
            return no_permission(intent, "findings:read")
        vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == intent.cve))
        if vuln is None:
            return Answer(
                intent.name,
                intent.source,
                [
                    f"Nie znam {intent.cve}: nie ma jej w lokalnej bazie podatności "
                    "(NVD, KEV, EPSS).",
                    "Jeśli to nowa podatność, pojawi się po najbliższej synchronizacji feedów.",
                ],
                suggestions=_suggest(),
                pose="surprised",
            )
        text = [f"{vuln.cve_id} to podatność w publicznym rejestrze CVE."]
        facts = _cve_facts(vuln)
        if facts:
            text.append("Najważniejsze fakty: " + "; ".join(facts) + ".")
        cached = _cached_explanation(session, vuln.cve_id)
        if cached:
            text.append(cached)
        return Answer(
            intent.name,
            intent.source,
            text,
            links=[{"label": "Zagrożenia", "to": "/zagrozenia"}],
            suggestions=[f"Czy jesteśmy podatni na {vuln.cve_id}?", *_suggest()[:2]],
        )
    if intent.term is None:
        return out_of_scope(intent)
    term = next((t for t in config.glossary if t.key == intent.term.key), None)
    if term is None:
        return out_of_scope(intent)
    return Answer(
        intent.name,
        intent.source,
        [f"{term.name}: {term.definition}"],
        suggestions=_suggest("Co to jest KEV?"),
    )


def exposure_check(session: Session, intent: Intent, config: ReportsConfig) -> Answer:
    fresh = _fresh(session, config)
    caveat = (
        "Sprawdzam inwentarz i wyniki ostatniego skanu, więc odpowiedź jest tak świeża jak te dane."
    )
    if intent.cve is not None:
        vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == intent.cve))
        if vuln is None:
            return Answer(
                intent.name,
                intent.source,
                [
                    f"Nie znam {intent.cve}: nie ma jej w lokalnej bazie podatności.",
                    "Nie potrafię więc powiedzieć, czy nas dotyczy. "
                    "Sprawdzę po synchronizacji feedów.",
                ],
                suggestions=_suggest(),
                pose="surprised",
                freshness=fresh,
            )
        items = open_items(session, cve_ids=[vuln.cve_id])
        if not items:
            return Answer(
                intent.name,
                intent.source,
                [f"Nie widzę {vuln.cve_id} na żadnym naszym urządzeniu.", caveat],
                suggestions=_suggest(),
                pose="thumbs_up",
                freshness=fresh,
            )
        names = ", ".join(sorted({i.asset.name for i in items})[:5])
        hit = len({i.asset.id for i in items})
        return Answer(
            intent.name,
            intent.source,
            [
                f"Tak. {vuln.cve_id} dotyczy "
                f"{count(hit, 'urządzenia', 'urządzeń', 'urządzeń')}: {names}.",
                f"Najwyższe ryzyko: {items[0].finding.risk_level} "
                f"({items[0].finding.risk_score:.0f}/100).",
                caveat,
            ],
            links=[{"label": "Zagrożenia", "to": "/zagrozenia"}],
            suggestions=[f"Co to jest {vuln.cve_id}?", "Do kiedy trzeba naprawić zagrożenia?"],
            pose="surprised",
            freshness=fresh,
        )
    if intent.product is None:
        return out_of_scope(intent)
    product = intent.product.name
    assets = session.scalars(
        select(Asset)
        .join(Software, Software.asset_id == Asset.id)
        .where(Software.product == product)
        .distinct()
    ).all()
    if not assets:
        return Answer(
            intent.name,
            intent.source,
            [f"Nie widzę programu {product} w naszym inwentarzu.", caveat],
            suggestions=_suggest(),
            pose="thumbs_up",
            freshness=fresh,
        )
    ids = [a.id for a in assets]
    open_count = session.scalar(
        select(Finding.id)
        .where(Finding.asset_id.in_(ids), Finding.status.in_(ACTIVE_STATUSES))
        .limit(1)
    )
    names = ", ".join(sorted(a.name for a in assets)[:5])
    text = [
        f"Tak, {product} działa na "
        f"{count(len(assets), 'urządzeniu', 'urządzeniach', 'urządzeniach')}: {names}."
    ]
    text.append(
        "Na tych urządzeniach są otwarte zagrożenia, szczegóły w widoku zagrożeń."
        if open_count
        else "Na tych urządzeniach nie ma otwartych zagrożeń."
    )
    text.append(caveat)
    return Answer(
        intent.name,
        intent.source,
        text,
        links=[{"label": "Zasoby", "to": "/zasoby"}],
        suggestions=_suggest(),
        pose="point_right",
        freshness=fresh,
    )


def deadlines(session: Session, intent: Intent, config: ReportsConfig, today: date) -> Answer:
    items = open_items(session)
    rules = ", ".join(
        f"{level} {count(config.fix_within_days[level], 'dzień', 'dni', 'dni')}"
        for level in LEVEL_ORDER
        if level in config.fix_within_days
    )
    note = (
        f"To wewnętrzne terminy naprawy ({rules}; krócej, gdy CISA wyznaczyła termin w KEV). "
        "Terminów ustawowych tu nie podaję."
    )
    if not items:
        return Answer(
            intent.name,
            intent.source,
            ["Nie ma otwartych zagrożeń, więc nie ma terminów.", note],
            suggestions=_suggest(),
            pose="thumbs_up",
        )
    dated = sorted(((deadline(i, config, today), i) for i in items), key=lambda pair: pair[0])
    lines = ["Najbliższe terminy:"]
    for due, item in dated[:4]:
        lines.append(
            f"{due.strftime('%d.%m.%Y')}: {item.asset.name}, {_label(item)} "
            f"(ryzyko: {item.finding.risk_level})."
        )
    soon = sum(1 for due, _ in dated if (due - today).days <= 7)
    if soon:
        lines.append(
            f"W ciągu tygodnia: {soon} {plural(soon, 'zagrożenie', 'zagrożenia', 'zagrożeń')}."
        )
    lines.append(note)
    return Answer(
        intent.name,
        intent.source,
        lines,
        links=[{"label": "Wszystkie zagrożenia", "to": "/zagrozenia"}],
        suggestions=_suggest("Do kiedy trzeba naprawić zagrożenia?"),
        pose="point_right",
        freshness=_fresh(session, config),
    )


def scan_request(session: Session, intent: Intent, config: ReportsConfig) -> Answer:
    if intent.device is not None:
        label = f"host {intent.device.name}"
        command = f"Przeskanuj ponownie host {intent.device.name} (odkrywanie usług, L1)"
    else:
        label = "cały autoryzowany zakres"
        command = "Przeskanuj ponownie cały autoryzowany zakres (odkrywanie hostów i usług, L1)"
    return Answer(
        intent.name,
        intent.source,
        [
            f"Mogę przygotować zadanie dla agenta: nowy skan ({label}).",
            "Sam nie skanuję. Zadanie zlecasz Ty, agent przygotuje plan, a skan ruszy dopiero po "
            "zatwierdzeniu planu przez administratora albo editora. Każdy cel przechodzi przez "
            "scope_guard.",
            _fresh(session, config),
        ],
        action={"kind": "agent_task", "command": command},
        links=[{"label": "Agent AI", "to": "/agent"}],
        suggestions=_suggest(),
        pose="point_left",
    )


def tour(intent: Intent) -> Answer:
    return Answer(
        intent.name,
        intent.source,
        [
            "Pulpit pokazuje stan skanów i zagrożeń. Zasoby to inwentarz hostów z historią, "
            "Skany to przebiegi i akcje do zatwierdzenia, a Agent AI przyjmuje zadania, "
            "których plan zatwierdza człowiek.",
            "Pytaj mnie o hosty, zagrożenia, terminy i podatności CVE.",
        ],
        links=[{"label": "Pulpit", "to": "/"}],
        suggestions=_suggest(),
        pose="wave",
    )


def build(
    session: Session,
    intent: Intent,
    config: ReportsConfig,
    principal: Principal,
    today: date,
) -> Answer:
    needed = NEEDS.get(intent.name)
    if needed is not None and not principal.can(needed):
        return no_permission(intent, needed)
    if intent.name == "top_risks":
        return top_risks(session, intent, config, today)
    if intent.name == "devices":
        return devices(session, intent, config)
    if intent.name == "device_story":
        return device_story(session, intent, config, today)
    if intent.name == "explain":
        return explain(session, intent, config, principal)
    if intent.name == "exposure_check":
        return exposure_check(session, intent, config)
    if intent.name == "deadlines":
        return deadlines(session, intent, config, today)
    if intent.name == "scan_request":
        return scan_request(session, intent, config)
    if intent.name == "tour":
        return tour(intent)
    return out_of_scope(intent)
