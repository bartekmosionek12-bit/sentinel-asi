"""Reguły raportów (`rules/reports.yaml`) i słownik terminów (`rules/glossary.yaml`)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.models.report import REPORT_LIGHTS
from app.scoring.engine import LEVEL_ORDER

# Pięć pytań warstwy „W skrócie” (docs/ARCHITECTURE.md, sekcja 12.3), w tej kolejności.
QUESTIONS: tuple[tuple[str, str], ...] = (
    ("what", "Co się stało?"),
    ("exposed", "Czy jesteśmy zagrożeni?"),
    ("worst", "Co najgorszego może się stać?"),
    ("todo", "Co trzeba zrobić?"),
    ("who", "Kto i do kiedy?"),
)
QUESTION_KEYS = tuple(key for key, _ in QUESTIONS)


@dataclass(frozen=True)
class LightRule:
    color: str
    reason: str
    min_level: str | None = None
    in_kev: bool | None = None
    exposure: str | None = None


@dataclass(frozen=True)
class PlainLanguage:
    max_tokens: int = 120
    min_chars: int = 30
    max_chars: int = 420
    max_sentences: int = 3
    max_words_per_sentence: int = 28


@dataclass(frozen=True)
class GlossaryTerm:
    key: str
    name: str
    definition: str


@dataclass(frozen=True)
class ReportsConfig:
    light: tuple[LightRule, ...]
    recipients: tuple[str, ...] = ("administrator",)
    max_findings_in_summary: int = 5
    fix_within_days: dict[str, int] = field(default_factory=dict)
    plain_language: PlainLanguage = field(default_factory=PlainLanguage)
    contradictions: dict[str, tuple[str, ...]] = field(default_factory=dict)
    glossary: tuple[GlossaryTerm, ...] = ()
    # Dane ze skanu starsze niż tyle godzin dostają ostrzeżenie (moduł 21, §25.1).
    freshness_hours: int = 24

    @property
    def abbreviations(self) -> frozenset[str]:
        """Skróty dozwolone w warstwie „W skrócie” (klucze słownika pisane wielkimi literami)."""
        return frozenset(term.key for term in self.glossary if term.key.isupper())

    @classmethod
    def from_dict(
        cls, data: dict[str, Any], glossary: dict[str, Any] | None = None
    ) -> ReportsConfig:
        rules: list[LightRule] = []
        for item in data.get("light") or []:
            when = item.get("when") or {}
            rule = LightRule(
                color=str(item["color"]),
                reason=str(item.get("reason", "")),
                min_level=when.get("min_level"),
                in_kev=when.get("in_kev"),
                exposure=when.get("exposure"),
            )
            if (
                rule.color not in REPORT_LIGHTS
                or (rule.min_level is not None and rule.min_level not in LEVEL_ORDER)
                or rule.exposure not in (None, "internet", "internal")
            ):
                raise ValueError(f"Nieprawidłowa reguła światła raportu: {item}")
            rules.append(rule)
        if not rules or any(r.min_level or r.in_kev is not None or r.exposure for r in rules[-1:]):
            raise ValueError("Ostatnia reguła światła musi być domyślna (bez warunków)")
        days = {str(k): int(v) for k, v in (data.get("fix_within_days") or {}).items()}
        if set(days) != set(LEVEL_ORDER):
            raise ValueError("fix_within_days musi mieć termin dla każdego poziomu ryzyka")
        contradictions = {
            str(color): tuple(str(p).lower() for p in phrases or ())
            for color, phrases in (data.get("contradictions") or {}).items()
        }
        terms = tuple(
            GlossaryTerm(str(key), str(value.get("name", key)), str(value.get("definition", "")))
            for key, value in ((glossary or {}).get("terms") or {}).items()
        )
        return cls(
            light=tuple(rules),
            recipients=tuple(str(r) for r in data.get("recipients") or ("administrator",)),
            max_findings_in_summary=int(data.get("max_findings_in_summary", 5)),
            fix_within_days=days,
            plain_language=PlainLanguage(**(data.get("plain_language") or {})),
            contradictions=contradictions,
            glossary=terms,
            freshness_hours=int(data.get("freshness_hours", 24)),
        )

    @classmethod
    def from_dir(cls, rules_dir: Path) -> ReportsConfig:
        def load(name: str) -> dict[str, Any]:
            path = rules_dir / name
            return yaml.safe_load(path.read_text(encoding="utf-8")) or {} if path.is_file() else {}

        return cls.from_dict(load("reports.yaml"), load("glossary.yaml"))
