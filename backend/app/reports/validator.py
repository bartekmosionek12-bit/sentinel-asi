"""Walidacja warstwy „W skrócie”: pochodzenie faktów, tokeny, prosty język, zgodność z oceną.

Tekst modelu dla kierownictwa przechodzi, tylko gdy:
- każdy token `asset_<n>`/`person_<n>` pochodzi z kontekstu, a w tekście nie ma adresów IP,
  domen ani nazw zasobów (model nigdy ich nie widział, więc mogły przyjść tylko z wstrzyknięcia),
- identyfikatory CVE, wersje i daty pochodzą z faktów; nie ma linków ani poleceń,
- odpowiedź nie przeczy światłu policzonemu przez kod (np. „ryzyko jest niskie” przy czerwonym),
- spełnia rubrykę prostego języka (długość, liczba i długość zdań, skróty ze słownika, polszczyzna).

Błędy faktów i sprzeczności odrzucają odpowiedź bez ponownej próby; błędy formy pozwalają na
jedną ponowną próbę. Szablon kodu przechodzi tę samą walidację (test).
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass

from app.explainer.guards import (
    copies_prompt,
    secret_request,
    shell_command,
    trusted_text,
    unknown_identifiers,
)
from app.explainer.validator import (
    _ABBREVIATIONS_RE,
    _CODE_RE,
    _DATE_RE,
    _URL_RE,
    _VERSION_RE,
    CVE_RE,
    Problem,
    ValidationResult,
    count_sentences,
    looks_polish,
)
from app.reports.config import QUESTIONS, ReportsConfig

TOKEN_RE = re.compile(r"\b(?:asset|person)_\d+\b")
# Model bywa, że zacznie zdanie od „Person_1”; bez normalizacji token nie zostałby podmieniony.
_ANY_CASE_TOKEN_RE = re.compile(r"\b(asset|person)_(\d+)\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:[a-z]{2,24})\b", re.IGNORECASE)
ABBREVIATION_RE = re.compile(r"\b[A-ZĄĆĘŁŃÓŚŹŻ]{2,}\b")
_WORD_RE = re.compile(r"\S+")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?…])\s+")


@dataclass(frozen=True)
class SummaryContext:
    """Wszystko, co walidator wie o raporcie (te same dane dostał model)."""

    facts: Mapping[str, list[str]]
    entities: Mapping[str, Mapping[str, object]]
    light: str
    products: Collection[str] = ()
    system_prompt: str = ""

    def facts_text(self) -> str:
        return "\n".join(line for lines in self.facts.values() for line in lines)

    def trusted_text(self) -> str:
        """Fakty bez opisów z rejestru: źródło dozwolonych CVE, wersji, dat i identyfikatorów."""
        return trusted_text(self.facts_text())


def _abbreviations_allowed(config: ReportsConfig, context: SummaryContext) -> set[str]:
    allowed = set(config.abbreviations)
    for product in context.products:
        allowed.update(ABBREVIATION_RE.findall(product))
    return allowed


def _sentences(text: str) -> list[str]:
    return [part for part in _SENTENCE_SPLIT_RE.split(text.strip()) if part]


def check_answer(
    key: str, text: str, *, config: ReportsConfig, context: SummaryContext
) -> list[Problem]:
    problems: list[Problem] = []
    label = dict(QUESTIONS)[key]
    stripped = text.strip()
    if not stripped:
        return [Problem("empty", f"{label}: brak odpowiedzi", True)]
    # Opis CVE z rejestru widzi model, ale nie jest źródłem faktów (pośrednie injection).
    facts = context.trusted_text()

    # --- fakty i dane, których model nie mógł znać: odrzucenie bez ponownej próby ---
    for token in dict.fromkeys(TOKEN_RE.findall(stripped)):
        if token not in context.entities:
            problems.append(Problem("unknown_token", f"{label}: {token} spoza kontekstu", False))
    leaked = [
        str(entity.get("name"))
        for entity in context.entities.values()
        if entity.get("name") and str(entity.get("name")).lower() in stripped.lower()
    ]
    if IPV4_RE.search(stripped) or IPV6_RE.search(stripped) or leaked:
        problems.append(
            Problem("identity_leak", f"{label}: adres albo nazwa zasobu lub osoby w tekście", False)
        )
    without_ids = CVE_RE.sub(" ", stripped)
    products = " ".join(context.products).lower()
    plain = _ABBREVIATIONS_RE.sub(" ", _URL_RE.sub(" ", without_ids))
    for domain in DOMAIN_RE.findall(plain):
        if domain.lower() not in products:
            problems.append(Problem("domain", f"{label}: nazwa domeny {domain} w tekście", False))
            break
    for cve in dict.fromkeys(m.upper() for m in CVE_RE.findall(stripped)):
        if cve not in facts.upper():
            problems.append(Problem("unknown_cve", f"{label}: {cve} nie pochodzi z faktów", False))
    for version in dict.fromkeys(_VERSION_RE.findall(_DATE_RE.sub(" ", without_ids))):
        if version not in facts:
            problems.append(
                Problem("unknown_version", f"{label}: wersja {version} spoza faktów", False)
            )
    for found in dict.fromkeys(_DATE_RE.findall(stripped)):
        if found not in facts:
            problems.append(Problem("unknown_date", f"{label}: data {found} spoza faktów", False))
    if _URL_RE.search(stripped) or _CODE_RE.search(stripped) or shell_command(stripped):
        problems.append(Problem("url_or_command", f"{label}: link albo polecenie w tekście", False))
    if secret_request(stripped):
        problems.append(
            Problem("secret_request", f"{label}: prośba o hasło, kod albo przelew", False)
        )
    strangers = unknown_identifiers(without_ids, f"{facts}\n{products}")
    if strangers:
        problems.append(
            Problem(
                "unknown_identifier",
                f"{label}: identyfikator spoza faktów: {', '.join(strangers[:3])}",
                False,
            )
        )
    if context.system_prompt and copies_prompt(stripped, context.system_prompt):
        problems.append(
            Problem("prompt_leak", f"{label}: fragment instrukcji systemowych w tekście", False)
        )
    lowered = " ".join(stripped.lower().split())
    for phrase in config.contradictions.get(context.light, ()):
        if phrase in lowered:
            problems.append(
                Problem(
                    "contradiction",
                    f"{label}: „{phrase}” przeczy ocenie systemu ({context.light})",
                    False,
                )
            )
            break

    # --- forma i prosty język: jedna ponowna próba ---
    rubric = config.plain_language
    if not rubric.min_chars <= len(stripped) <= rubric.max_chars:
        problems.append(
            Problem(
                "length",
                f"{label}: {len(stripped)} znaków poza {rubric.min_chars}–{rubric.max_chars}",
                True,
            )
        )
    if count_sentences(stripped) > rubric.max_sentences:
        problems.append(
            Problem("sentences", f"{label}: więcej niż {rubric.max_sentences} zdania", True)
        )
    for sentence in _sentences(stripped):
        if len(_WORD_RE.findall(sentence)) > rubric.max_words_per_sentence:
            problems.append(
                Problem(
                    "long_sentence",
                    f"{label}: zdanie dłuższe niż {rubric.max_words_per_sentence} słów",
                    True,
                )
            )
            break
    allowed = _abbreviations_allowed(config, context)
    unknown = sorted(set(ABBREVIATION_RE.findall(CVE_RE.sub(" ", stripped))) - allowed)
    if unknown:
        problems.append(
            Problem("jargon", f"{label}: skróty spoza słownika: {', '.join(unknown)}", True)
        )
    return problems


def validate_summary(
    answers: Mapping[str, str], *, config: ReportsConfig, context: SummaryContext
) -> ValidationResult:
    problems: list[Problem] = []
    for key, label in QUESTIONS:
        if key not in answers:
            problems.append(Problem("format", f"brak odpowiedzi na pytanie „{label}”", True))
            continue
        problems.extend(check_answer(key, answers[key], config=config, context=context))
    joined = " ".join(TOKEN_RE.sub("zasób", answers.get(key, "")) for key, _ in QUESTIONS)
    polish, why = looks_polish(joined)
    if not polish:
        problems.append(Problem("language", why, True))
    return ValidationResult(tuple(problems))


def parse_answers(text: str) -> dict[str, str]:
    """Dzieli odpowiedź modelu na pięć części po nagłówkach z pytaniami."""
    positions: list[tuple[int, int, str]] = []
    lowered = text.lower()
    for key, label in QUESTIONS:
        found = lowered.find(label.lower())
        if found >= 0:
            positions.append((found, found + len(label), key))
    positions.sort()
    answers: dict[str, str] = {}
    for index, (_start, end, key) in enumerate(positions):
        stop = positions[index + 1][0] if index + 1 < len(positions) else len(text)
        body = text[end:stop].strip().strip("*#:- \n").strip()
        body = _ANY_CASE_TOKEN_RE.sub(lambda m: f"{m[1].lower()}_{m[2]}", body)
        answers[key] = " ".join(body.split())
    return answers
