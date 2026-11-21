"""Ścieżka analizy: produkty → CPE → findingi → ocena ryzyka → powiadomienia.

Uruchamiana po każdym skanie, synchronizacji feedów i decyzji w kolejce weryfikacji.
Cała konfiguracja decyzji pochodzi z plików w `rules/`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.orm import Session

from app.matching.cpe import CpeEntry, MatchingConfig, load_aliases
from app.matching.engine import (
    MatchReport,
    ProductReport,
    build_normalizer,
    evaluate_findings,
    resolve_products,
)
from app.matching.signals import SignalReport, match_signals
from app.models import Notification
from app.notifications.channels import Sender
from app.notifications.engine import NotificationConfig, notify
from app.planner.engine import ScanPlanner
from app.scoring.engine import ScoringConfig


@dataclass(frozen=True)
class Rulebook:
    matching: MatchingConfig
    scoring: ScoringConfig
    aliases: dict[str, CpeEntry]
    notifications: NotificationConfig
    planner: ScanPlanner

    @classmethod
    def from_dir(cls, rules_dir: Path) -> Rulebook:
        return cls(
            matching=MatchingConfig.from_file(rules_dir / "matching.yaml"),
            scoring=ScoringConfig.from_file(rules_dir / "scoring.yaml"),
            aliases=load_aliases(rules_dir / "product_aliases.yaml"),
            notifications=NotificationConfig.from_file(rules_dir / "notifications.yaml"),
            planner=ScanPlanner.from_file(rules_dir / "scan_rules.yaml"),
        )


@dataclass
class AnalysisReport:
    products: ProductReport = field(default_factory=ProductReport)
    findings: MatchReport = field(default_factory=MatchReport)
    notifications: list[Notification] = field(default_factory=list)
    signals: SignalReport = field(default_factory=SignalReport)

    def summary(self) -> dict[str, int]:
        return {
            "products_auto": self.products.auto,
            "products_needs_review": self.products.needs_review,
            "products_unmatched": self.products.unmatched,
            "findings_created": len(self.findings.of_kind("created")),
            "findings_rescored": len(self.findings.of_kind("rescored")),
            "findings_reopened": len(self.findings.of_kind("reopened")),
            "findings_resolved": len(self.findings.of_kind("resolved")),
            "versions_undetermined": self.findings.undetermined,
            "notifications": len(self.notifications),
            "signals_created": self.signals.created,
        }


def analyze(session: Session, rulebook: Rulebook, sender: Sender | None = None) -> AnalysisReport:
    normalizer = build_normalizer(session, rulebook.aliases)
    products = resolve_products(session, normalizer, rulebook.matching)
    findings = evaluate_findings(session, rulebook.scoring)
    signals = match_signals(session, normalizer, rulebook.matching)
    notifications = notify(session, findings.changes, rulebook.notifications, sender)
    return AnalysisReport(products, findings, notifications, signals)
