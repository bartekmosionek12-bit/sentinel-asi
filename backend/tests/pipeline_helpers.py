"""Wspólne dane do testów ścieżki: konfiguracja z `rules/` i mały inwentarz demo."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.feeds.base import OfflineSource
from app.feeds.service import sync_all
from app.inventory.service import (
    asset_fingerprint,
    import_assets,
    parse_assets_csv,
    record_host_scan,
)
from app.inventory.sources import touch_source
from app.matching.cpe import MatchingConfig, load_aliases
from app.models import Asset
from app.scanners.models import HostScan, ServiceInfo
from app.scoring.engine import ScoringConfig

RULES = Path(__file__).resolve().parents[2] / "rules"
FEEDS_DIR = Path(__file__).parent / "fixtures" / "feeds"

MATCHING = MatchingConfig.from_file(RULES / "matching.yaml")
SCORING = ScoringConfig.from_file(RULES / "scoring.yaml")
ALIASES = load_aliases(RULES / "product_aliases.yaml")

ASSETS_CSV = """name,type,address,exposure,criticality,owner,tags
web-01,host,172.30.99.10,internet,5,Zespół WWW,prod
proxy-01,host,172.30.99.11,internal,2,Zespół WWW,
legacy-01,host,172.30.99.12,internal,3,,
"""

SERVICES = {
    "172.30.99.10": (
        ServiceInfo(
            80,
            "tcp",
            "http",
            "Apache httpd",
            "2.4.49",
            "(Unix)",
            ("cpe:/a:apache:http_server:2.4.49",),
        ),
    ),
    "172.30.99.11": (
        ServiceInfo(80, "tcp", "http", "nginx", "1.18.0", "", ("cpe:/a:igor_sysoev:nginx:1.18.0",)),
    ),
    "172.30.99.12": (
        ServiceInfo(
            80,
            "tcp",
            "http",
            "Apache httpd",
            "2.4.25",
            "(Debian)",
            ("cpe:/a:apache:http_server:2.4.25",),
        ),
        ServiceInfo(3000, "tcp", "ppp"),
    ),
}


def asset_by_ip(session: Session, ip: str) -> Asset:
    asset = session.scalar(select(Asset).where(Asset.fingerprint == f"host:{ip}"))
    assert asset is not None
    return asset


def seed_inventory(session: Session) -> None:
    rows, errors = parse_assets_csv(ASSETS_CSV)
    assert errors == []
    import_assets(session, rows, source="csv", actor="test")
    for ip, services in SERVICES.items():
        record_host_scan(session, asset_by_ip(session, ip), HostScan(ip=ip, services=services))


def seed_feeds(session: Session) -> None:
    assert sync_all(session, OfflineSource(FEEDS_DIR)).ok


def seed_new_host(session: Session) -> Asset:
    """Fikcyjny host, który odpowiedział w skanie, a nie było go w inwentarzu (`shadow`)."""
    asset = Asset(
        type="workstation",
        name="DESKTOP-7Q2KD1",
        fingerprint=asset_fingerprint("workstation", "DESKTOP-7Q2KD1"),
        status="shadow",
    )
    session.add(asset)
    session.flush()
    touch_source(session, asset, "scan")
    return asset
