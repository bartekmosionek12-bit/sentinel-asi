"""Skan od planu do findingów: brama, zgody L2, rate limit, błędy narzędzia."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.scope_guard import ScopeConfig, ScopeGuard, SeedDemoApproval
from app.inventory.service import import_assets, parse_assets_csv
from app.models import Asset, AuditLog, Finding, Notification, ScanAction, Software
from app.pipeline import Rulebook
from app.scanners.models import ServiceInfo
from app.scanners.nmap import NmapAdapter
from app.scans.service import ScanActionError, ScanService
from tests.conftest import FakeResolver, MemoryAudit
from tests.pipeline_helpers import ASSETS_CSV, RULES, SERVICES, asset_by_ip, seed_feeds
from tests.scanner_fakes import FakeLab

RULEBOOK = Rulebook.from_dir(RULES)
LAB = "172.30.99.0/24"
SCOPE: dict[str, Any] = {"allow": {"cidrs": [LAB]}, "deny": {"cidrs": ["172.30.99.1/32"]}}


def _guard(
    audit_sink: MemoryAudit,
    scope: dict[str, Any] | None = None,
    *,
    demo_mode: bool = False,
    lab: str = LAB,
    expires_in_hours: float = 4,
) -> ScopeGuard:
    return ScopeGuard(
        ScopeConfig.from_dict(SCOPE if scope is None else scope),
        audit=audit_sink,
        resolver=FakeResolver(),
        seed_demo=SeedDemoApproval(
            demo_mode=demo_mode,
            lab_network=ip_network(lab),
            expires_at=datetime.now(UTC) + timedelta(hours=expires_in_hours),
        ),
    )


@pytest.fixture
def lab() -> FakeLab:
    return FakeLab(SERVICES)


@pytest.fixture
def seeded(session: Session) -> Session:
    seed_feeds(session)
    rows, _ = parse_assets_csv(ASSETS_CSV)
    import_assets(session, rows, source="csv", actor="test")
    return session


def _service(session: Session, guard: ScopeGuard, lab: FakeLab) -> ScanService:
    return ScanService(session, guard, RULEBOOK, nmap=NmapAdapter(lab.runner))


def _actions(session: Session) -> list[tuple[str, str, str]]:
    return [
        (a.rule_name, a.target, a.status)
        for a in session.scalars(select(ScanAction).order_by(ScanAction.created_at))
    ]


def test_full_run_discovers_scans_matches_scores_and_notifies(
    seeded: Session, audit_sink: MemoryAudit, lab: FakeLab
) -> None:
    run = _service(seeded, _guard(audit_sink), lab).run(trigger="manual", actor="test")

    assert run.status == "done"
    assert run.summary["hosts_up"] == 3
    assert run.summary["findings_created"] == 3
    assert run.summary["products_needs_review"] == 1
    assert run.summary["notifications"] == 1
    assert _actions(seeded) == [
        ("scope_sweep", LAB, "done"),
        ("stale_host_service_rescan", "172.30.99.10", "done"),
        ("stale_host_service_rescan", "172.30.99.11", "done"),
        ("stale_host_service_rescan", "172.30.99.12", "done"),
        # web-01 ma podatność z KEV: pełny skan portów to L2, czeka na człowieka
        ("kev_full_port_scan", "172.30.99.10", "awaiting_approval"),
    ]
    # denylista trafiła do narzędzia, a cel jest zawsze ostatnim argumentem po „--”
    sweep = lab.runner.calls[0]
    assert sweep[sweep.index("--exclude") + 1] == "172.30.99.1/32"
    assert all(call[-2] == "--" for call in lab.runner.calls)
    assert not any("1-65535" in call for call in lab.runner.calls)
    assert seeded.scalar(select(func.count()).select_from(Notification)) == 1

    actions = seeded.scalars(select(AuditLog.action)).all()
    for expected in ("scan_started", "scan_action_done", "finding_created", "scan_finished"):
        assert expected in actions
    assert audit_sink.actions.count("scope_allowed") == 4
    assert audit_sink.actions[-1] == "scope_awaiting_approval"


def test_second_run_changes_nothing_and_does_not_repeat_notifications(
    seeded: Session, audit_sink: MemoryAudit, lab: FakeLab
) -> None:
    service = _service(seeded, _guard(audit_sink), lab)
    service.run(trigger="manual", actor="test")
    calls = len(lab.runner.calls)
    run = service.run(trigger="manual", actor="test")
    # hosty znane i świeżo zeskanowane: tylko odkrywanie
    assert len(lab.runner.calls) == calls + 1
    assert run.summary["findings_created"] == 0
    assert run.summary["notifications"] == 0
    assert seeded.scalar(select(func.count()).select_from(Finding)) == 3
    awaiting = [a for a in _actions(seeded) if a[2] == "awaiting_approval"]
    assert len(awaiting) == 1


def test_empty_scope_scans_nothing(seeded: Session, audit_sink: MemoryAudit, lab: FakeLab) -> None:
    run = _service(seeded, _guard(audit_sink, {}), lab).run(trigger="manual", actor="test")
    assert lab.runner.calls == []
    assert run.summary["note"].startswith("Zakres jest pusty")
    assert _actions(seeded) == []


def test_denied_address_reported_by_the_tool_is_ignored(
    seeded: Session, audit_sink: MemoryAudit, lab: FakeLab
) -> None:
    # Narzędzie zwraca adres z denylisty mimo --exclude: nie trafia do inwentarza ani skanu.
    lab.services["172.30.99.1"] = (ServiceInfo(22, "tcp", "ssh", "OpenSSH", "9.6"),)
    scope = {"allow": {"cidrs": [LAB]}, "deny": {"cidrs": ["172.30.99.1/32"]}}
    _service(seeded, _guard(audit_sink, scope), lab).run(trigger="manual", actor="test")
    assert not any(call[-1] == "172.30.99.1" for call in lab.runner.calls)
    assert seeded.scalar(select(Asset).where(Asset.fingerprint == "host:172.30.99.1")) is None


def test_shadow_host_is_recorded_and_scanned_as_new(
    seeded: Session, audit_sink: MemoryAudit, lab: FakeLab
) -> None:
    lab.services["172.30.99.14"] = (
        ServiceInfo(6379, "tcp", "redis", "Redis key-value store", "5.0.7"),
    )
    run = _service(seeded, _guard(audit_sink), lab).run(trigger="manual", actor="test")
    shadow = asset_by_ip(seeded, "172.30.99.14")
    assert shadow.status == "shadow"
    assert run.summary["hosts_new"] == 1
    assert ("new_host_service_scan", "172.30.99.14", "done") in _actions(seeded)
    keys = seeded.scalars(select(Finding.dedup_key).where(Finding.asset_id == shadow.id)).all()
    # Podatność z usługi. Nowy host to stan w inwentarzu (P5: stany hostów), nie finding.
    assert sorted(k.split(":")[0] for k in keys) == ["cve"]
    assert any("CVE-2022-24735" in k for k in keys)


def test_rate_limit_per_target_blocks_and_is_recorded(
    seeded: Session, audit_sink: MemoryAudit, lab: FakeLab
) -> None:
    scope = {**SCOPE, "rate_limits": {"per_target": {"172.30.99.11": 0}}}
    _service(seeded, _guard(audit_sink, scope), lab).run(trigger="manual", actor="test")
    assert ("stale_host_service_rescan", "172.30.99.11", "denied") in _actions(seeded)
    denied = seeded.scalar(select(ScanAction).where(ScanAction.target == "172.30.99.11"))
    assert denied is not None
    assert denied.scope_decision == "scope_rate_limited"
    assert not any(call[-1] == "172.30.99.11" for call in lab.runner.calls)


def test_tool_failure_marks_action_failed_and_run_continues(
    seeded: Session, audit_sink: MemoryAudit, lab: FakeLab
) -> None:
    original = lab.runner._respond

    def flaky(argv: tuple[str, ...]) -> str:
        return "to nie jest XML" if argv[-1] == "172.30.99.11" else original(argv)

    lab.runner._respond = flaky
    run = _service(seeded, _guard(audit_sink), lab).run(trigger="manual", actor="test")
    assert run.status == "done"
    assert ("stale_host_service_rescan", "172.30.99.11", "failed") in _actions(seeded)
    assert run.summary["findings_created"] == 2


def test_human_approval_runs_the_intrusive_scan_and_finds_more(
    seeded: Session, audit_sink: MemoryAudit, lab: FakeLab
) -> None:
    lab.extra_ports["172.30.99.10"] = (
        ServiceInfo(16379, "tcp", "redis", "Redis key-value store", "5.0.7"),
    )
    service = _service(seeded, _guard(audit_sink), lab)
    service.run(trigger="manual", actor="test")
    action = seeded.scalar(select(ScanAction).where(ScanAction.status == "awaiting_approval"))
    assert action is not None

    with pytest.raises(ScanActionError, match="Nie znaleziono"):
        service.approve(action.scan_run_id, approved_by="anna", reason="x")
    service.approve(action.id, approved_by="anna", reason="Okno serwisowe uzgodnione")
    assert (action.status, action.approval_source) == ("done", "human:anna")
    assert any("1-65535" in call for call in lab.runner.calls)
    web = asset_by_ip(seeded, "172.30.99.10")
    assert web.attributes["open_ports"] == [80, 16379]
    assert web.attributes["full_scan_only_ports"] == [16379]
    assert seeded.scalar(select(func.count()).select_from(Finding)) == 4
    assert "scan_action_approved" in seeded.scalars(select(AuditLog.action)).all()
    with pytest.raises(ScanActionError, match="nie czeka"):
        service.approve(action.id, approved_by="anna", reason="x")

    # Późniejszy skan częściowy nie „zamyka” portu znalezionego pełnym skanem.
    web.attributes = {**web.attributes, "last_service_scan": "2020-01-01T00:00:00+00:00"}
    seeded.flush()
    service.run(trigger="manual", actor="test")
    ports = seeded.scalars(select(Software.port).where(Software.asset_id == web.id)).all()
    assert sorted(p for p in ports if p) == [80, 16379]
    assert seeded.scalar(select(func.count()).select_from(Finding)) == 4


def test_rejected_action_never_runs(seeded: Session, audit_sink: MemoryAudit, lab: FakeLab) -> None:
    service = _service(seeded, _guard(audit_sink), lab)
    service.run(trigger="manual", actor="test")
    action = seeded.scalar(select(ScanAction).where(ScanAction.status == "awaiting_approval"))
    assert action is not None
    service.reject(action.id, rejected_by="anna", reason="Poza oknem serwisowym")
    assert (action.status, action.scope_decision) == ("denied", "rejected_by_human")
    assert not any("1-65535" in call for call in lab.runner.calls)
    assert "scan_action_rejected" in seeded.scalars(select(AuditLog.action)).all()


def test_seed_demo_approval_replaces_the_click_inside_the_lab(
    seeded: Session, audit_sink: MemoryAudit, lab: FakeLab
) -> None:
    _service(seeded, _guard(audit_sink, demo_mode=True), lab).run(trigger="seed_demo", actor="t")
    action = seeded.scalar(select(ScanAction).where(ScanAction.rule_name == "kev_full_port_scan"))
    assert action is not None
    assert (action.status, action.approval_source) == ("done", "seed_demo")
    allowed = [e for e in audit_sink.events if e.inputs.get("approval_source") == "seed_demo"]
    assert len(allowed) == 1
    assert allowed[0].inputs["approval_expires_at"] is not None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"demo_mode": False},
        {"demo_mode": True, "expires_in_hours": -1},
        # cel w zakresie użytkownika, ale poza siecią demo-lab
        {"demo_mode": True, "lab": "172.30.98.0/24"},
    ],
)
def test_seed_demo_approval_does_not_work_outside_its_conditions(
    seeded: Session, audit_sink: MemoryAudit, lab: FakeLab, kwargs: dict[str, Any]
) -> None:
    _service(seeded, _guard(audit_sink, **kwargs), lab).run(trigger="seed_demo", actor="t")
    action = seeded.scalar(select(ScanAction).where(ScanAction.rule_name == "kev_full_port_scan"))
    assert action is not None
    assert (action.status, action.approval_source) == ("awaiting_approval", None)
    assert not any("1-65535" in call for call in lab.runner.calls)
