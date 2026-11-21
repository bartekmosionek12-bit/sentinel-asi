#!/usr/bin/env python3
"""Sprawdza przez API, czy seed_demo przeszedł całą ścieżkę krytyczną na demo-lab.

Użycie: python3 scripts/check_demo.py http://localhost:8080
        python3 scripts/check_demo.py http://localhost:8080 --zero-day   (po inject_kev.sh)
Loguje się jak przeglądarka (Keycloak, PKCE, hasło i TOTP) kontami demo z pliku
data/demo-credentials.env, który tworzy scripts/seed_demo.sh. Tylko biblioteka standardowa.
Kod wyjścia 1, gdy którykolwiek warunek nie jest spełniony.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oidc_login import login  # noqa: E402

CREDENTIALS = Path(__file__).resolve().parent.parent / "data" / "demo-credentials.env"
TOKEN = {"value": ""}


def credentials() -> dict[str, str]:
    values = {}
    for line in CREDENTIALS.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def call(base: str, path: str, token: str, body: object | None = None) -> tuple[int, object]:
    headers = {"Authorization": f"Bearer {token}"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(  # noqa: S310
        f"{base}/api{path}", data=data, headers=headers, method="POST" if data else "GET"
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=15) as response:
            body = response.read()
            return response.status, json.loads(body) if body else None
    except urllib.error.HTTPError as error:
        return error.code, None


def get(base: str, path: str) -> object:
    status, body = call(base, path, TOKEN["value"])
    if status != 200:
        raise SystemExit(f"BŁĄD GET /api{path}: HTTP {status}")
    return body


def assistant_checks(base: str, editor: str) -> dict[str, bool]:
    """Sentek w konsoli zespołu IT: odpowiada z danych, prośbę o skan zamienia w propozycję."""
    _, top = call(base, "/assistant", editor, {"question": "Co jest teraz najgroźniejsze?"})
    _, refusal = call(base, "/assistant", editor, {"question": "Wyłącz serwer web-01"})
    _, scan = call(base, "/assistant", editor, {"question": "zeskanuj web-01"})
    top_text = " ".join(top.get("text", [])) if isinstance(top, dict) else ""
    action = scan.get("action") if isinstance(scan, dict) else None
    return {
        "Sentek odpowiada z danych (web-01 i CVE na liście)": isinstance(top, dict)
        and top.get("intent") == "top_risks"
        and "web-01" in top_text,
        "Sentek odmawia zmiany ustawień": isinstance(refusal, dict)
        and refusal.get("intent") == "out_of_scope"
        and refusal.get("action") is None,
        "Sentek tylko proponuje zadanie agenta zamiast skanować": isinstance(action, dict)
        and action.get("kind") == "agent_task",
    }


def report_checks(base: str, viewer: str, *, zero_day: bool) -> dict[str, bool]:
    """Skrzynka raportów (rola Odczyt): raport po seed_demo albo raport zero-day po inject_kev."""
    inbox_status, inbox = call(base, "/inbox", viewer)
    items = inbox["items"] if isinstance(inbox, dict) else []  # type: ignore[index]
    kind = "zero_day" if zero_day else "assessment"
    report = next((r for r in items if r["kind"] == kind), None)
    detail: object = None
    if report is not None:
        _, detail = call(base, f"/reports/{report['id']}", viewer)
    summary = detail.get("summary", []) if isinstance(detail, dict) else []
    label = "zero-day" if zero_day else "po seed_demo"
    checks = {
        f"raport {label} w skrzynce, nieprzeczytany": inbox_status == 200
        and report is not None
        and report["read"] is False,
        f"raport {label}: czerwone światło policzone przez kod": report is not None
        and report["light"] == "red",
        f"raport {label}: pięć odpowiedzi „W skrócie”": len(summary) == 5
        and all(item["answer"] for item in summary),
    }
    if zero_day:
        checks["raport zero-day dotyczy CVE-2021-23017 na proxy-01"] = (
            isinstance(detail, dict)
            and detail.get("title") == "Zero-day: CVE-2021-23017"
            and any(row.get("asset") == "proxy-01" for row in detail.get("technical", []))
        )
    return checks


def main() -> int:
    base = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8080"
    demo = credentials()
    totp = demo["DEMO_ADMIN_TOTP_SECRET"]  # wspólny sekret TOTP kont demo

    def as_role(name: str) -> str:
        return login(base, "sentinel-admin", name, demo[f"DEMO_{name.upper()}_PASSWORD"], totp)

    if "--zero-day" in sys.argv:
        return report(report_checks(base, as_role("viewer"), zero_day=True))
    TOKEN["value"] = login(base, "sentinel-admin", "admin", demo["DEMO_ADMIN_PASSWORD"], totp)
    me = get(base, "/me")
    # Cztery role z briefu: każda wchodzi do konsoli z TOTP, a API pilnuje uprawnień.
    viewer = as_role("viewer")
    modifier = as_role("modifier")
    editor = as_role("editor")
    viewer_console, _ = call(base, "/console/admin", viewer)
    viewer_scan_status, _ = call(base, "/scans", viewer, {})
    modifier_audit_status, _ = call(base, "/audit-log", modifier)
    editor_actions_status, _ = call(base, "/scan-actions", editor)
    denied = get(base, "/audit-log?action=access_denied&limit=50")
    findings = get(base, "/findings?status=active")["items"]  # type: ignore[index]
    stats = get(base, "/stats")
    assets = {a["name"]: a for a in get(base, "/assets?limit=500")["items"]}  # type: ignore[index]
    actions = get(base, "/scan-actions")
    audit = get(base, "/audit-log/verify")
    # Findingi bez CVE (np. sygnały bez podatności) pomijamy.
    by_cve = {
        (f["vulnerability"]["cve_id"], f["asset"]["name"]): f
        for f in findings
        if f.get("vulnerability") and f.get("asset")
    }
    web = by_cve.get(("CVE-2021-41773", "web-01"), {})
    explanation = get(base, f"/findings/{web['id']}/explanation?audience=technical") if web else {}
    llm = get(base, "/llm/status")
    agent = get(base, "/agent/status")
    last_test = agent.get("last_test") or {} if isinstance(agent, dict) else {}
    explained = (
        isinstance(explanation, dict)
        and isinstance(llm, dict)
        and explanation.get("cve_id") == "CVE-2021-41773"
        and "Co to jest:" in explanation.get("text", "")
        and explanation.get("asset_context", "").startswith("Dotyczy: web-01")
        and (explanation.get("source") == "template" or bool(llm.get("available")))
    )

    checks = {
        "administrator zalogowany przez Keycloak z TOTP (MFA w tokenie)": isinstance(me, dict)
        and me.get("mfa") is True
        and "administrator" in me.get("roles", []),
        "Odczyt (viewer) wchodzi do konsoli z TOTP": viewer_console == 204,
        "Odczyt nie uruchamia skanu (403)": viewer_scan_status == 403,
        "odmowa dla roli Odczyt zapisana w dzienniku audytu": any(
            e["actor"] == "user:viewer" and e["inputs"].get("permission") == "scan:run"
            for e in denied["items"]  # type: ignore[index]
        ),
        "Modyfikacja nie czyta dziennika audytu (403)": modifier_audit_status == 403,
        "editor widzi akcje skanujące do zatwierdzenia": editor_actions_status == 200,
        "CVE-2021-41773 na web-01 jest krytyczne": by_cve.get(("CVE-2021-41773", "web-01"), {}).get(
            "risk_level"
        )
        == "krytyczny",
        "najwyższe ryzyko jest pierwsze na liście": bool(findings)
        and findings[0]["risk_score"] == max(f["risk_score"] for f in findings),
        "nginx dopasowany przez alias (CVE-2021-23017 na proxy-01)": ("CVE-2021-23017", "proxy-01")
        in by_cve,
        "pakiet z Debiana czeka w kolejce weryfikacji, bez findingów": stats["review_queue"] == 1  # type: ignore[index]
        and not any(asset == "legacy-01" for _, asset in by_cve),
        "host spoza inwentarza oznaczony jako nowy (shadow)": assets.get("172.30.99.14", {}).get(
            "status"
        )
        == "shadow",
        "zasób, który nie odpowiada, oznaczony jako missing": assets.get("old-db-01", {}).get(
            "status"
        )
        == "missing",
        "skan L2 wykonany ze zgodą seed_demo": any(
            a["intrusiveness"] == 2
            and a["status"] == "done"
            and a["approval_source"] == "seed_demo"
            for a in actions  # type: ignore[union-attr]
        ),
        "żadna akcja nie dotknęła adresu spoza demo-lab": all(
            a["target"].startswith("172.30.99.")
            for a in actions  # type: ignore[union-attr]
        ),
        "feedy wczytane w trybie offline": all(
            f["status"] == "ok" and f["mode"] == "offline"
            for f in stats["feeds"]  # type: ignore[index]
        ),
        "powiadomienie o KEV na zasobie z internetu": stats["notifications_today"] >= 1,  # type: ignore[index]
        "wyjaśnienie dostępne także bez modelu (szablon z faktami z bazy)": explained,
        "agent aktywny dopiero po zaliczonym i podpisanym teście (moduł 19)": isinstance(
            agent, dict
        )
        and bool(agent.get("capability"))
        and last_test.get("passed") is True
        and last_test.get("signature_valid") is True,
        "łańcuch dziennika audytu jest spójny": audit["ok"] is True,  # type: ignore[index]
        **report_checks(base, viewer, zero_day=False),
        **assistant_checks(base, editor),
    }
    return report(checks)


def report(checks: dict[str, bool]) -> int:
    failed = [name for name, ok in checks.items() if not ok]
    for name, ok in checks.items():
        sys.stdout.write(f"{'OK  ' if ok else 'BŁĄD'} {name}\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
