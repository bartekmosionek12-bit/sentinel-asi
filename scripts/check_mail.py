#!/usr/bin/env python3
"""E-mail z raportem zero-day w Mailpit (CI, demo-lab).

Użycie (po inject_kev.sh, z SMTP_HOST=mailpit w .env):
    python3 scripts/check_mail.py http://localhost:8025

Sprawdza, że raport zero-day dotarł e-mailem jako wersja „W skrócie”: z PDF w załączniku i bez
adresów z demo-lab w treści. Tylko biblioteka standardowa; kod wyjścia 1 przy niespełnionym
warunku.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_demo import report

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(base: str, path: str) -> dict:  # type: ignore[type-arg]
    with OPENER.open(f"{base}/api/v1{path}", timeout=10) as response:
        return json.loads(response.read())  # type: ignore[no-any-return]


def main() -> int:
    base = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8025"
    message: dict | None = None  # type: ignore[type-arg]
    deadline = time.monotonic() + 30
    while message is None and time.monotonic() < deadline:
        listed = get(base, "/messages").get("messages") or []
        found = next((m for m in listed if "Zero-day" in m.get("Subject", "")), None)
        if found is not None:
            message = get(base, f"/message/{found['ID']}")
        else:
            time.sleep(1)
    text = (message or {}).get("Text", "")
    attachments = (message or {}).get("Attachments") or []
    checks = {
        "e-mail z raportem zero-day dotarł do Mailpit": message is not None,
        "PDF raportu w załączniku": any(
            a.get("ContentType") == "application/pdf" for a in attachments
        ),
        "treść ma warstwę „W skrócie”": "W skrócie" in text,
        "treść bez adresów demo-lab (wersja „W skrócie”)": message is not None
        and "172.30.99." not in text,
    }
    return report(checks)


if __name__ == "__main__":
    raise SystemExit(main())
