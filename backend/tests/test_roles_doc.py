"""docs/ROLES.md zgadza się z kodem: macierz rola × endpoint × akcja jest generowana."""

from __future__ import annotations

from app.iam.deps import get_role_catalog
from app.iam.roles_doc import DOC, current_section, render
from app.main import create_app


def test_roles_doc_matrix_is_up_to_date() -> None:
    expected = render(get_role_catalog(), create_app())
    actual = current_section(DOC.read_text(encoding="utf-8"))
    assert actual == expected, (
        "docs/ROLES.md jest nieaktualny: uruchom w backend/ "
        "RULES_DIR=../rules python -m app.iam.roles_doc --write"
    )


def test_roles_doc_has_no_undeclared_endpoint() -> None:
    assert "BRAK" not in current_section(DOC.read_text(encoding="utf-8"))
