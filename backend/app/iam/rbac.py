"""Model ról i uprawnień z `rules/roles.yaml`.

Rola to zestaw uprawnień, a uprawnienie oznaczone `mfa: true` działa wyłącznie z tokenem
po uwierzytelnieniu wieloskładnikowym. Wszystko, czego nie ma w pliku, jest zabronione.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

PrincipalKind = str  # "human", "agent", "system"
KINDS = ("human", "agent", "system")
# Uprawnień z tej listy nie da się włożyć do roli własnej: zarządzanie tożsamością zostaje
# wyłącznie przy roli `administrator` z pliku (brak eskalacji przez edytor ról).
RESERVED_PERMISSIONS = frozenset({"iam:manage"})
# Role z pliku, które administrator może nadać w konsoli. `administrator` nadaje tylko Keycloak.
GRANTABLE_BUILTIN_ROLES = ("editor", "modifier", "viewer")


class RbacConfigError(ValueError):
    """Błąd w pliku ról: lepiej nie wystartować, niż nadać za dużo uprawnień."""


@dataclass(frozen=True)
class Permission:
    name: str
    description: str
    mfa: bool = False


@dataclass(frozen=True)
class Role:
    name: str
    description: str
    kind: PrincipalKind
    permissions: frozenset[str]


@dataclass(frozen=True)
class RoleCatalog:
    version: int
    permissions: dict[str, Permission]
    roles: dict[str, Role]
    _mfa: frozenset[str] = field(default=frozenset(), repr=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RoleCatalog:
        raw_permissions = data.get("permissions") or {}
        if not isinstance(raw_permissions, dict) or not raw_permissions:
            raise RbacConfigError("Brak listy uprawnień")
        permissions: dict[str, Permission] = {}
        for name, spec in raw_permissions.items():
            spec = spec or {}
            permissions[str(name)] = Permission(
                name=str(name),
                description=str(spec.get("description", "")),
                mfa=bool(spec.get("mfa", False)),
            )
        roles: dict[str, Role] = {}
        for name, spec in (data.get("roles") or {}).items():
            kind = str(spec.get("kind", "human"))
            if kind not in KINDS:
                raise RbacConfigError(f"Rola {name}: nieznany rodzaj {kind}")
            raw = spec.get("permissions", [])
            if raw == "*":
                granted = frozenset(permissions)
            else:
                if not isinstance(raw, list):
                    raise RbacConfigError(f"Rola {name}: uprawnienia muszą być listą albo '*'")
                unknown = sorted(set(map(str, raw)) - set(permissions))
                if unknown:
                    raise RbacConfigError(f"Rola {name}: nieznane uprawnienia {unknown}")
                granted = frozenset(map(str, raw))
            roles[str(name)] = Role(str(name), str(spec.get("description", "")), kind, granted)
        if not roles:
            raise RbacConfigError("Brak ról")
        mfa = frozenset(p.name for p in permissions.values() if p.mfa)
        return cls(int(data.get("version", 1)), permissions, roles, mfa)

    @classmethod
    def from_file(cls, path: Path) -> RoleCatalog:
        with path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return cls.from_dict(data)

    def resolve(self, role_names: frozenset[str], *, mfa: bool) -> frozenset[str]:
        """Uprawnienia dla zestawu ról. Nieznane role nie dają niczego (deny-by-default)."""
        granted: set[str] = set()
        for name in role_names:
            role = self.roles.get(name)
            if role is not None:
                granted |= role.permissions
        if not mfa:
            granted -= self._mfa
        return frozenset(granted)

    def with_custom(self, custom: Iterable[tuple[str, str, Iterable[str]]]) -> RoleCatalog:
        """Katalog z rolami własnymi (nazwa, opis, uprawnienia) dołożonymi do ról z pliku.

        Rola własna nie nadpisuje roli z pliku, jest zawsze rodzaju `human`, a nieznane i
        zastrzeżone uprawnienia są pomijane (deny-by-default także przy złym wierszu w bazie).
        """
        roles = dict(self.roles)
        for name, description, permissions in custom:
            if name in self.roles:
                continue
            granted = frozenset(
                p for p in permissions if p in self.permissions and p not in RESERVED_PERMISSIONS
            )
            roles[name] = Role(name, description, "human", granted)
        return replace(self, roles=roles)

    def requires_mfa(self, permission: str) -> bool:
        return permission in self._mfa

    def kind_of(self, role_names: frozenset[str]) -> PrincipalKind:
        """Rodzaj tożsamości: agent i system mają pierwszeństwo przed człowiekiem."""
        kinds = {self.roles[r].kind for r in role_names if r in self.roles}
        for kind in ("agent", "system"):
            if kind in kinds:
                return kind
        return "human"
