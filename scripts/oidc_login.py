#!/usr/bin/env python3
"""Logowanie do Keycloaka tak jak przeglądarka: kod autoryzacji z PKCE, hasło i TOTP.

Używane przez scripts/check_demo.py (e2e w CI), żeby sprawdzić prawdziwy przepływ logowania
z MFA, a nie obejście. Tylko biblioteka standardowa.

    python3 scripts/oidc_login.py http://localhost:8080 sentinel-admin admin HASŁO SEKRET_TOTP
wypisuje token dostępu.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import http.cookiejar
import json
import re
import secrets
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REALM = "sentinel"


class LoginError(RuntimeError):
    pass


def totp(secret: str, *, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    """Kod TOTP (RFC 6238). Keycloak używa bajtów sekretu w postaci, w jakiej go zapisano."""
    counter = int((at if at is not None else time.time()) // step)
    digest = hmac.new(secret.encode(), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 10**digits
    return str(code).zfill(digits)


class _LocalCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    """Ciasteczka Keycloaka mają flagę Secure. Przeglądarki wysyłają je do http://localhost
    (bezpieczny kontekst), więc skrypt robi to samo; poza localhost wymagany jest HTTPS."""

    def return_ok_secure(self, cookie: http.cookiejar.Cookie, request: object) -> bool:
        return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
        return None


def _form_action(page: str) -> str:
    match = re.search(r'<form[^>]*\baction="([^"]+)"', page)
    if not match:
        raise LoginError("Keycloak nie zwrócił formularza logowania")
    return html.unescape(match.group(1))


def login(base: str, client_id: str, username: str, password: str, totp_secret: str = "") -> str:
    """Zwraca token dostępu. `base` to adres interfejsu (nginx z /auth i /api)."""
    base = base.rstrip("/")
    redirect_uri = f"{base}/admin/"
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    jar = http.cookiejar.CookieJar(policy=_LocalCookiePolicy())
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar), _NoRedirect()
    )
    oidc = f"{base}/auth/realms/{REALM}/protocol/openid-connect"
    query = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid",
            "state": secrets.token_hex(8),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    with opener.open(f"{oidc}/auth?{query}", timeout=15) as response:  # noqa: S310
        page = response.read().decode()

    def submit(page: str, fields: dict[str, str]) -> tuple[str | None, str]:
        data = urllib.parse.urlencode(fields).encode()
        try:
            with opener.open(_form_action(page), data=data, timeout=15) as response:  # noqa: S310
                return None, response.read().decode()
        except urllib.error.HTTPError as error:
            if error.code in (301, 302, 303):
                return error.headers["Location"], ""
            raise

    location, page = submit(page, {"username": username, "password": password})
    if location is None and 'name="otp"' in page:
        if not totp_secret:
            raise LoginError("Keycloak wymaga kodu TOTP, a nie podano sekretu")
        code = totp(totp_secret)
        location, page = submit(page, {"otp": code})
        if location is None and 'name="otp"' in page:
            # Keycloak nie przyjmuje drugi raz tego samego kodu (ochrona przed powtórzeniem),
            # a skrypty demo logują to samo konto kilka razy w ciągu 30 s. Czekamy na
            # następny kod i próbujemy raz jeszcze.
            while totp(totp_secret) == code:
                time.sleep(1)
            location, page = submit(page, {"otp": totp(totp_secret)})
    if location is None:
        error = re.search(r'id="input-error[^"]*"[^>]*>\s*([^<]+)', page)
        raise LoginError(f"Logowanie odrzucone: {error.group(1).strip() if error else 'brak kodu'}")
    params = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    if "code" not in params:
        raise LoginError(f"Brak kodu autoryzacji w przekierowaniu: {location}")
    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": params["code"][0],
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        }
    ).encode()
    with opener.open(f"{oidc}/token", data=body, timeout=15) as response:  # noqa: S310
        token: str = json.load(response)["access_token"]
    return token


def main() -> int:
    if len(sys.argv) < 5:
        sys.stderr.write(__doc__ or "")
        return 2
    base, client_id, username, password = sys.argv[1:5]
    secret = sys.argv[5] if len(sys.argv) > 5 else ""
    print(login(base, client_id, username, password, secret))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
