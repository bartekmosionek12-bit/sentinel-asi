#!/usr/bin/env bash
# Konta demo w Keycloaku dla czterech ról z briefu (docs/ROLES.md): admin (administrator),
# editor, modifier i viewer. Każde loguje się do konsoli zespołu IT hasłem i TOTP (wspólny
# sekret TOTP kont demo). Tylko DEMO_MODE=true.
#
# Hasła i sekret TOTP bierze z .env (DEMO_ADMIN_PASSWORD, DEMO_ADMIN_TOTP_SECRET,
# DEMO_EDITOR_PASSWORD, DEMO_MODIFIER_PASSWORD, DEMO_VIEWER_PASSWORD); puste wartości generuje
# i zapisuje w data/demo-credentials.env
# (poza Gitem, uprawnienia 600), żeby kolejne uruchomienia używały tych samych.
# Nazwiska są fikcyjne, adresy e-mail w domenie example (RFC 2606).
set -euo pipefail
cd "$(dirname "$0")/.."

if ! grep -Eq '^DEMO_MODE=true[[:space:]]*$' .env; then
  echo "Konta demo tworzymy tylko przy DEMO_MODE=true w pliku .env." >&2
  exit 1
fi

CREDS=data/demo-credentials.env
mkdir -p data
umask 077
touch "$CREDS"

value() {  # value NAZWA: z .env, potem z pliku kont demo
  local name=$1 found
  found=$(grep -E "^${name}=" .env | tail -n1 | cut -d= -f2- || true)
  if [ -z "$found" ]; then
    found=$(grep -E "^${name}=" "$CREDS" | tail -n1 | cut -d= -f2- || true)
  fi
  printf '%s' "$found"
}

random() { python3 -c "import secrets; print(secrets.token_urlsafe($1))"; }

ADMIN_PASSWORD=$(value DEMO_ADMIN_PASSWORD); ADMIN_PASSWORD=${ADMIN_PASSWORD:-$(random 18)}
TOTP_SECRET=$(value DEMO_ADMIN_TOTP_SECRET); TOTP_SECRET=${TOTP_SECRET:-$(random 15)}
EDITOR_PASSWORD=$(value DEMO_EDITOR_PASSWORD); EDITOR_PASSWORD=${EDITOR_PASSWORD:-$(random 18)}
MODIFIER_PASSWORD=$(value DEMO_MODIFIER_PASSWORD); MODIFIER_PASSWORD=${MODIFIER_PASSWORD:-$(random 18)}
VIEWER_PASSWORD=$(value DEMO_VIEWER_PASSWORD); VIEWER_PASSWORD=${VIEWER_PASSWORD:-$(random 18)}

# Aplikacje TOTP przyjmują sekret w Base32; Keycloak przechowuje jego surowe bajty.
TOTP_BASE32=$(python3 -c "import base64,sys; print(base64.b32encode(sys.argv[1].encode()).decode().rstrip('='))" "$TOTP_SECRET")

cat > "$CREDS" <<CREDS
# Konta demo (DEMO_MODE). Plik poza Gitem; usuń go, żeby wygenerować nowe hasła.
DEMO_ADMIN_PASSWORD=${ADMIN_PASSWORD}
DEMO_ADMIN_TOTP_SECRET=${TOTP_SECRET}
DEMO_ADMIN_TOTP_BASE32=${TOTP_BASE32}
DEMO_EDITOR_PASSWORD=${EDITOR_PASSWORD}
DEMO_MODIFIER_PASSWORD=${MODIFIER_PASSWORD}
DEMO_VIEWER_PASSWORD=${VIEWER_PASSWORD}
CREDS

USERS=$(ADMIN_PASSWORD="$ADMIN_PASSWORD" TOTP_SECRET="$TOTP_SECRET" \
  EDITOR_PASSWORD="$EDITOR_PASSWORD" MODIFIER_PASSWORD="$MODIFIER_PASSWORD" \
  VIEWER_PASSWORD="$VIEWER_PASSWORD" python3 - <<'PY'
import json, os

def user(name, first, last, role, password, totp=None):
    credentials = [{"type": "password", "value": password, "temporary": False}]
    if totp:
        credentials.append({
            "type": "otp",
            "userLabel": "demo",
            "secretData": json.dumps({"value": totp}),
            "credentialData": json.dumps(
                {"subType": "totp", "digits": 6, "period": 30, "algorithm": "HmacSHA1", "counter": 0}
            ),
        })
    return {
        "username": name, "firstName": first, "lastName": last,
        "email": f"{name}@demo.sentinel.example", "emailVerified": True, "enabled": True,
        "realmRoles": [role], "credentials": credentials,
        "attributes": {"demo": ["true"]},
    }

print(json.dumps({"ifResourceExists": "OVERWRITE", "users": [
    user("admin", "Anna", "Demonstracyjna", "administrator", os.environ["ADMIN_PASSWORD"], os.environ["TOTP_SECRET"]),
    user("editor", "Edward", "Demonstracyjny", "editor", os.environ["EDITOR_PASSWORD"], os.environ["TOTP_SECRET"]),
    user("modifier", "Monika", "Demonstracyjna", "modifier", os.environ["MODIFIER_PASSWORD"], os.environ["TOTP_SECRET"]),
    user("viewer", "Wiktor", "Demonstracyjny", "viewer", os.environ["VIEWER_PASSWORD"], os.environ["TOTP_SECRET"]),
]}))
PY
)

# kcadm.sh działa w kontenerze Keycloaka; konsola administracyjna nie jest wystawiona na zewnątrz.
# Tuż po starcie Keycloak bywa jeszcze niegotowy (503), stąd kilka prób.
for attempt in 1 2 3 4 5 6; do
  if docker compose exec -T keycloak sh -c '/opt/keycloak/bin/kcadm.sh config credentials \
      --server http://localhost:8080/auth --realm master \
      --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD"' >/dev/null 2>&1 \
    && printf '%s' "$USERS" | docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh \
      create partialImport -r sentinel -s ifResourceExists=OVERWRITE -f - >/dev/null; then
    break
  fi
  [ "$attempt" = 6 ] && { echo "Keycloak nie przyjął kont (sprawdź: docker compose logs keycloak)" >&2; exit 1; }
  sleep 10
done

echo "Konta demo gotowe (hasła w ${CREDS}):"
echo "  admin     Administracja (wszystko, edytor ról)"
echo "  editor    Dodawanie, usuwanie, modyfikacja (skany, zatwierdzanie planów agenta i L2+)"
echo "  modifier  Modyfikacja i odczyt"
echo "  viewer    Odczyt"
echo "  Każde konto: hasło + TOTP (wspólny sekret kont demo, Base32: ${TOTP_BASE32})"
echo "  TOTP do aplikacji: otpauth://totp/Sentinel%20ASI:demo?secret=${TOTP_BASE32}&issuer=Sentinel%20ASI"
