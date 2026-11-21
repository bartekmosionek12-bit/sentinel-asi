# Role i uprawnienia

Brief CBI AGH, pkt 12–13: „tworzenie i obsługa różnych ról” oraz cztery role (odczyt;
modyfikacja i odczyt; dodawanie, usuwanie i modyfikacja; administracja). Ten dokument opisuje,
jak to działa w Sentinel ASI, i zawiera macierz rola × endpoint × akcja wyliczaną z kodu.

## Zasady

- **Deny-by-default.** Każdy endpoint deklaruje uprawnienie (`require()`), dostęp dla
  zalogowanego (`authenticated()`) albo jawnie publiczny (`public_endpoint()`). Trasa bez
  deklaracji nie przejdzie testu `test_every_route_declares_access`.
- **Źródło prawdy:** `rules/roles.yaml`. Keycloak przechowuje tylko przynależność do ról,
  uprawnienia wylicza backend przy każdym żądaniu.
- **MFA.** Konsola zespołu IT (`/admin`) wymaga logowania z TOTP od wszystkich ról. Uprawnienia
  oznaczone „MFA” działają tylko z tokenem po drugim składniku; bez niego zostaje odczyt.
- **Audyt.** Każda odmowa to wpis `access_denied` (kto, jakie uprawnienie, który endpoint).
  Zmiany ról i nadania to wpisy `role_created`, `role_updated`, `role_deleted`, `role_granted`,
  `role_revoked`.

## Role

| Rola w kodzie | Nazwa w UI (brief) | Co może |
|---|---|---|
| `administrator` | Administracja | wszystko, w tym użytkownicy i role (edytor ról), zakres skanowania, zdolności agenta, integracje, dziennik audytu |
| `editor` | Dodawanie, usuwanie, modyfikacja | dodawanie i import zasobów, uruchamianie skanów, zatwierdzanie akcji L2 i L3 oraz planów agenta, zadania dla agenta, kill switch, raporty, decyzje w kolejce weryfikacji |
| `modifier` | Modyfikacja i odczyt | odczyt wszystkiego (poza dziennikiem audytu) i zmiana istniejących danych: statusy zagrożeń, decyzje w kolejce weryfikacji; bez dodawania, usuwania i uruchamiania |
| `viewer` | Odczyt | odczyt danych, dashboard, raporty, eksport JSON/CSV/PDF, pytania do Sentka |
| `agent` | tożsamość techniczna | brak uprawnień do API; działa wyłącznie przez serwer MCP ze zdolnościami nadanymi przez administratora |
| `system` | tożsamość techniczna | brak uprawnień do API (deterministyczny pipeline) |

Decyzja z 21.11.2026: akcje L2 i L3 oraz plany agenta zatwierdza `administrator` albo `editor`,
zawsze człowiek i zawsze z wpisem w audycie. Kill switch ma też `editor`: zatrzymanie skanów
jest bezpieczne, więc może je zrobić każdy, kto może je uruchomić.

Granice, które pilnuje test `test_matrix_covers_key_expectations`:
`viewer` ⊂ `modifier` ⊂ `editor` ⊂ `administrator`, a `iam:manage`, `scope:manage`,
`agent:configure`, `agent_test:override`, `integrations:manage`, `llm:external:manage`,
`audit:read` i `audit:export` ma wyłącznie `administrator`.

## Edytor ról

Administrator w konsoli (Administracja → Role i użytkownicy) może:

- utworzyć, zmienić i usunąć **rolę własną** złożoną z uprawnień z listy poniżej
  (`PUT`/`DELETE /api/iam/roles/{nazwa}`); rola własna nie może zawierać `iam:manage`
  (brak eskalacji przez edytor) i nie nadpisze roli z pliku,
- **nadać i odebrać** użytkownikowi rolę własną albo `editor`, `modifier`, `viewer`
  (`POST`/`DELETE /api/iam/users/{id}/roles`). Rolę `administrator` nadaje wyłącznie Keycloak,
  a role nadaje się tylko ludziom (agent ma zdolności, nie role).

Konto pojawia się na liście po pierwszym logowaniu. Nadanie działa od następnego żądania.
Usunięcie roli własnej odbiera ją wszystkim kontom (lista kont w audycie).

## Sprawdzenia w treści endpointów

Część decyzji zależy od danych, więc poza uprawnieniem z tabeli endpoint sprawdza jeszcze:

| Endpoint | Dodatkowe uprawnienie | Kiedy |
|---|---|---|
| `POST /api/scan-actions/{id}/approve` | `scan:approve:l2` albo `scan:approve:l3` | według poziomu zatwierdzanej akcji |
| `POST /api/agent/tasks/{id}/approve` | `scan:approve:l2` albo `scan:approve:l3` | według najwyższego poziomu kroku w planie |
| `PATCH /api/findings/{id}` | `risk:accept` | zmiana statusu na „ryzyko zaakceptowane” |
| `POST /api/explanations` | `llm:external:use` | gdy wyjaśnienie ma iść do zewnętrznego modelu |

## Macierz rola × endpoint × akcja

„✓” = rola ma dostęp (przy logowaniu z MFA), „·” = 403 z wpisem w audycie. Tabelę generuje
`RULES_DIR=../rules python -m app.iam.roles_doc --write` (z katalogu `backend`); test `test_roles_doc.py` sprawdza, że jest aktualna, a
`test_role_endpoint_matrix` wywołuje każdy endpoint każdą rolą i porównuje wynik z tą macierzą.

<!-- roles_doc:begin (generowane: python -m app.iam.roles_doc --write) -->

### Uprawnienia ról

| Uprawnienie | MFA | administrator | editor | modifier | viewer | Opis |
|---|---|---|---|---|---|---|
| `agent:configure` | tak | ✓ | · | · | · | Nadawanie zdolności agentowi |
| `agent:kill` | tak | ✓ | ✓ | · | · | Kill switch: zatrzymanie agenta i wszystkich skanów |
| `agent:read` |  | ✓ | ✓ | ✓ | ✓ | Odczyt zadań, planów, zdolności i poświadczeń JIT agenta (bez sekretów) |
| `agent:task` | tak | ✓ | ✓ | · | · | Zlecanie zadań agentowi i zatwierdzanie jego planów |
| `agent_test:override` | tak | ✓ | · | · | · | Wymuszenie konfiguracji agenta mimo niezaliczonego testu (z uzasadnieniem) |
| `agent_test:read` |  | ✓ | ✓ | ✓ | ✓ | Odczyt wyników testu bezpieczeństwa agenta |
| `agent_test:run` | tak | ✓ | ✓ | · | · | Uruchomienie testu bezpieczeństwa agenta |
| `assistant:use` |  | ✓ | ✓ | ✓ | ✓ | Pytania do asystenta Sentek (odpowiedzi z danych, w granicach własnych uprawnień) |
| `audit:export` |  | ✓ | · | · | · | Eksport dziennika audytu i dowodów |
| `audit:read` |  | ✓ | · | · | · | Odczyt dziennika audytu |
| `console:admin` | tak | ✓ | ✓ | ✓ | ✓ | Wejście do konsoli zespołu IT (/admin); odmowa trafia do audytu |
| `explanations:generate` | tak | ✓ | ✓ | · | · | Zlecanie wyjaśnień modelowi lokalnemu |
| `feeds:sync` | tak | ✓ | ✓ | · | · | Ręczna synchronizacja feedów |
| `findings:read` |  | ✓ | ✓ | ✓ | ✓ | Odczyt zagrożeń, feedu i wyjaśnień |
| `findings:update` | tak | ✓ | ✓ | ✓ | · | Zmiana statusu zagrożenia |
| `iam:manage` | tak | ✓ | · | · | · | Użytkownicy, role i uprawnienia (edytor ról) |
| `iam:read` |  | ✓ | · | · | · | Odczyt użytkowników, ról i uprawnień |
| `integrations:manage` | tak | ✓ | · | · | · | Konfiguracja integracji (DefectDojo, kanały powiadomień) |
| `inventory:read` |  | ✓ | ✓ | ✓ | ✓ | Odczyt inwentarza zasobów |
| `inventory:write` | tak | ✓ | ✓ | · | · | Dodawanie i import zasobów |
| `llm:external:manage` | tak | ✓ | · | · | · | Włączanie zewnętrznego modelu |
| `llm:external:use` | tak | ✓ | ✓ | · | · | Użycie zewnętrznego modelu (dane zanonimizowane) |
| `notifications:read` |  | ✓ | ✓ | ✓ | ✓ | Odczyt powiadomień |
| `reports:export` |  | ✓ | ✓ | ✓ | ✓ | Eksport raportów (PDF, CSV, JSON) |
| `reports:generate` | tak | ✓ | ✓ | · | · | Tworzenie raportów i zlecanie warstwy „W skrócie” modelowi |
| `reports:read` |  | ✓ | ✓ | ✓ | ✓ | Odczyt raportów |
| `review:decide` | tak | ✓ | ✓ | ✓ | · | Decyzje w kolejce weryfikacji |
| `review:read` |  | ✓ | ✓ | ✓ | ✓ | Odczyt kolejki weryfikacji dopasowań |
| `risk:accept` | tak | ✓ | ✓ | · | · | Formalna akceptacja ryzyka (status „ryzyko zaakceptowane”) |
| `scan:approve:l2` | tak | ✓ | ✓ | · | · | Zatwierdzanie akcji L2 (także w planach agenta) |
| `scan:approve:l3` | tak | ✓ | ✓ | · | · | Zatwierdzanie akcji L3 (także w planach agenta) |
| `scan:read` |  | ✓ | ✓ | ✓ | ✓ | Odczyt skanów i akcji skanujących |
| `scan:run` | tak | ✓ | ✓ | · | · | Uruchamianie skanów L1 |
| `scope:manage` | tak | ✓ | · | · | · | Zmiana zakresu skanowania (allowlista, denylista, limity) |
| `scope:read` |  | ✓ | ✓ | ✓ | ✓ | Odczyt zakresu skanowania |
| `secrets:redacted:view` |  | ✓ | ✓ | ✓ | ✓ | Pełne dane techniczne (adresy, banery, dowody) poza sekretami |

### Endpointy

| Metoda | Ścieżka | Wymaga | administrator | editor | modifier | viewer |
|---|---|---|---|---|---|---|
| GET | `/api/agent/capabilities` | `agent:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/agent/capabilities` | `agent:configure` | ✓ | · | · | · |
| GET | `/api/agent/configs` | `agent:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/agent/configs/{config_id}/force` | `agent_test:override` | ✓ | · | · | · |
| POST | `/api/agent/kill` | `agent:kill` | ✓ | ✓ | · | · |
| GET | `/api/agent/leases` | `agent:read` | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/agent/status` | `agent:read` | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/agent/tasks` | `agent:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/agent/tasks` | `agent:task` | ✓ | ✓ | · | · |
| GET | `/api/agent/tasks/{task_id}` | `agent:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/agent/tasks/{task_id}/approve` | `agent:task` | ✓ | ✓ | · | · |
| POST | `/api/agent/tasks/{task_id}/reject` | `agent:task` | ✓ | ✓ | · | · |
| GET | `/api/agent/tests` | `agent_test:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/agent/tests` | `agent_test:run` | ✓ | ✓ | · | · |
| GET | `/api/agent/tests/{run_id}` | `agent_test:read` | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/assets` | `inventory:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/assets` | `inventory:write` | ✓ | ✓ | · | · |
| POST | `/api/assets/import` | `inventory:write` | ✓ | ✓ | · | · |
| GET | `/api/assets/{asset_id}` | `inventory:read` | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/assets/{asset_id}/details` | `inventory:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/assistant` | `assistant:use` | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/audit-log` | `audit:read` | ✓ | · | · | · |
| GET | `/api/audit-log/verify` | `audit:read` | ✓ | · | · | · |
| POST | `/api/auth/logout` | zalogowany | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/console/admin` | `console:admin` | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/explanations/jobs/{job_id}/events` | `findings:read` | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/feeds` | `findings:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/feeds/sync` | `feeds:sync` | ✓ | ✓ | · | · |
| GET | `/api/findings` | `findings:read` | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/findings/{finding_id}` | `findings:read` | ✓ | ✓ | ✓ | ✓ |
| PATCH | `/api/findings/{finding_id}` | `findings:update` | ✓ | ✓ | ✓ | · |
| GET | `/api/findings/{finding_id}/explanation` | `findings:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/findings/{finding_id}/explanation` | `explanations:generate` | ✓ | ✓ | · | · |
| GET | `/api/freshness` | `reports:read` | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/glossary` | zalogowany | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/health` | publiczny | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/iam/permissions` | `iam:read` | ✓ | · | · | · |
| GET | `/api/iam/roles` | `iam:read` | ✓ | · | · | · |
| DELETE | `/api/iam/roles/{name}` | `iam:manage` | ✓ | · | · | · |
| PUT | `/api/iam/roles/{name}` | `iam:manage` | ✓ | · | · | · |
| GET | `/api/iam/users` | `iam:read` | ✓ | · | · | · |
| POST | `/api/iam/users/{user_id}/roles` | `iam:manage` | ✓ | · | · | · |
| DELETE | `/api/iam/users/{user_id}/roles/{role}` | `iam:manage` | ✓ | · | · | · |
| GET | `/api/inbox` | `reports:read` | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/llm/status` | `findings:read` | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/me` | zalogowany | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/notifications` | `notifications:read` | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/reports` | `reports:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/reports` | `reports:generate` | ✓ | ✓ | · | · |
| GET | `/api/reports/{report_id}` | `reports:read` | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/reports/{report_id}/pdf` | `reports:export` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/reports/{report_id}/read` | `reports:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/reports/{report_id}/summary` | `reports:generate` | ✓ | ✓ | · | · |
| GET | `/api/review-queue` | `review:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/review-queue/{candidate_id}/decision` | `review:decide` | ✓ | ✓ | ✓ | · |
| GET | `/api/scan-actions` | `scan:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/scan-actions/{action_id}/approve` | `scan:approve:l2` | ✓ | ✓ | · | · |
| POST | `/api/scan-actions/{action_id}/reject` | `scan:approve:l2` | ✓ | ✓ | · | · |
| GET | `/api/scans` | `scan:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/scans` | `scan:run` | ✓ | ✓ | · | · |
| GET | `/api/scope` | `scope:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/scope/check` | `scope:manage` | ✓ | · | · | · |
| GET | `/api/signal-queue` | `review:read` | ✓ | ✓ | ✓ | ✓ |
| POST | `/api/signal-queue/{signal_id}/decision` | `review:decide` | ✓ | ✓ | ✓ | · |
| GET | `/api/stats` | `inventory:read` | ✓ | ✓ | ✓ | ✓ |
| GET | `/api/threat-feed` | `findings:read` | ✓ | ✓ | ✓ | ✓ |

<!-- roles_doc:end -->
