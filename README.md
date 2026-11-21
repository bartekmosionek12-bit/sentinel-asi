# Sentinel ASI

Platforma Attack Surface Intelligence: jeden centralny inwentarz zasobów, do którego
dopasowane są zagrożenia, aktualizacje, wyniki skanów i reguły zgodności. Projekt na
hackathon HackNation, zadanie „Attack Surface Intelligence” (AGH).

**Zasada:** decyzje (co skanować, jak ocenić ryzyko, czy wysłać alert) podejmuje
deterministyczny, testowalny kod. Lokalny model językowy służy wyłącznie do tłumaczenia
wyników na ludzki język.

> **Zmiana kierunku (21.11.2026).** Projekt prowadzimy pod oficjalny brief CBI AGH
> ([docs/BRIEF.md](docs/BRIEF.md)): skaner discovery dużej infrastruktury z fingerprintingiem
> HTTP, sygnaturami, porównaniem przebiegów, czterema rolami, szyfrowaniem w spoczynku i
> DefectDojo. Stan wymagań: [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md); plan etapów P0–P12:
> [docs/ROADMAP.md](docs/ROADMAP.md); co usuwamy i co zostaje:
> [docs/ARCHITECTURE.md, sekcja 0](docs/ARCHITECTURE.md#0-zmiana-kierunku-brief-agh). Od P1
> jest jedna konsola zespołu IT i cztery role z briefu ([docs/ROLES.md](docs/ROLES.md));
> pozostałe sekcje poniżej przepisujemy w kolejnych etapach.

## Uruchomienie

```bash
cp .env.example .env        # ustaw POSTGRES_PASSWORD i KEYCLOAK_ADMIN_PASSWORD
docker compose up --build
```

Konsola zespołu IT: <http://localhost:8080/admin/> (`/` przekierowuje tutaj). Dokumentacja
API: <http://localhost:8080/api/docs>.
Po takim starcie zakres skanowania jest pusty, system niczego nie skanuje i nie ma kont
użytkowników (patrz [Logowanie i role](#logowanie-i-role)).

## Demo w 3 minuty (bez internetu)

```bash
# w pliku .env ustaw świadomie: DEMO_MODE=true
./scripts/seed_demo.sh
```

Skrypt uruchamia stos razem z celowo podatnym [demo-lab](demo-lab/README.md), importuje
fikcyjny inwentarz, wczytuje feedy ze snapshotów, skanuje sieć demo-lab i liczy ryzyko.
Trwa około minuty po zbudowaniu obrazów. Na końcu zakłada w Keycloaku cztery fikcyjne
konta demo, po jednym na rolę z briefu, i wypisuje ich hasła oraz wspólny sekret TOTP
(zapisane też w `data/demo-credentials.env`, poza Gitem). Wszystkie logują się do `/admin/`
hasłem i kodem TOTP: dodaj sekret z wypisanego `otpauth://` do aplikacji uwierzytelniającej.

| Konto | Rola | Co może |
|---|---|---|
| `admin` | Administracja (`administrator`) | wszystko, w tym role i użytkownicy, zakres, integracje, zdolności agenta, audyt |
| `editor` | Dodawanie, usuwanie, modyfikacja (`editor`) | cele, skany, statusy, raporty, zadania agenta i zatwierdzanie akcji L2/L3 |
| `modifier` | Modyfikacja i odczyt (`modifier`) | zmiana statusów i decyzje w kolejce weryfikacji, bez dodawania i skanowania |
| `viewer` | Odczyt (`viewer`) | odczyt i eksport; próba skanu kończy się 403 z wpisem w audycie |

Pełna macierz rola × uprawnienie × endpoint: [docs/ROLES.md](docs/ROLES.md). W konsoli
(`admin`) zobaczysz:

| Widok | Co pokazuje |
|---|---|
| Zagrożenia | CVE-2021-41773 i CVE-2021-42013 na `web-01` jako krytyczne, z rozbiciem oceny na składniki i zdaniem „dlaczego”. |
| Feed zagrożeń | 9 znanych podatności, z czego 4 dotyczą naszych zasobów. |
| Kolejka weryfikacji | Apache 2.4.25 z Debiana na `legacy-01`: system nie zgaduje, czy poprawki są backportowane, i pyta człowieka. Zagrożenia powstają dopiero po potwierdzeniu. |
| Zasoby | `172.30.99.14` jako shadow IT (odpowiada, a nie ma go w inwentarzu), `old-db-01` jako zasób, który nie odpowiada. |
| Skany | Każda akcja z nazwą reguły i decyzją kontroli zakresu. Pełny skan portów (poziom L2) wykonany na podstawie zgody `seed_demo`. |
| Dziennik audytu | Każda decyzja: co, kiedy, która reguła, na podstawie jakich danych. |

Żeby zobaczyć zatwierdzanie przez człowieka, uruchom skrypt z pustą zgodą:
`DEMO_APPROVAL_EXPIRES_AT=1970-01-01T00:00:00Z ./scripts/seed_demo.sh`. Skan L2 pojawi się
wtedy w widoku Skany jako „Czeka na zgodę”.

### Raporty i scenariusz zero-day

Po `seed_demo` w Skrzynce (`/admin/skrzynka`) czeka raport o stanie z czerwonym światłem.
Warstwa „W skrócie” odpowiada na pięć pytań (Co się stało? Czy jesteśmy zagrożeni? Co
najgorszego może się stać? Co trzeba zrobić? Kto i do kiedy?) prostym językiem, z podpowiedzią
przy każdym terminie ze słownika; „Szczegóły techniczne” są zwinięte. Światło i fakty liczy
kod, a model tylko formułuje zdania w tle: raport jest w skrzynce od razu, z odpowiedziami z
szablonu, i zostaje przy nich, jeśli tekst modelu nie przejdzie walidacji.

Scenariusz zero-day na prezentacji (tylko `DEMO_MODE=true`):

```bash
./scripts/inject_kev.sh               # syntetyczny wpis KEV dla CVE-2021-23017 (nginx na proxy-01)
```

Wpis przechodzi tą samą ścieżką co prawdziwy feed KEV: dopasowanie, ocena ryzyka,
powiadomienie i raport „zero-day” w skrzynce każdej roli, bez modelu językowego. Skrypt
wypisuje czasy kolejnych kroków (lokalnie około 50 ms, CI pilnuje progu 5 s). W konsoli pojawia
się czerwony baner z linkiem do raportu i znika po jego przeczytaniu. W dzienniku audytu wpis
jest oznaczony jako syntetyczny.

![Raport „W skrócie”](docs/screenshots/etap4b-raport.png)
![Baner zero-day](docs/screenshots/etap4b-baner-zero-day.png)

![Zagrożenia](docs/screenshots/etap2-zagrozenia.png)
![Skany](docs/screenshots/etap2-skany.png)
![Kolejka weryfikacji](docs/screenshots/etap2-weryfikacja.png)

### Role i użytkownicy (P1)

Strona „Role i użytkownicy” (`/admin/role`, uprawnienie `iam:read`) pokazuje macierz
uprawnień czterech ról z briefu i ról własnych. Administrator tworzy w edytorze rolę własną z
dowolnego podzbioru uprawnień z [`rules/roles.yaml`](rules/roles.yaml), z wyjątkiem
`iam:manage`, i nadaje użytkownikom role wbudowane (bez Administracji, którą nadaje się tylko w
Keycloak) albo własne. Każda zmiana trafia do dziennika audytu. Karta hosta (`/admin/zasoby/:id`)
pokazuje atrybuty, wykryte usługi, aktywne zagrożenia i historię zmian.

Sentek (asystent) ma w P1 tylko backend: odpowiada z danych w granicach uprawnień pytającego,
a prośbę o skan zamienia w propozycję zadania dla agenta, którego plan zatwierdza człowiek.
Interfejs Sentka wraca w konsoli w P10.

![Role i użytkownicy](docs/screenshots/p1-role.png)
![Karta hosta](docs/screenshots/p1-karta-hosta.png)

### Feedy: snapshoty i tryb online

Domyślnie (`FEEDS_MODE=offline`) system czyta feedy z plików w `data/feeds/`, które nie
trafiają do Gita. Pobiera je `./scripts/fetch_feeds.sh` (wymaga internetu; uruchom po
zaimportowaniu inwentarza, przed prezentacją bez sieci). Gdy `data/feeds/` jest puste,
`seed_demo` używa miniaturowego, ręcznie przygotowanego zestawu z
`backend/tests/fixtures/feeds/` (9 publicznie znanych CVE, wartości EPSS fikcyjne i tak oznaczone w pliku; interfejs pokazuje wtedy etykietę „Dane demonstracyjne”).

### Wyjaśnienia z lokalnego modelu (opcjonalnie)

System działa w pełni bez modelu: każde zagrożenie ma wtedy wyjaśnienie z szablonu,
zbudowane przez kod z danych w bazie.

**Domyślny model: Qwen3 4B (Q4_K_M)**, ustawiony w `.env.example` jako
`LLM_MODEL=qwen3-4b-q4km`. W ewaluacji z promptami v2 jego odpowiedzi przechodzą walidator w
93% przypadków (poziom techniczny 95%), Bielika 4.5B w 70%; szczegóły w
[eval/RESULTS.md](eval/RESULTS.md). Żeby go włączyć:

```bash
./scripts/fetch_models.sh          # Qwen3 4B, około 2,5 GB, przypięta rewizja i suma SHA-256
docker compose up -d
```

**Opcja: Bielik 4.5B v3.0** (`LLM_MODEL=bielik-4.5b-q4km`). Pisze lepszą polszczyzną, ale
częściej wychodzi poza fakty, więc częściej dostajesz wersję z szablonu. Oficjalne
repozytorium nie publikuje wariantu Q4_K_M, więc `fetch_models.sh` pobiera fp16 (9,5 GB) i
kwantyzuje go obrazem `ghcr.io/ggml-org/llama.cpp`. **Ta ścieżka nie jest zweryfikowana**:
kwantyzację sprawdziłem tylko llama.cpp uruchomionym poza Dockerem, bo obraz z GHCR nie był
dostępny w moim środowisku.

Model działa w Ollamie, w sieci bez dostępu do internetu. W widoku Zagrożenia panel
„Wyjaśnienie” ma trzy poziomy (zarządczy, operacyjny, techniczny) i pokazuje odpowiedź na
żywo. Model dostaje wyłącznie fakty z bazy, bez nazw i adresów zasobów; kontekst zasobu
dokleja kod. Każdą odpowiedź sprawdza walidator: identyfikatory CVE, wersje, daty i polecenia
muszą pochodzić z faktów, inaczej użytkownik dostaje wersję z szablonu. Tekst dla danego CVE
i poziomu powstaje raz i trafia do cache. `seed_demo` zleca generowanie w tle, gdy model
jest skonfigurowany. Na 4 rdzeniach jedna odpowiedź trwa zwykle 15–40 s.

Zewnętrzny model jest domyślnie wyłączony (`EXTERNAL_LLM_ENABLED=false`). Po świadomym
włączeniu przez administratora dostaje tylko tekst po anonimizacji (zasoby jako
`asset_<id>`, adresy IP, domeny i e-maile zamaskowane), a każde użycie trafia do dziennika
audytu.

![Wyjaśnienie generowane na żywo](docs/screenshots/etap3-strumien.png)

## Logowanie i role

Logowanie obsługuje Keycloak (OIDC, kod autoryzacji z PKCE), wystawiony przez ten sam nginx
pod `/auth`. Realm `sentinel` jest importowany przy starcie z
[`infra/keycloak/sentinel-realm.json`](infra/keycloak/sentinel-realm.json) i nie zawiera
haseł ani sekretów.

- **Role:** `administrator`, `editor`, `modifier`, `viewer` (cztery role z briefu) oraz
  techniczne `agent` i `system`. Keycloak trzyma tylko przynależność do ról; uprawnienia ról
  są w [`rules/roles.yaml`](rules/roles.yaml), a sprawdza je backend na każdym endpoincie
  (deny-by-default). Role własne i nadania z konsoli są w bazie (`iam_custom_role`,
  `iam_role_grant`). Test przegląda wszystkie trasy i nie przechodzi, gdy któraś nie deklaruje
  uprawnienia; macierz rola × endpoint × akcja sprawdza 2xx, 403 i 401
  ([docs/ROLES.md](docs/ROLES.md)).
- **MFA:** każda rola loguje się do `/admin/` hasłem i kodem TOTP. Backend uznaje MFA
  wyłącznie na podstawie claimu `amr` w tokenie, więc konsola, zmiany i zgody na skany L2/L3
  bez drugiego składnika kończą się odmową; bez MFA zostaje tylko odczyt przez API.
- **Sesje:** token dostępu 5 minut z odświeżaniem, 30 minut bezczynności, maksymalnie 12 h.
  Wylogowanie unieważnia sesję w Keycloaku i w backendzie (lista w Redisie; gdy Redis nie
  odpowiada, backend odmawia). Po 5 nieudanych próbach konto jest blokowane na 1–15 minut.
- **Redakcja danych technicznych:** bez uprawnienia `secrets:redacted:view` adresy IP,
  banery, dowody i parametry techniczne są usuwane w warstwie serializacji API, nie w
  interfejsie. Cztery role z briefu je mają; redakcja dotyczy ról własnych bez tego uprawnienia.
- **Odmowy w audycie:** każda odpowiedź 403 trafia do dziennika audytu z aktorem i
  identyfikatorem żądania (`X-Request-ID`).
- **Break-glass:** `./scripts/breakglass.sh` ustawia hasło i TOTP konta `breakglass-admin` i
  wypisuje je raz; skrypt niczego nie zapisuje. Każde logowanie tym kontem tworzy alert i
  wpis w audycie. Do Etapu 5 hasło trzeba samodzielnie przechować w sejfie; od Etapu 5
  trafi do OpenBao.

**Dostęp spoza localhost.** Na razie interfejs nasłuchuje tylko na `127.0.0.1`. Dostęp z
sieci powstanie w Etapie 9 jako profil Compose `tls`: Caddy z certyfikatem lokalnym jako
reverse proxy dla konsoli, API i Keycloaka. Bez HTTPS logowanie spoza localhost i tak by
nie zadziałało: przeglądarka udostępnia Web Crypto (potrzebne do PKCE) tylko w bezpiecznym
kontekście, a ciasteczka Keycloaka mają flagę `Secure`.

![Drugi składnik logowania admina](docs/screenshots/etap4-totp.png)
![Odmowy w dzienniku audytu](docs/screenshots/etap4-audyt-odmowy.png)

## Wymagania sprzętowe

4+ rdzenie CPU, 16 GB RAM, około 30 GB SSD, Docker z Compose. **GPU nie jest wymagane.**

## Co już działa

| Obszar | Opis |
|---|---|
| `scope_guard` | Jedyna brama dla aktywnych działań sieciowych. Zakres domyślnie pusty, denylista przed allowlistą, sprawdzenie po rozwiązaniu DNS, zgoda człowieka na skany inwazyjne, limit szybkości per cel. Test architektury pilnuje, żeby żaden moduł nie sięgał do sieci z pominięciem bramy. |
| Dziennik audytu | Tylko do dopisywania (trigger w bazie) z łańcuchem skrótów. |
| Inwentarz | Import CSV, scalanie importu ze skanem po odcisku zasobu, shadow IT, zasoby, które przestały odpowiadać, historia zmian usług. |
| Scan Planner | Deterministyczne reguły w [`rules/scan_rules.yaml`](rules/scan_rules.yaml). Przy każdej akcji zapisana jest reguła, która ją wywołała. |
| Skanowanie | nmap jako adapter przyjmujący wyłącznie cel wydany przez `scope_guard`. Narzędzia są tylko w obrazie skanera. |
| Feedy | NVD, CISA KEV, EPSS. Jedna ścieżka kodu dla trybu online i dla snapshotów offline. |
| Dopasowanie | Słownik aliasów, CPE z narzędzia, dopasowanie rozmyte z progami w [`rules/matching.yaml`](rules/matching.yaml). Niska pewność trafia do kolejki weryfikacji. Nieznana wersja nie tworzy zagrożenia. |
| Ocena ryzyka | Jawna formuła z wagami w [`rules/scoring.yaml`](rules/scoring.yaml), rozbicie na składniki i zdanie „dlaczego” budowane przez kod. |
| Powiadomienia | Reguły w [`rules/notifications.yaml`](rules/notifications.yaml): grupowanie per zasób, bez powtórek w ciągu doby. E-mail, Slack i Teams są wyłączone do czasu konfiguracji w `.env`. |
| AI Explainer | Wyjaśnienia na trzech poziomach z lokalnego modelu (Ollama), generowane raz i trzymane w cache, z walidatorem faktów i wersją z szablonu, gdy model jest niedostępny albo się myli. Streaming przez SSE. Prompty wersjonowane w `backend/app/explainer/prompts/`, limity w [`rules/explainer.yaml`](rules/explainer.yaml). |
| Raporty | Raport dwuwarstwowy: światło z reguł [`rules/reports.yaml`](rules/reports.yaml), „W skrócie” z modelu po walidacji (albo z szablonu), słownik terminów [`rules/glossary.yaml`](rules/glossary.yaml), szczegóły techniczne. Doręczenie do skrzynki ról z potwierdzeniem odczytu per osoba. Nazwy zasobów i osób model widzi tylko jako tokeny (`asset_1`, `person_1`). |
| Scenariusz zero-day | `scripts/inject_kev.sh`: syntetyczny wpis KEV, raport w skrzynce i baner w konsoli w czasie poniżej 5 s, bez modelu. |
| Testy własnego AI | [promptfoo w `ai-tests/`](ai-tests/README.md): pośrednie prompt injection przez opisy CVE na prawdziwej ścieżce aplikacji, z posłuszną atrapą (każdy PR) i z Qwen3 4B (9 przypadków w każdym PR, pełny zestaw nocą), wyniki osobno. Nocą także generowany red team OWASP LLM Top 10 (generator i sędzia przez API na syntetycznych danych, bez klucza Bielik 4.5B). |
| Agent AI | Polecenie → plan (model albo szablon) → walidacja kodem → zatwierdzenie przez admina → wykonanie przez serwer MCP `mcp-scanner` (polityka zdolności → `scope_guard` → adapter). Sześć narzędzi: `discover_hosts`, `scan_services`, `probe_http` (L1), `scan_all_ports`, `verify_cve` z nuclei (szablony detekcyjne), `collect_software_authenticated` (L2). Jedna runda kroków uzupełniających, też do zatwierdzenia. Kill switch jednym kliknięciem. |
| Poświadczenia JIT | OpenBao: certyfikat SSH podpisywany na zadanie z TTL 15 min, klucz tylko w pamięci, odwołanie leasu po zadaniu. Sekret nie trafia do modelu, logów, API ani audytu (testy z kanarkami). |
| Test agenta (moduł 19) | Niezależny harness na osobnej kolejce i osobnym użytkowniku bazy, tryb dry-run z atrapami narzędzi i kanarkami, 12 przypadków w sześciu kategoriach, dwie oceny (model i kod), wynik podpisany Ed25519 i w audycie. Bramka zmian konfiguracji agenta z wymuszeniem wymagającym uzasadnienia. Nocny przebieg w CI. |
| Sygnały bez CPE | Wpis KEV bez zakresu wersji w NVD trafia do kolejki weryfikacji jako sygnał; finding powstaje wyłącznie po decyzji człowieka. |
| Kolejki | Osobne kolejki Celery: `default`, `scans`, `feeds`, `llm` (zawsze jedno zadanie naraz), `agent`, `agent_tests`. |
| Tożsamość i RBAC | Keycloak (OIDC, PKCE), TOTP dla każdej roli, krótkie sesje z unieważnianiem, blokada po nieudanych próbach, break-glass z alertem. Cztery role z briefu, edytor ról własnych, nadawanie ról z konsoli, uprawnienie na każdym endpoincie, odmowy w audycie ([ROLES.md](docs/ROLES.md)). |
| Interfejs | Jedna konsola zespołu IT `/admin/`: Pulpit, Skrzynka, Raporty, Zasoby z kartą hosta, Zagrożenia, Feed zagrożeń, Kolejka weryfikacji, Skany, Zakres skanowania, Agent AI, Test agenta, Dziennik audytu, Role i użytkownicy. Menu i formularze zależą od uprawnień roli; o dostępie decyduje backend. |
| Sentek | Asystent (na razie tylko API, interfejs w P10): model rozpoznaje tylko intencję (limit 4 s, potem słowa kluczowe), odpowiedź buduje kod z bazy z RBAC, prośba o skan to tylko propozycja zadania dla agenta, odmowa poleceń zmieniających cokolwiek, audyt bez treści pytania. Eval 39 wypowiedzi, promptfoo z wrogą atrapą w każdym PR. |

## Zakres skanowania

Zakres ustawia się w [`rules/scope.yaml`](rules/scope.yaml). Domyślnie jest pusty, więc
system niczego nie skanuje. Każda decyzja bramy (także odmowa) trafia do dziennika audytu.

Tryb demo (`DEMO_MODE=true`) pozwala skryptowi `seed_demo` zastąpić kliknięcie człowieka
przy skanach inwazyjnych, ale wyłącznie w sieci demo-lab, do daty wygaśnięcia i nadal
przez `scope_guard`. Domyślnie jest wyłączony.

## Rozwój

```bash
# backend
cd backend
uv sync --extra dev
uv run ruff check . && uv run ruff format --check . && uv run mypy app tests
uv run pytest                 # bez sieci, bez bazy, bez modelu

# frontend
cd frontend
npm ci
npm run lint && npm run typecheck && npm run build

# testy własnego AI (promptfoo), szczegóły w ai-tests/README.md
cd ../ai-tests && npm ci && ./run.sh mock
npm run dev:admin             # http://localhost:5173/admin/, proxy /api na :8000
npm run e2e                   # Playwright z podstawionym API (fikcyjne dane z e2e/fixtures)
# /auth trafia do Keycloaka z docker compose (SENTINEL_AUTH_URL, domyślnie :8080);
# PUBLIC_URL w .env musi wtedy wskazywać adres serwera deweloperskiego
```

Zmiany trafiają do `main` wyłącznie przez pull requesty z gałęzi etapowych
(`pN-nazwa`), w konwencji Conventional Commits.

## demo-lab

Katalog [`demo-lab/`](demo-lab/README.md) opisuje **celowo podatne** usługi do testów.
Działają w sieci Dockera oznaczonej `internal: true`: bez wyjścia na zewnątrz i bez portów
na hoście. Widzi je wyłącznie kontener skanera. Startują tylko z profilem `demo`.
Nie uruchamiaj ich w żadnej innej konfiguracji.

## Ograniczenia

- System wykrywa i weryfikuje, **nie eksploatuje** podatności.
- Nie „wykrywa zero-dayów”. Szybko łapie wczesne sygnały i odpowiada, czy i gdzie
  organizacja jest narażona.
- Dostęp spoza localhost dopiero w Etapie 9 (profil `tls`, sekcja
  [Logowanie i role](#logowanie-i-role)).
- Keycloak i aplikacja korzystają z jednej instancji PostgreSQL, ale z osobnymi
  użytkownikami: każdy jest właścicielem tylko własnego schematu (`public` albo `keycloak`) i
  nie ma dostępu do drugiego, co sprawdza test w CI. Hasło administratora bazy zna tylko
  jednorazowa usługa `db-init`. Osobna instancja bazy jest w [ROADMAP](docs/ROADMAP.md).
- Logowanie bez Keycloaka (`AUTH_PROVIDER=local`) nie powstało: Keycloak mieści się w
  budżecie pamięci, więc fallback nie był potrzebny.
- Weryfikacja podatności (nuclei) używa wyłącznie szablonów detekcyjnych z jawnej listy i
  potwierdza podatność po wersji; nic nie jest eksploatowane.
- Przez serwer MCP idzie tylko agent. Pipeline skanów woła adaptery bezpośrednio, zawsze
  przez `scope_guard` (przejście na MCP w [ROADMAP](docs/ROADMAP.md)).
- Kill switch blokuje agenta od razu, wyłącza jego klienta w Keycloak, hurtowo odwołuje tokeny
  `mcp-scanner` w OpenBao i przerywa trwające skany. **Luka:** certyfikaty SSH wydane przed
  wyłączeniem działają do końca TTL (najwyżej 15 minut), bo hosty nie mają listy KRL (ROADMAP).
- Do sieci demo-lab podłączone są dwa skanery: `mcp-scanner` (agent) i `worker-scans`
  (pipeline, dopóki nie przejdzie na MCP). Worker agenta i pozostałe usługi nie mają tam drogi.
- OpenBao w demo trzyma klucz rozpieczętowania w wolumenie `openbao-init`, dostępnym tylko
  dla usługi inicjalizującej. Produkcja: auto-unseal przez KMS/HSM.
- E-mail z raportami i digestami idzie zawsze w wersji „W skrócie” z PDF (bez danych
  technicznych) na jeden adres `NOTIFY_EMAIL_TO`; Slack, Teams dla raportów i baner przez SSE
  są w [ROADMAP](docs/ROADMAP.md).
- Reguły przeciw pośredniemu prompt injection (sprzeczności, prośby o hasła) są słownikowe i
  nie złapią każdej parafrazy. Twarda gwarancja: ocenę ryzyka, światło i terminy liczy kod,
  a model nie może ich zmienić (sprawdza to [`ai-tests/`](ai-tests/README.md)).
- Walidator wyjaśnień sprawdza pochodzenie identyfikatorów, wersji, dat, poleceń i linków,
  ale nie sens zdań. Model może więc nieprecyzyjnie streścić fakt (przykłady w
  [eval/RESULTS.md](eval/RESULTS.md)). Dlatego decyzje i ocena ryzyka nigdy nie zależą od
  tekstu modelu, a obok wyjaśnienia zawsze widać fakty z bazy.
- W repozytorium nie ma modeli, snapshotów feedów, wyników skanów ani danych o
  rzeczywistej infrastrukturze.
