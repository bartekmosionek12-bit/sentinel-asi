# Macierz zgodności z briefem AGH

Stan na 21.11.2026 (Etap P0, przed zmianami w kodzie). Źródło wymagań: [BRIEF.md](BRIEF.md).
Ta tabela jest też slajdem prezentacji; aktualizujemy ją po każdym etapie.

**Status:** ✅ jest · 🟡 częściowo · ❌ brak. „Częściowo” znaczy, że jest działający kod, który
da się rozbudować, ale nie spełnia wymagania w całości.

**Kryteria oceny (sekcja 8 briefu):**

| Kod | Kryterium | Waga |
|---|---|---|
| K1 | Skuteczność discovery i poprawność identyfikacji usług w dużej infrastrukturze | 30% |
| K2 | Jakość techniczna, dokumentacja, prezentacja, uruchomienie, import/eksport, DefectDojo | 20% |
| K3 | Zmiany w czasie, niestabilne hosty, użyteczność raportowania | 15% |
| K4 | Bezpieczeństwo działania, kontrola intensywności, przejrzystość dashboardu | 15% |
| K5 | Fingerprinting, technologie, CMS-y, nagłówki, ciasteczka, sygnatury | 10% |
| K6 | Role i zabezpieczenie danych | 10% |

**Etapy:** P1 role i porządki · P2 wejście danych, nadpisania, eksport · P3 discovery na skalę ·
P4 fingerprinting HTTP i technologie · P5 zmiany w czasie i niestabilne hosty · P6 DefectDojo ·
P7 własne sygnatury · P8 harmonogram i okna · P9 szyfrowanie w spoczynku · P10 dashboard,
raporty, Sentek · P11 testy AI w konsoli i test endpointu · P12 walidacja, dokumentacja,
prezentacja. Plan i linia cięcia: [ROADMAP.md](ROADMAP.md).

## Podsumowanie

| Grupa | ✅ | 🟡 | ❌ |
|---|---|---|---|
| Sekcja 2, pkt 1–16 | 1 | 9 | 6 |
| Sygnatury i harmonogram (akapity sekcji 2) | 0 | 1 | 1 |
| Minimalny zakres (sekcja 3) | 3 | 4 | 7 |
| Mile widziany zakres (sekcja 3) | 0 | 6 | 5 |
| Wymagania formalne i techniczne (sekcje 4–5) | 1 | 3 | 1 |
| Walidacja (sekcja 6, pkt 1–12) | 1 | 6 | 5 |
| **Razem (60 pozycji)** | **6** | **29** | **25** |

Wniosek: mamy solidne fundamenty bezpieczeństwa (scope_guard, audyt, RBAC deny-by-default,
Keycloak z MFA, OpenBao, agent z zatwierdzaniem i testem bezpieczeństwa), ale rdzeń briefu
(discovery na skalę, fingerprinting HTTP, sygnatury, porównanie przebiegów, DefectDojo,
szyfrowanie pól) trzeba zbudować. Największe ryzyko punktowe: K1 (30%) i K2 (20%, DefectDojo
obowiązkowe).

## A. Sekcja 2, pkt 1–16

| ID | Wymaganie | Status | Gdzie dziś w kodzie | Co trzeba zrobić | Etap | Kryt. |
|---|---|---|---|---|---|---|
| R1 | Wczytanie listy IP, zakresów CIDR lub domen | 🟡 | `POST /api/assets`, `POST /api/assets/import` (CSV, `inventory/service.py:parse_assets_csv`); zakres skanu tylko z pliku `rules/scope.yaml` | Obiekt „cel” (IP, CIDR, domena) z formularza i z pliku CSV/JSON; walidacja, deduplikacja, podgląd; cele zasilają allowlistę scope_guard (tylko rola z uprawnieniem) | P2 | K2 |
| R2 | Bezpieczny skan discovery: wielowątkowy, pomiar czasu, podział na optymalne podgrupy | 🟡 | `scanners/nmap.py` (nmap `-sn`, `-sV`, `-T4`), `scans/service.py` (jeden przebieg na sieć, sekwencyjnie), `ScanRun.started_at/finished_at`, limit per cel w `core/scope_guard.py` | Podział na paczki o rozmiarze dobieranym z zmierzonej szybkości, równoległe workery, czas paczki i przebiegu, ETA, zapis przyrostowy, limity globalne i per podsieć, timing nie agresywniejszy niż T3 | P3 | K1, K4 |
| R3 | Wykrycie aktywnych hostów | 🟡 | `nmap -sn -PS` na 9 portach TCP (`DISCOVERY_PORTS`), `inventory/service.py:record_discovery` (nowy / widziany / missing po jednym braku) | Kombinacja technik (ICMP echo i timestamp, TCP SYN/ACK, ARP lokalnie, wybrane UDP), tylko porty dozwolone przez organizatora; stan hosta według reguł (P5) | P3 | K1 |
| R4 | Identyfikacja podstawowych usług | ✅ | `nmap -sV` na „top 1000” + porty dodatkowe (`rules/scan_rules.yaml`), `record_host_scan`, tabela `software` z CPE | Przenieść na paczki i równoległość (P3), zapisać banery, intensywność `-sV` w konfiguracji | P3 | K1 |
| R5 | HTTP/HTTPS: tytuł, kod, nagłówki, ciasteczka, certyfikat TLS, przekierowania | 🟡 | `scanners/http_probe.py`: tylko kod, nagłówek `Server` i tytuł; tylko jako narzędzie agenta `probe_http` | Moduł fingerprintingu w zwykłym przebiegu: wszystkie nagłówki, ciasteczka z atrybutami, TLS (wystawca, podmiot, SAN, ważność, algorytmy), łańcuch przekierowań, hash favicony (mmh3), fragmenty HTML; httpx (Go) + własny moduł | P4 | K5, K1 |
| R6 | Proste wykrywanie technologii: CMS, framework, serwer aplikacyjny, IoT | ❌ | Tylko produkt i wersja z `nmap -sV` | Fingerprinty (baza Wappalyzer/webanalyze, sygnatury nmap, własne), poziom pewności z dowodami | P4 | K5 |
| R7 | Staging/środowisko testowe, panel administracyjny | ❌ | brak | Reguły na nazwach hostów, tytułach, nagłówkach, ciasteczkach, certyfikatach; ścieżki `/admin`, `/login`, `/manager` tylko GET/HEAD | P4 | K5 |
| R8 | Porównanie wyników między przebiegami | 🟡 | `AssetHistory` (discovered, missing, reappeared, zmiany usług z `ServiceDiff`) | Porównanie dowolnych dwóch przebiegów: hosty, usługi, technologie, nagłówki, ciasteczka, certyfikaty; widok różnic i eksport | P5 | K3 |
| R9 | Oznaczenie nowych, znikających i zmienionych usług | 🟡 | `ServiceDiff` (dodane i usunięte), bez „zmienionych” | Stany nowy / zmieniony / niepotwierdzony / znikający / nieaktywny według reguł; zmiana wersji, banera, TLS jako „zmieniona” | P5 | K3 |
| R10 | Własne sygnatury detekcyjne | ❌ | (nuclei tylko jako `verify_cve` agenta, poziom L2) | Format YAML, typy dopasowań z briefu, walidator bezpieczeństwa (tylko GET/HEAD), UI: dodaj, edytuj, testuj, import/eksport | P7 | K5 |
| R11 | Formularz: ręcznie oraz plik CSV i/lub JSON, przetwarzane tak samo | 🟡 | Formularz i import CSV zasobów w `/admin/zasoby`; brak JSON; zasoby nie wyznaczają celów skanu | Jedna ścieżka przetwarzania dla formularza, CSV i JSON (cele i wyniki skanów); podgląd przed zapisem | P2 | K2 |
| R12 | RBAC z możliwością tworzenia i obsługi różnych ról | 🟡 | `rules/roles.yaml`, `iam/rbac.py`, `require()` na każdym endpoincie (deny-by-default), Keycloak; ról nie da się tworzyć w UI | Zarządzanie rolami w konsoli (administrator: tworzenie roli z listy uprawnień, przypisanie użytkownikom); macierz testów rola × endpoint × akcja | P1 | K6 |
| R13 | Role: Administracja; Dodawanie, usuwanie, modyfikacja; Modyfikacja i odczyt; Odczyt | ❌ | Role `admin`, `manager`, `auditor`, `agent` | `administrator`, `editor`, `modifier`, `viewer` + tożsamość `agent`; polskie nazwy w UI; `docs/ROLES.md` | P1 | K6 |
| R14 | Edycja wartości niezależnie od stanu skanu, zachowana przy kolejnych skanach | ❌ | Tylko status findingu (`PATCH /api/findings/{id}`); dane hosta nadpisuje kolejny skan | Warstwa nadpisań użytkownika oddzielna od obserwacji; skan nigdy jej nie nadpisuje; widok scalony z oznaczeniem kto i kiedy; historia | P2 | K2, K6 |
| R15 | Czytelny interfejs dla każdej roli, dashboard najważniejszych znalezisk | 🟡 | Konsola `/admin/` (Pulpit pod CVE i ryzyko); konsola menedżera do usunięcia | Dashboard discovery: znaleziska, zmiany, panele i staging, niestabilne hosty, skany z ETA, status DefectDojo; elementy ukryte według roli | P10 | K4 |
| R16 | Szyfrowanie w spoczynku pól z danymi wrażliwymi | ❌ | brak (OpenBao jest, ale tylko do poświadczeń JIT) | Szyfrowanie pól (OpenBao Transit), HMAC do wyszukiwania, rotacja kluczy, test `pg_dump`, `docs/DATA_PROTECTION.md` | P9 | K6 |

## B. Akapity sekcji 2: sygnatury i harmonogram

| ID | Wymaganie | Status | Gdzie dziś w kodzie | Co trzeba zrobić | Etap | Kryt. |
|---|---|---|---|---|---|---|
| S1 | Sygnatury bezpieczne: nagłówek, ciasteczko, hash favicony, fragment HTML, ścieżka bez logowania, wersja w stopce, fingerprint CMS; bez eksploatacji | ❌ | brak | Jak R10; walidator odrzuca metody inne niż GET/HEAD, treść żądania, poświadczenia, parametry ataku, nadmiar żądań; `docs/SIGNATURES.md` | P7 | K5, K4 |
| S2 | Harmonogram: okna czasowe i częstotliwość; po przekroczeniu okna zatrzymanie i wznowienie w kolejnym | 🟡 | Celery beat: skan raz na dobę (`workers/celery_app.py`), bez okien | Okna (np. pon–pt 22:00–06:00), częstotliwość, punkt kontrolny (skończone paczki), wznowienie, statusy przebiegu, widok harmonogramu | P8 | K1, K3 |

## C. Minimalny oczekiwany zakres (sekcja 3)

| ID | Wymaganie | Status | Uwagi / odwołanie | Etap | Kryt. |
|---|---|---|---|---|---|
| M1 | Import listy hostów lub zakresów | 🟡 | Jak R1, R11 | P2 | K2 |
| M2 | Import wyników skanów w JSON lub CSV | ❌ | Do zbudowania; nmap XML jako bonus (parser już jest: `parse_nmap_xml`) | P2 | K2 |
| M3 | Obsługa dużych zakresów, ponad 10 000 IP | ❌ | Niezweryfikowane; demo-lab ma kilka hostów. Test /18 lub /16 i `docs/PERFORMANCE.md` | P3 | K1 |
| M4 | Konfiguracja skanu: okno czasowe i częstotliwość | ❌ | Jak S2 | P8 | K1 |
| M5 | Ograniczanie tempa zapytań | 🟡 | Limit akcji na cel na minutę w scope_guard; brak limitu pakietów (`--max-rate`), równoległości i per podsieć | P3 | K4 |
| M6 | Wykrywanie aktywnych hostów | 🟡 | Jak R3 | P3 | K1 |
| M7 | Podstawowa identyfikacja usług | ✅ | Jak R4 | P3 | K1 |
| M8 | Zapis wyników do bazy lub pliku | ✅ | PostgreSQL (`asset`, `software`, `scan_run`, `scan_action`, `asset_history`) | P3 (zapis przyrostowy) | K1 |
| M9 | Porównanie dwóch skanów | ❌ | Brak widoku przebieg × przebieg (jest tylko historia zasobu) | P5 | K3 |
| M10 | Dashboard lub raport najważniejszych zmian | ❌ | Raporty są o CVE, nie o zmianach discovery | P5, P10 | K3, K4 |
| M11 | Eksport wyników do JSON lub CSV | ❌ | Jest tylko PDF raportu | P2 | K2 |
| M12 | Rozgraniczenie funkcjonalności na role | ✅ | RBAC na każdym endpoincie; role do wymiany (R13) | P1 | K6 |
| M13 | Edycja danych istniejących skanów, wyników i konfiguracji | 🟡 | Tylko status findingu i decyzje kolejki weryfikacji | P2, P8 | K2 |
| M14 | Ochrona danych ze skanów (szyfrowanie) | ❌ | Jak R16 | P9 | K6 |

## D. Mile widziany zakres (sekcja 3)

| ID | Wymaganie | Status | Uwagi / odwołanie | Etap | Kryt. |
|---|---|---|---|---|---|
| N1 | Harmonogram cyklicznych skanów | 🟡 | Stały beat raz na dobę | P8 | K3 |
| N2 | Różnice zależne od pory dnia | ❌ | Profil dostępności 24 h × 7 dni | P5 | K3 |
| N3 | Ocena „ciekawości” / priorytetu analitycznego | 🟡 | Jest jawny scoring ryzyka CVE (`rules/scoring.yaml`), trzeba nowej formuły dla obserwacji | P5 | K3 |
| N4 | Powtarzanie pomiarów hostów niestabilnych | ❌ | Dodatkowe próby w przebiegu i w kolejnych oknach | P5 | K3 |
| N5 | Moduł HTTP/HTTPS fingerprinting | 🟡 | Jak R5 | P4 | K5 |
| N6 | Proste wykrywanie CMS-ów lub technologii | ❌ | Jak R6 | P4 | K5 |
| N7 | Grupowanie podobnych usług | ❌ | Technologia + wersja + favicon | P4 | K5 |
| N8 | Obsługa tagów | 🟡 | Pole `asset.tags` (formularz, CSV); brak tagów na usługach i obserwacjach, brak filtrów | P2 | K2 |
| N9 | Eksport obserwacji do DefectDojo (finding informacyjny lub evidence) | ❌ | **Traktujemy jako obowiązkowe** (kryterium K2, nmap „integrujący się z DefectDojo”) | P6 | K2 |
| N10 | Wizualizacja zmian w czasie | 🟡 | Jest wykres trendu pokrycia (do usunięcia z konsolą menedżera); trzeba wykresów zmian discovery | P5, P10 | K3 |
| N11 | Integracja z pasywnymi źródłami danych, jeśli zostaną udostępnione | 🟡 | Feedy NVD, KEV, EPSS (offline i online) to źródła pasywne o podatnościach; pasywny DNS itp. dopiero po udostępnieniu | po P12 | K1 |

## E. Wymagania formalne i techniczne (sekcje 4–5)

| ID | Wymaganie | Status | Uwagi | Etap |
|---|---|---|---|---|
| F1 | Repozytorium kodu | ✅ | GitHub, CI (backend, frontend z Playwright, migracje, e2e na demo-lab, Trivy, promptfoo) | – |
| F2 | Dokumentacja techniczna | 🟡 | ARCHITECTURE, DEMO, PRIVACY itd. opisują stary kierunek; potrzebne: REQUIREMENTS, ROLES, SIGNATURES, DATA_PROTECTION, SAFE_SCANNING, PERFORMANCE, VALIDATION, DEMO_GUIDE | P0–P12 |
| F3 | Prezentacja do 10 slajdów z działającym demo | ❌ | `docs/PRESENTATION_OUTLINE.md` | P12 |
| F4 | Demo lokalnie lub w środowisku testowym | 🟡 | `seed_demo.sh` + demo-lab działa offline; scenariusz do przepisania (dwa przebiegi ze zmianami, import, edycja, role, DefectDojo) | P12 |
| T1 | Technologie bezpłatne i open source; sugerowane Go, Rust, C++ | 🟡 | Wszystko open source. Orkiestracja w Pythonie, ciężka praca w narzędziach natywnych (nmap w C, httpx/naabu w Go). Uzasadnienie pomiarami w `docs/PERFORMANCE.md`; wąskie gardło w Pythonie → osobny moduł w Go | P3, P12 |

## F. Walidacja (sekcja 6): co sprawdzą organizatorzy

Test: co najmniej dwa przebiegi skanu, edycja znalezisk, import, rozgraniczenie ról.

| ID | Punkt walidacji | Status | Na czym polegamy / co brakuje | Etap |
|---|---|---|---|---|
| V1 | Poprawność wykrycia aktywnych hostów | 🟡 | R3; brak ICMP/ARP/UDP i testu skali | P3 |
| V2 | Poprawność identyfikacji usług | ✅ | R4 (`nmap -sV`); do potwierdzenia na wynikach referencyjnych | P3, P12 |
| V3 | Trafność fingerprintingu HTTP/HTTPS | ❌ | R5 | P4 |
| V4 | Wykrywanie CMS-ów lub technologii | ❌ | R6 | P4 |
| V5 | Ciekawe nagłówki i ciasteczka | ❌ | Reguły z uzasadnieniem „dlaczego ciekawe” | P4 |
| V6 | Działanie customowych sygnatur | ❌ | R10, S1; testy na sygnaturach od organizatora | P7 |
| V7 | Porównanie wyników między skanami | 🟡 | R8, M9 | P5 |
| V8 | Hosty niestabilne lub zmieniające odpowiedź | ❌ | Model stanu, powtórzenia, profil pory dnia | P5 |
| V9 | Bezpieczeństwo i ostrożność skanera | 🟡 | scope_guard, poziomy L1–L3 ze zgodą, audyt z łańcuchem skrótów, kill switch agenta; do zrobienia: T3 zamiast T4, limity pakietów, User-Agent z kontaktem, kill switch dla wszystkich skanów, `docs/SAFE_SCANNING.md` | P3, P12 |
| V10 | Czytelność dashboardu lub raportu | 🟡 | R15 | P10 |
| V11 | Import oraz eksport danych | 🟡 | Import CSV zasobów jest; brak JSON, importu wyników i eksportu | P2 |
| V12 | Rozgraniczenie funkcjonalności między role | 🟡 | RBAC jest; role do wymiany na cztery z briefu | P1 |

## G. Pytania z briefu i nasze odpowiedzi (do opisania w dokumentacji)

| Pytanie z briefu | Planowana odpowiedź | Etap |
|---|---|---|
| W jaki sposób raportować zmianę? | Zmiana to różnica między obserwacjami w dwóch przebiegach (host, usługa, technologia, nagłówek, ciasteczko, certyfikat). Znikająca usługa najpierw „niepotwierdzona”, dopiero po spełnieniu reguły „usunięta”. Widok różnic, eksport i opcjonalnie finding informacyjny w DefectDojo | P5 |
| Jak określić pewność identyfikacji technologii? | Wynik 0–100 liczony z liczby i siły niezależnych dowodów (np. nagłówek + ciasteczko + hash favicony + fragment HTML); lista dowodów widoczna w UI | P4 |
| Po jakim czasie braku odpowiedzi raportować host jako nieaktywny? | Konfigurowalna reguła: „nieaktywny” po N kolejnych przebiegach bez odpowiedzi i/lub po czasie T (domyślnie np. N = 3, T = 7 dni); „niestabilny”, gdy odpowiedzi przeplatają się w ostatnich M przebiegach; powtórzenia pomiaru przed zmianą stanu | P5 |

## H. Założenia i pytania do mentorów

Założenia przyjmujemy od razu; po odpowiedzi mentorów poprawiamy kod i tę tabelę.

| # | Niejasność | Nasze założenie | Pytanie do mentorów |
|---|---|---|---|
| Q1 | „Tworzenie i obsługa różnych ról” (pkt 12) | Administrator tworzy role z listy uprawnień w konsoli, poza czterema rolami z pkt 13 | Czy wystarczą cztery stałe role, czy oczekujecie edytora ról? |
| Q2 | Dozwolone techniki discovery (ICMP, ARP, UDP) i porty | Tylko porty z listy organizatora; ICMP i TCP SYN domyślnie, UDP tylko na wybranych portach | Czy w środowisku testowym wolno używać ICMP i UDP? Lista portów? |
| Q3 | Limity tempa | Domyślnie umiarkowane (timing nie agresywniejszy niż T3, limit pakietów na sekundę konfigurowalny) | Jakie limity ruchu obowiązują w środowisku testowym? |
| Q4 | Format importu i eksportu JSON/CSV | Własny, udokumentowany format; adapter na format organizatora po jego otrzymaniu | Kiedy będzie przykładowy format? |
| Q5 | Domeny: tylko rozwiązanie DNS czy też enumeracja subdomen | Rozwiązujemy podane domeny; enumeracja subdomen (pasywna) poza linią cięcia | Czy oczekujecie wyszukiwania subdomen? |
| Q6 | „Pola z danymi wrażliwymi” (pkt 16) | Wartości ciasteczek, nagłówki mogące nieść tokeny, fragmenty treści, notatki, poświadczenia, tokeny integracji | Czy adresy IP i nazwy hostów też uznajecie za wrażliwe? |
| Q7 | Wersja DefectDojo i sposób eksportu | API v2, findingi „Info” i evidence, nmap XML przez wbudowany parser | Jaka wersja DefectDojo będzie w środowisku testowym? |
| Q8 | IPv6 | Tylko IPv4 w prototypie | Czy środowisko testowe ma IPv6? |
| Q9 | Kto czyta dziennik audytu | Administrator; pozostałe role nie | Czy audytor (osobna rola tylko do audytu) jest potrzebny? |

## I. Sprzeczności z dotychczasową specyfikacją (rozstrzygnięte na korzyść briefu)

| Dotychczas | Teraz | Źródło |
|---|---|---|
| Role `admin`, `manager`, `auditor` | Cztery role z briefu + `agent` | Brief pkt 13 |
| „L2 i L3 wymagają zgody człowieka z rolą admin” | Zgoda: `administrator` albo `editor` (decyzja Bartka 21.11) | Polecenie P0 |
| Konsola menedżera, raporty „W skrócie” dla zarządu, pseudonimizacja pracowników | Usunięte; jedna konsola dla zespołu IT/bezpieczeństwa | Brief: „narzędzie dla zespołu bezpieczeństwa” |
| Compliance prawny (KSC, RODO, ISO…), rejestr ryzyk governance, Artemis, film demo | Usunięte | Poza briefem |
| Host „missing” po jednym przebiegu bez odpowiedzi | Reguła N przebiegów / czas T, stan „niestabilny” | Brief, pytanie o nieaktywne hosty |
| nmap `-T4` | Domyślnie nie agresywniej niż T3, limity konfigurowalne | Brief: „bezpieczny skan”, K4 |
| Zakres skanu tylko w pliku `rules/scope.yaml` | Cele z formularza i plików, przez scope_guard | Brief pkt 1, 11 |
| Rdzeń: dopasowanie CVE i scoring ryzyka | Rdzeń: discovery, fingerprinting, zmiany; CVE jako wzbogacenie | Brief, kryteria |
| DefectDojo: brak w planie | Obowiązkowe | Brief, K2 |
