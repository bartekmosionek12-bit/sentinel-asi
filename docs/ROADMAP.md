# Sentinel ASI: mapa drogowa

Od 21.11.2026 projekt jest prowadzony pod oficjalny brief CBI AGH ([BRIEF.md](BRIEF.md)):
skaner discovery dużej infrastruktury z fingerprintingiem HTTP, sygnaturami, porównaniem
przebiegów, niestabilnymi hostami, czterema rolami, szyfrowaniem w spoczynku i DefectDojo.
Uzasadnienie i lista zmian: [ARCHITECTURE.md, sekcja 0](ARCHITECTURE.md#0-zmiana-kierunku-brief-agh).
Stan wymagań: [REQUIREMENTS.md](REQUIREMENTS.md). Pytania do mentorów: #42.

Funkcje spoza briefu nie dają punktów, więc czas dzielimy według wag kryteriów oceny: K1
discovery 30%, K2 jakość i DefectDojo 20%, K3 zmiany w czasie 15%, K4 bezpieczeństwo i
dashboard 15%, K5 fingerprinting i sygnatury 10%, K6 role i dane 10%.

## Plan etapów

Każdy etap na osobnej gałęzi z PR do `main`, CI zielone przed scaleniem. Po etapie: co
zrobione, jak przetestować, które wymagania z REQUIREMENTS.md zmieniły status.

Każdy etap od P2 dostaje też narzędzie agenta dla swojego modułu (propozycja, zatwierdzenie
przez `administrator` albo `editor`, wykonanie przez `mcp-scanner`), zgodnie z
[ARCHITECTURE.md §0.10](ARCHITECTURE.md#010-współpraca-z-agentem).

| Etap | Zakres | Wymagania | Kryt. | Issue |
|---|---|---|---|---|
| P0 | Analiza, macierz wymagań, plan (bez kodu) | wszystkie | – | – |
| P1 | Cztery role z briefu + `agent`, edytor ról, `docs/ROLES.md`, macierz testów rola × endpoint × akcja; usunięcie konsoli menedżera i modułów spoza briefu; przeniesienie przydatnych komponentów do konsoli zespołu IT | R12, R13, M12, V12 | K6 | #30 |
| P2 | Cele z formularza i plików CSV/JSON (jedna ścieżka), podgląd, deduplikacja; import wyników JSON/CSV (+ nmap XML); eksport JSON/CSV; warstwa nadpisań użytkownika; tagi | R1, R11, R14, M1, M2, M11, M13, N8, V11 | K2 | #31 |
| P3 | Discovery na skalę: paczki o rozmiarze z mierzonej szybkości, równoległe workery, limity tempa (globalne, per podsieć, pakiety/s), pomiar czasu i ETA, zapis przyrostowy, ICMP/TCP/ARP/UDP, timing ≤ T3; test > 10 000 IP i `docs/PERFORMANCE.md` | R2, R3, R4, M3, M5–M8, V1, V2, T1 | K1, K4 | #32 |
| P4 | Fingerprinting HTTP/HTTPS (nagłówki, ciasteczka, TLS, przekierowania, favicon, HTML), technologie i CMS-y z pewnością i dowodami, staging i panele (tylko GET/HEAD), ciekawe nagłówki i ciasteczka, grupowanie | R5, R6, R7, N5, N6, N7, V3, V4, V5 | K5, K1 | #33 |
| P5 | Porównanie dwóch przebiegów, stany hosta i usługi (aktywny, niestabilny, prawdopodobnie nieaktywny, nieaktywny), powtórzenia pomiaru, profil pory dnia, ocena ciekawości, wizualizacja zmian | R8, R9, M9, M10, N2, N3, N4, N10, V7, V8 | K3 | #34 |
| P6 | DefectDojo: profil Compose, konfiguracja w UI (token w OpenBao), eksport findingów „Info” i evidence z deduplikacją, nmap XML parserem DefectDojo, eksport automatyczny i ręczny, testy w CI | N9 | K2 | #35 |
| P7 | Własne sygnatury: YAML, walidator bezpieczeństwa (GET/HEAD), UI z testem na hoście, import/eksport, `docs/SIGNATURES.md` | R10, S1, V6 | K5 | #36 |
| P8 | Harmonogram: okna czasowe, częstotliwość, zatrzymanie na końcu okna z punktem kontrolnym, wznowienie | S2, M4, N1 | K1, K3 | #37 |
| P9 | Szyfrowanie pól wrażliwych (OpenBao Transit), HMAC do wyszukiwania, rotacja kluczy, test `pg_dump`, `docs/DATA_PROTECTION.md` | R16, M14 | K6 | #38 |
| P10 | Dashboard zespołu IT, raporty ze skanów (agent i Sentek, fakty z bazy, PDF i eksport), Sentek z intencjami discovery | R15, M10, V10 | K4, K3 | #39 |
| P11 | Testy AI w konsoli: test bezpieczeństwa agenta (moduł 19) i test wskazanego endpointu przez agenta (HTTP oraz API modelu z promptfoo, L3 ze zgodą) | D10 | K4 | #40 |
| P12 | Walidacja na środowisku organizatora (precyzja i czułość), `docs/VALIDATION.md`, `docs/SAFE_SCANNING.md`, `docs/PRESENTATION_OUTLINE.md`, DEMO_GUIDE pod scenariusz briefu | F2–F4, V1–V12 | K2 | #41 |

## Linia cięcia

**Nigdy nie tniemy:** discovery na skalę, fingerprinting HTTP, porównanie skanów, DefectDojo,
role, szyfrowanie, bezpieczeństwo skanera (scope_guard, limity tempa, audyt, kill switch).
Test bezpieczeństwa agenta (moduł 19) zostaje zawsze, bo już działa.

Gdy zabraknie czasu, odpada od dołu tej listy (pierwsza do odcięcia jest pozycja 7):

1. nmap XML eksportowany do DefectDojo parserem DefectDojo
2. Raporty agenta ze skanów
3. Test endpointu AI przez agenta (promptfoo, L3)
4. Sentek w konsoli zespołu IT
5. Grupowanie podobnych usług
6. Profil dostępności według pory dnia
7. Ocena „ciekawości” obserwacji

## Usunięte po zmianie kierunku

Te kierunki istnieją w historii Git (do scalenia PR #29 włącznie) i nie są dalej rozwijane:
konsola menedżera i rola `manager`, dane pracowników i pseudonimizacja, mapa organizacji z
działami, „Aktualny obraz” i prośby menedżera o skan, compliance prawny i frameworki (KSC, RODO,
KRI, ISO, NIST, AI Act), rejestr ryzyk governance, widok z zewnątrz (Artemis, moje.cert.pl),
film demo z lektorem, ogólne discovery systemów AI w infrastrukturze.

## Po hackathonie

### Skanowanie i skala

- Pipeline skanów przez `mcp-scanner` (#27): worker jako klient MCP z własną tożsamością,
  `worker-scans` bez dostępu do sieci celów.
- Rozproszone sondy skanujące w kilku segmentach sieci, sterowane centralnie (mTLS).
- IPv6, pasywny DNS i inne źródła pasywne, gdy zostaną udostępnione.
- Partycjonowanie tabel obserwacji i historii przy milionach rekordów.
- Przeniesienie gorących ścieżek przetwarzania do Go, jeśli pomiary z `docs/PERFORMANCE.md`
  to uzasadnią.

### Poświadczenia i agent

- Pełne odwołanie certyfikatów SSH przez listy KRL (dziś certyfikat wydany przed kill switchem
  działa do końca TTL 15 min).
- Auto-unseal OpenBao przez KMS albo HSM (dziś tylko tryb demo).
- Feedy OVAL dystrybucji Linuksa: backporty bez ręcznej weryfikacji.

### Tożsamość

- Federacja Keycloak z AD i Entra ID, synchronizacja grup na role.
- WebAuthn jako domyślne MFA.
- Osobna instancja PostgreSQL dla Keycloaka.

### Integracje

- Ticketing (Jira, GLPI), powiadomienia Slack i Teams.
- Dwukierunkowa synchronizacja statusów z DefectDojo.
- SecureCodeBox jako alternatywny wykonawca skanów w Kubernetes.

### AI

- Większy model lokalny na sprzęcie z GPU, wybierany tym samym eval.
- Testy MITRE ATLAS dla agentów z narzędziami.
