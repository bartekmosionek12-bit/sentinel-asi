# Przewodnik demo

Pokaz na żywo na scenariuszach z [DEMO.md](DEMO.md). Film demo z lektorem usunęliśmy przy
zmianie kierunku (21.11.2026); scenariusz prezentacji pod brief AGH powstaje w P12
([ROADMAP.md](ROADMAP.md)).

## Pokaz na żywo

1. `./scripts/seed_demo.sh`, potem `python3 scripts/check_demo.py http://localhost:8080`.
   Skrypt loguje się jak przeglądarka (Keycloak, hasło, TOTP) i sprawdza ścieżkę krytyczną,
   w tym Sentka, cztery role (odmowy 403 w audycie) i kolejkę akcji L2+ dla `editor`.
2. Scenariusze krok po kroku: [DEMO.md](DEMO.md) (zero-day, agent z certyfikatem SSH, cztery
   role i edytor ról, zatruty host i test agenta).
