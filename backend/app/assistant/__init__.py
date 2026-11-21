"""Sentek: asystent konsoli zespołu IT (moduł 21, ARCHITECTURE §25.2).

Model lokalny tylko rozpoznaje intencję i parametry (JSON według schematu). Odpowiedź
buduje kod z danych w bazie, z tymi samymi uprawnieniami co reszta API. Sentek czyta
dane: nie skanuje sieci i nie zmienia ustawień. Prośbę o skan tylko proponuje, a składa
ją człowiek przyciskiem w konsoli (`scan:request`).
"""
