"""Celery: osobne kolejki, żeby wolne zadania nie blokowały szybkich.

* `scans`   aktywne skanowanie (jedyny worker w sieci z dostępem do celów)
* `feeds`   pobieranie feedów threat intelligence
* `llm`     inferencja, zawsze concurrency=1
* `default` planner, matching, scoring, powiadomienia
* `agent`   plan i wykonanie zadań agenta (klient MCP; bez dostępu do sieci celów)
* `agent_tests` niezależny test bezpieczeństwa agenta (moduł 19, osobny worker i użytkownik bazy)
"""

from __future__ import annotations

from celery import Celery
from celery.signals import setup_logging

from app.core.config import get_settings
from app.core.logging import configure_logging

QUEUES = ("default", "scans", "feeds", "llm", "agent", "agent_tests")

settings = get_settings()

celery_app = Celery("sentinel", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    task_default_queue="default",
    task_routes={
        "app.workers.tasks.scans.*": {"queue": "scans"},
        "app.workers.tasks.feeds.*": {"queue": "feeds"},
        "app.workers.tasks.llm.*": {"queue": "llm"},
        "app.workers.tasks.agent.*": {"queue": "agent"},
        "app.workers.tasks.agent_tests.*": {"queue": "agent_tests"},
    },
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    result_expires=3600,
    broker_connection_retry_on_startup=True,
    # Priorytety w Redisie: 0 = żądanie użytkownika na żywo, 5 = generowanie w tle.
    broker_transport_options={"priority_steps": [0, 5], "queue_order_strategy": "priority"},
    task_default_priority=5,
    imports=("app.workers.tasks",),
    beat_schedule={
        # Feedy co 6 godzin (offline: ponowne wczytanie snapshotu niczego nie zmienia).
        "sync-feeds": {"task": "app.workers.tasks.feeds.sync_feeds", "schedule": 6 * 3600.0},
        # Skan zakresu raz na dobę. Przy pustym zakresie nic się nie wykonuje.
        "scheduled-scan": {"task": "app.workers.tasks.scans.run_scan", "schedule": 24 * 3600.0},
        # Digest z powiadomień `delivery: digest` raz na dobę (Etap 6).
        "daily-digest": {"task": "app.workers.tasks.create_digest", "schedule": 24 * 3600.0},
        # Moduł 19: nocny pełny test bezpieczeństwa agenta na aktywnej konfiguracji.
        "agent-test-nightly": {
            "task": "app.workers.tasks.agent_tests.run_agent_test",
            "schedule": 24 * 3600.0,
            "kwargs": {"suite": "full", "trigger": "nightly", "requested_by": "system:beat"},
        },
    },
)


@setup_logging.connect
def _configure_logging(**_: object) -> None:
    configure_logging(settings.log_level)
