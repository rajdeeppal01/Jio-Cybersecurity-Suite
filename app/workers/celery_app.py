from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "jcs_tasks",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.workers.tasks_tier1",
        "app.workers.tasks_tier2",
        "app.workers.tasks_tier3",
        "app.workers.tasks_pentest",
    ]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "app.workers.tasks_tier1.*": {"queue": "tier1"},
        "app.workers.tasks_tier2.*": {"queue": "tier2"},
        "app.workers.tasks_tier3.*": {"queue": "tier3"},
        "app.workers.tasks_pentest.*": {"queue": "tier3"},
    }
)
