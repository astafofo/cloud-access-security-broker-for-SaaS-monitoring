"""
Celery configuration for background tasks.
"""

from celery import Celery
from .config import settings

# Create Celery app
celery_app = Celery(
    "casb",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.services.monitoring",
        "app.services.alerts",
        "app.services.dlp",
        "app.services.anomaly_detection"
    ]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)

# Configure periodic tasks
celery_app.conf.beat_schedule = {
    "monitor-saas-applications": {
        "task": "app.services.monitoring.monitor_saas_applications",
        "schedule": 60.0,  # Every minute
    },
    "check-policy-violations": {
        "task": "app.services.monitoring.check_policy_violations",
        "schedule": 30.0,  # Every 30 seconds
    },
    "run-anomaly-detection": {
        "task": "app.services.anomaly_detection.run_anomaly_detection",
        "schedule": 300.0,  # Every 5 minutes
    },
    "cleanup-old-logs": {
        "task": "app.services.monitoring.cleanup_old_logs",
        "schedule": 3600.0,  # Every hour
    },
}
