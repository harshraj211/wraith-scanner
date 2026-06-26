from celery import Celery
from celery.schedules import crontab
import os

app = Celery('wraith_scheduler', broker='redis://localhost:6379/0', backend='redis://localhost:6379/1')

# Configure the periodic schedule
app.conf.beat_schedule = {
    'weekly-dast-scan-prod': {
        'task': 'scanner.core.worker.run_dast_scan_task',
        'schedule': crontab(hour=2, minute=0, day_of_week='sunday'), # Runs every Sunday at 2 AM
        'args': ('https://prod.yourcompany.com', {'safety_mode': 'safe'}),
    },
    'daily-sast-scan-repo': {
        'task': 'scanner.core.worker.run_sast_scan_task',
        'schedule': crontab(hour=1, minute=0), # Runs every day at 1 AM
        'args': ('https://github.com/yourcompany/main-app',),
    },
}

# In production, you run this alongside the worker:
# celery -A scanner.core.scheduler beat --loglevel=info
