# Isso garantirá que o app seja sempre importado quando
# o Django iniciar para que shared_task use este app.
from .celery import app as celery_app

__all__ = ('celery_app',)