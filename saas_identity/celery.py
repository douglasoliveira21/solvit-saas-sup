import os
from celery import Celery

# Define o módulo de configurações padrão do Django para o programa 'celery'
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'saas_identity.settings')

app = Celery('saas_identity')

# Usando uma string aqui significa que o worker não precisa serializar
# o objeto de configuração para processos filhos.
# - namespace='CELERY' significa que todas as configurações relacionadas ao celery
#   devem ter um prefixo `CELERY_`.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Carrega módulos de tarefas de todos os apps Django registrados.
app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')