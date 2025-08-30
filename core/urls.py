from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from .health import health_check, readiness_check, liveness_check

router = DefaultRouter()
router.register(r'audit-logs', views.AuditLogViewSet)
router.register(r'api-keys', views.APIKeyViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('health/', health_check, name='health-check'),
    path('health/readiness/', readiness_check, name='readiness-check'),
    path('health/liveness/', liveness_check, name='liveness-check'),
]