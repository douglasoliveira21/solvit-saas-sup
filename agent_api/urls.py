from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    AgentHeartbeatView,
    AgentConfigurationView,
    AgentSyncViewSet,
    AgentLogsView
)

# Router para ViewSets
router = DefaultRouter()
router.register(r'sync', AgentSyncViewSet, basename='agent-sync')

urlpatterns = [
    # Endpoints específicos
    path('heartbeat/', AgentHeartbeatView.as_view(), name='agent-heartbeat'),
    path('config/', AgentConfigurationView.as_view(), name='agent-config'),
    path('logs/', AgentLogsView.as_view(), name='agent-logs'),
    
    # ViewSets via router
    path('', include(router.urls)),
]