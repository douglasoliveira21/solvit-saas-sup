from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from .tenant_settings_views import TenantSettingsViewSet

router = DefaultRouter()
router.register(r'tenants', views.TenantViewSet)
router.register(r'tenant-users', views.TenantUserViewSet)
router.register(r'tenant-settings', TenantSettingsViewSet)
router.register(r'ad-config', views.ADConfigurationViewSet)
router.register(r'm365-config', views.M365ConfigurationViewSet)
router.register(r'users', views.ManagedUserViewSet)
router.register(r'groups', views.ManagedGroupViewSet)

urlpatterns = [
    path('', include(router.urls)),
]