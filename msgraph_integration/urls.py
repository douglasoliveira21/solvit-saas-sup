from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import M365IntegrationViewSet

router = DefaultRouter()
router.register(r'm365', M365IntegrationViewSet, basename='m365-integration')

urlpatterns = [
    path('', include(router.urls)),
]