from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'm365', views.M365IntegrationViewSet, basename='m365-integration')

urlpatterns = [
    path('', include(router.urls)),
]