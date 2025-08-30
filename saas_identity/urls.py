from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Authentication endpoints
    path('api/auth/', include('web_auth.urls')),
    
    # API endpoints
    path('api/tenants/', include('tenants.urls')),
    path('api/msgraph/', include('msgraph_integration.urls')),
    path('api/agent/', include('agent_api.urls')),
    path('api/core/', include('core.urls')),
]