from django.contrib import admin
from .models import AuditLog, SystemConfiguration, APIKey


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = [
        'created_at', 'user', 'tenant', 'action', 'resource_type',
        'resource_name', 'success', 'ip_address'
    ]
    list_filter = [
        'action', 'resource_type', 'success', 'created_at', 'tenant'
    ]
    search_fields = [
        'user__username', 'resource_name', 'description', 'ip_address'
    ]
    readonly_fields = [
        'created_at', 'updated_at', 'user', 'tenant', 'action',
        'resource_type', 'resource_id', 'resource_name', 'description',
        'ip_address', 'user_agent', 'success', 'error_message', 'metadata'
    ]
    ordering = ['-created_at']
    date_hierarchy = 'created_at'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser


@admin.register(SystemConfiguration)
class SystemConfigurationAdmin(admin.ModelAdmin):
    list_display = ['key', 'description', 'is_sensitive', 'created_at', 'updated_at']
    list_filter = ['is_sensitive', 'created_at']
    search_fields = ['key', 'description']
    readonly_fields = ['created_at', 'updated_at']
    ordering = ['key']
    
    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if obj and obj.is_sensitive:
            form.base_fields['value'].widget.attrs['type'] = 'password'
        return form


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'tenant', 'is_active', 'last_used', 'expires_at', 'created_at'
    ]
    list_filter = ['is_active', 'tenant', 'created_at', 'expires_at']
    search_fields = ['name', 'tenant__name']
    readonly_fields = ['key', 'last_used', 'created_at', 'updated_at']
    ordering = ['-created_at']
    
    fieldsets = (
        ('Informações Básicas', {
            'fields': ('name', 'tenant', 'is_active')
        }),
        ('Chave de API', {
            'fields': ('key',),
            'classes': ('collapse',)
        }),
        ('Configurações', {
            'fields': ('expires_at', 'permissions')
        }),
        ('Auditoria', {
            'fields': ('last_used', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def save_model(self, request, obj, form, change):
        if not change:  # Novo objeto
            import secrets
            import string
            alphabet = string.ascii_letters + string.digits
            obj.key = ''.join(secrets.choice(alphabet) for _ in range(64))
        super().save_model(request, obj, form, change)