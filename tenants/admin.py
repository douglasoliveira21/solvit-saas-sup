from django.contrib import admin
from .models import (
    Tenant, TenantUser, ADConfiguration, M365Configuration,
    ManagedUser, ManagedGroup
)


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'domain', 'is_active', 'has_ad_integration',
        'has_m365_integration', 'current_users_count', 'current_groups_count',
        'created_at'
    ]
    list_filter = [
        'is_active', 'has_ad_integration', 'has_m365_integration', 'created_at'
    ]
    search_fields = ['name', 'domain', 'contact_name', 'contact_email']
    readonly_fields = ['created_at', 'updated_at', 'current_users_count', 'current_groups_count']
    prepopulated_fields = {'slug': ('name',)}
    
    fieldsets = (
        ('Informações Básicas', {
            'fields': ('name', 'slug', 'domain', 'description', 'is_active')
        }),
        ('Limites', {
            'fields': ('max_users', 'max_groups')
        }),
        ('Integrações', {
            'fields': ('has_ad_integration', 'has_m365_integration')
        }),
        ('Contato', {
            'fields': ('contact_name', 'contact_email', 'contact_phone')
        }),
        ('Auditoria', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )


@admin.register(TenantUser)
class TenantUserAdmin(admin.ModelAdmin):
    list_display = ['user', 'tenant', 'role', 'is_active', 'created_at']
    list_filter = ['role', 'is_active', 'tenant', 'created_at']
    search_fields = ['user__username', 'user__email', 'tenant__name']
    readonly_fields = ['created_at', 'updated_at']
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'tenant')


@admin.register(ADConfiguration)
class ADConfigurationAdmin(admin.ModelAdmin):
    list_display = [
        'tenant', 'domain_name', 'sync_enabled', 'agent_status',
        'agent_last_heartbeat', 'created_at'
    ]
    list_filter = ['sync_enabled', 'agent_status', 'created_at']
    search_fields = ['tenant__name', 'domain_name', 'domain_controller']
    readonly_fields = [
        'created_at', 'updated_at', 'agent_last_heartbeat',
        'agent_version', 'agent_status', 'service_account_password_encrypted'
    ]
    
    fieldsets = (
        ('Tenant', {
            'fields': ('tenant',)
        }),
        ('Configurações de Conexão', {
            'fields': ('domain_controller', 'domain_name', 'base_dn')
        }),
        ('Credenciais', {
            'fields': ('service_account_username', 'service_account_password_encrypted'),
            'classes': ('collapse',)
        }),
        ('Sincronização', {
            'fields': ('users_ou', 'groups_ou', 'sync_enabled', 'sync_interval_minutes')
        }),
        ('Status do Agente', {
            'fields': ('agent_last_heartbeat', 'agent_version', 'agent_status'),
            'classes': ('collapse',)
        }),
        ('Auditoria', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if 'service_account_password_encrypted' in form.base_fields:
            form.base_fields['service_account_password_encrypted'].widget.attrs['type'] = 'password'
        return form


@admin.register(M365Configuration)
class M365ConfigurationAdmin(admin.ModelAdmin):
    list_display = [
        'tenant', 'client_id', 'sync_enabled', 'connection_status',
        'last_sync', 'created_at'
    ]
    list_filter = ['sync_enabled', 'connection_status', 'created_at']
    search_fields = ['tenant__name', 'client_id', 'tenant_id']
    readonly_fields = [
        'created_at', 'updated_at', 'last_sync', 'connection_status',
        'last_error', 'client_secret_encrypted'
    ]
    
    fieldsets = (
        ('Tenant', {
            'fields': ('tenant',)
        }),
        ('Configurações Azure AD', {
            'fields': ('client_id', 'client_secret_encrypted', 'tenant_id')
        }),
        ('Sincronização', {
            'fields': ('sync_enabled', 'sync_interval_minutes')
        }),
        ('Configurações de Usuário', {
            'fields': ('default_usage_location', 'default_password_profile')
        }),
        ('Status', {
            'fields': ('last_sync', 'connection_status', 'last_error'),
            'classes': ('collapse',)
        }),
        ('Auditoria', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if 'client_secret_encrypted' in form.base_fields:
            form.base_fields['client_secret_encrypted'].widget.attrs['type'] = 'password'
        return form


@admin.register(ManagedUser)
class ManagedUserAdmin(admin.ModelAdmin):
    list_display = [
        'display_name', 'username', 'email', 'tenant', 'is_active',
        'sync_status', 'created_at'
    ]
    list_filter = ['tenant', 'is_active', 'sync_status', 'created_at']
    search_fields = [
        'username', 'email', 'first_name', 'last_name',
        'display_name', 'tenant__name'
    ]
    readonly_fields = [
        'created_at', 'updated_at', 'ad_object_guid', 'm365_object_id',
        'last_ad_sync', 'last_m365_sync', 'sync_status'
    ]
    
    fieldsets = (
        ('Tenant', {
            'fields': ('tenant',)
        }),
        ('Informações Básicas', {
            'fields': ('username', 'email', 'first_name', 'last_name', 'display_name')
        }),
        ('Status', {
            'fields': ('is_active',)
        }),
        ('IDs Externos', {
            'fields': ('ad_object_guid', 'm365_object_id'),
            'classes': ('collapse',)
        }),
        ('Sincronização', {
            'fields': ('last_ad_sync', 'last_m365_sync', 'sync_status'),
            'classes': ('collapse',)
        }),
        ('Auditoria', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('tenant')


class ManagedGroupMembersInline(admin.TabularInline):
    model = ManagedGroup.members.through
    extra = 0
    verbose_name = "Membro"
    verbose_name_plural = "Membros"


@admin.register(ManagedGroup)
class ManagedGroupAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'tenant', 'group_type', 'is_active',
        'members_count', 'sync_status', 'created_at'
    ]
    list_filter = ['tenant', 'group_type', 'is_active', 'sync_status', 'created_at']
    search_fields = ['name', 'description', 'tenant__name']
    readonly_fields = [
        'created_at', 'updated_at', 'ad_object_guid', 'm365_object_id',
        'last_ad_sync', 'last_m365_sync', 'sync_status', 'members_count'
    ]
    filter_horizontal = ['members']
    
    fieldsets = (
        ('Tenant', {
            'fields': ('tenant',)
        }),
        ('Informações Básicas', {
            'fields': ('name', 'description', 'group_type')
        }),
        ('Status', {
            'fields': ('is_active',)
        }),
        ('Membros', {
            'fields': ('members',)
        }),
        ('IDs Externos', {
            'fields': ('ad_object_guid', 'm365_object_id'),
            'classes': ('collapse',)
        }),
        ('Sincronização', {
            'fields': ('last_ad_sync', 'last_m365_sync', 'sync_status'),
            'classes': ('collapse',)
        }),
        ('Auditoria', {
            'fields': ('created_at', 'updated_at', 'members_count'),
            'classes': ('collapse',)
        })
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('tenant')
    
    def formfield_for_manytomany(self, db_field, request, **kwargs):
        if db_field.name == "members":
            # Filtra apenas usuários do mesmo tenant se estivermos editando
            if request.resolver_match.kwargs.get('object_id'):
                try:
                    group_id = request.resolver_match.kwargs['object_id']
                    group = ManagedGroup.objects.get(id=group_id)
                    kwargs["queryset"] = ManagedUser.objects.filter(tenant=group.tenant)
                except ManagedGroup.DoesNotExist:
                    pass
        return super().formfield_for_manytomany(db_field, request, **kwargs)