from rest_framework import serializers
from .models import (
    Tenant, TenantUser, AuditLog, SystemConfiguration, APIKey, 
    ManagedUser, ManagedGroup, GroupMembership, ADConfiguration, M365Configuration
)


class TenantSerializer(serializers.ModelSerializer):
    """Serializer para tenants"""
    
    class Meta:
        model = Tenant
        fields = [
            'id', 'name', 'slug', 'domain', 'contact_name', 'contact_email',
            'contact_phone', 'is_active', 'has_ad_integration', 'has_m365_integration',
            'settings', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class TenantUserSerializer(serializers.ModelSerializer):
    """Serializer para associações de usuários a tenants"""
    user_name = serializers.CharField(source='user.username', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    role_display = serializers.CharField(source='get_role_display', read_only=True)
    
    class Meta:
        model = TenantUser
        fields = [
            'id', 'tenant', 'tenant_name', 'user', 'user_name', 'user_email',
            'role', 'role_display', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer para logs de auditoria"""
    user_name = serializers.CharField(source='user.username', read_only=True)
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    resource_type_display = serializers.CharField(source='get_resource_type_display', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'user', 'user_name', 'tenant', 'tenant_name',
            'action', 'action_display', 'resource_type', 'resource_type_display',
            'resource_id', 'resource_name', 'description', 'ip_address',
            'user_agent', 'success', 'error_message', 'metadata',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class SystemConfigurationSerializer(serializers.ModelSerializer):
    """Serializer para configurações do sistema"""
    
    class Meta:
        model = SystemConfiguration
        fields = [
            'id', 'key', 'value', 'description', 'is_sensitive',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate_key(self, value):
        """Valida se a chave não contém espaços ou caracteres especiais"""
        if ' ' in value or not value.replace('_', '').replace('-', '').isalnum():
            raise serializers.ValidationError(
                "A chave deve conter apenas letras, números, hífens e underscores."
            )
        return value.upper()


class APIKeySerializer(serializers.ModelSerializer):
    """Serializer para chaves de API"""
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = APIKey
        fields = [
            'id', 'name', 'key', 'tenant', 'tenant_name', 'is_active',
            'last_used', 'expires_at', 'permissions', 'is_expired',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'key', 'last_used', 'created_at', 'updated_at']
        extra_kwargs = {
            'key': {'write_only': True}
        }
    
    def create(self, validated_data):
        """Gera uma chave única ao criar"""
        import secrets
        import string
        
        # Gera uma chave aleatória de 64 caracteres
        alphabet = string.ascii_letters + string.digits
        key = ''.join(secrets.choice(alphabet) for _ in range(64))
        
        validated_data['key'] = key
        return super().create(validated_data)


class CreateAuditLogSerializer(serializers.ModelSerializer):
    """Serializer para criação de logs de auditoria"""
    
    class Meta:
        model = AuditLog
        fields = [
            'action', 'resource_type', 'resource_id', 'resource_name',
            'description', 'success', 'error_message', 'metadata'
        ]
    
    def create(self, validated_data):
        """Adiciona informações do request ao criar o log"""
        request = self.context.get('request')
        if request:
            validated_data['user'] = request.user if request.user.is_authenticated else None
            validated_data['ip_address'] = self.get_client_ip(request)
            validated_data['user_agent'] = request.META.get('HTTP_USER_AGENT', '')
            
            # Tenta obter o tenant do usuário
            if hasattr(request.user, 'tenant'):
                validated_data['tenant'] = request.user.tenant
        
        return super().create(validated_data)
    
    def get_client_ip(self, request):
        """Obtém o IP real do cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class ManagedUserSerializer(serializers.ModelSerializer):
    """Serializer para usuários gerenciados"""
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    source_display = serializers.CharField(source='get_source_display', read_only=True)
    sync_status_display = serializers.CharField(source='get_sync_status_display', read_only=True)
    groups_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ManagedUser
        fields = [
            'id', 'tenant', 'tenant_name', 'username', 'email', 'first_name',
            'last_name', 'display_name', 'is_active', 'external_id', 'source',
            'source_display', 'last_synced_at', 'sync_enabled', 'sync_status',
            'sync_status_display', 'sync_error_message', 'groups_count',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'last_synced_at']
    
    def get_groups_count(self, obj):
        """Retorna o número de grupos do usuário"""
        return GroupMembership.objects.filter(user=obj).count()


class ManagedGroupSerializer(serializers.ModelSerializer):
    """Serializer para grupos gerenciados"""
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    source_display = serializers.CharField(source='get_source_display', read_only=True)
    sync_status_display = serializers.CharField(source='get_sync_status_display', read_only=True)
    group_type_display = serializers.CharField(source='get_group_type_display', read_only=True)
    members_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ManagedGroup
        fields = [
            'id', 'tenant', 'tenant_name', 'name', 'description', 'is_active',
            'external_id', 'source', 'source_display', 'group_type', 'group_type_display',
            'last_synced_at', 'sync_enabled', 'sync_status', 'sync_status_display',
            'sync_error_message', 'members_count', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'last_synced_at']
    
    def get_members_count(self, obj):
        """Retorna o número de membros do grupo"""
        return GroupMembership.objects.filter(group=obj).count()


class GroupMembershipSerializer(serializers.ModelSerializer):
    """Serializer para associações de usuários a grupos"""
    user_username = serializers.CharField(source='user.username', read_only=True)
    user_display_name = serializers.CharField(source='user.display_name', read_only=True)
    group_name = serializers.CharField(source='group.name', read_only=True)
    
    class Meta:
        model = GroupMembership
        fields = [
            'id', 'group', 'group_name', 'user', 'user_username', 'user_display_name',
            'added_at', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'added_at', 'created_at', 'updated_at']


class ADConfigurationSerializer(serializers.ModelSerializer):
    """Serializer para configurações do Active Directory"""
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    agent_status_display = serializers.CharField(source='get_agent_status_display', read_only=True)
    last_sync_status_display = serializers.CharField(source='get_last_sync_status_display', read_only=True)
    
    class Meta:
        model = ADConfiguration
        fields = [
            'id', 'tenant', 'tenant_name', 'domain_controller', 'domain_name',
            'base_dn', 'service_account_username', 'service_account_password',
            'sync_enabled', 'sync_interval_minutes', 'sync_users', 'sync_groups',
            'users_ou', 'groups_ou', 'agent_status', 'agent_status_display',
            'agent_last_seen', 'agent_version', 'last_sync_at', 'last_sync_status',
            'last_sync_status_display', 'last_sync_message', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'agent_last_seen', 'agent_version', 'last_sync_at', 
            'last_sync_status', 'last_sync_message', 'created_at', 'updated_at'
        ]
        extra_kwargs = {
            'service_account_password': {'write_only': True}
        }


class M365ConfigurationSerializer(serializers.ModelSerializer):
    """Serializer para configurações do Microsoft 365"""
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    last_sync_status_display = serializers.CharField(source='get_last_sync_status_display', read_only=True)
    
    class Meta:
        model = M365Configuration
        fields = [
            'id', 'tenant', 'tenant_name', 'azure_tenant_id', 'client_id',
            'client_secret', 'redirect_uri', 'sync_enabled', 'sync_interval_minutes',
            'sync_users', 'sync_groups', 'user_filter', 'group_filter',
            'last_sync_at', 'last_sync_status', 'last_sync_status_display',
            'last_sync_message', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'last_sync_at', 'last_sync_status', 'last_sync_message',
            'created_at', 'updated_at'
        ]
        extra_kwargs = {
            'client_secret': {'write_only': True}
        }