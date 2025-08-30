from rest_framework import serializers
from django.contrib.auth.models import User
from .models import (
    Tenant, TenantUser, ADConfiguration, M365Configuration,
    ManagedUser, ManagedGroup
)


class TenantSerializer(serializers.ModelSerializer):
    """Serializer para Tenants"""
    current_users_count = serializers.ReadOnlyField()
    current_groups_count = serializers.ReadOnlyField()
    can_add_user = serializers.ReadOnlyField()
    can_add_group = serializers.ReadOnlyField()
    
    class Meta:
        model = Tenant
        fields = [
            'id', 'name', 'slug', 'domain', 'description', 'is_active',
            'max_users', 'max_groups', 'has_ad_integration', 'has_m365_integration',
            'contact_name', 'contact_email', 'contact_phone',
            'current_users_count', 'current_groups_count',
            'can_add_user', 'can_add_group', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate_slug(self, value):
        """Valida se o slug é único"""
        if self.instance:
            if Tenant.objects.exclude(id=self.instance.id).filter(slug=value).exists():
                raise serializers.ValidationError("Este slug já está em uso.")
        else:
            if Tenant.objects.filter(slug=value).exists():
                raise serializers.ValidationError("Este slug já está em uso.")
        return value
    
    def validate_domain(self, value):
        """Valida se o domínio é único"""
        if self.instance:
            if Tenant.objects.exclude(id=self.instance.id).filter(domain=value).exists():
                raise serializers.ValidationError("Este domínio já está em uso.")
        else:
            if Tenant.objects.filter(domain=value).exists():
                raise serializers.ValidationError("Este domínio já está em uso.")
        return value


class TenantUserSerializer(serializers.ModelSerializer):
    """Serializer para relacionamento usuário-tenant"""
    user_username = serializers.CharField(source='user.username', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_full_name = serializers.SerializerMethodField()
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    role_display = serializers.CharField(source='get_role_display', read_only=True)
    
    class Meta:
        model = TenantUser
        fields = [
            'id', 'user', 'user_username', 'user_email', 'user_full_name',
            'tenant', 'tenant_name', 'role', 'role_display', 'is_active',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_user_full_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip()


class ADConfigurationSerializer(serializers.ModelSerializer):
    """Serializer para configuração do Active Directory"""
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    is_agent_online = serializers.ReadOnlyField()
    service_account_password = serializers.CharField(write_only=True, required=False)
    agent_status_display = serializers.CharField(source='get_agent_status_display', read_only=True)
    
    class Meta:
        model = ADConfiguration
        fields = [
            'id', 'tenant', 'tenant_name', 'domain_controller', 'domain_name',
            'base_dn', 'service_account_username', 'service_account_password',
            'users_ou', 'groups_ou', 'sync_enabled', 'sync_interval_minutes',
            'agent_last_heartbeat', 'agent_version', 'agent_status',
            'agent_status_display', 'is_agent_online', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'agent_last_heartbeat', 'agent_version', 'agent_status',
            'created_at', 'updated_at'
        ]
        extra_kwargs = {
            'service_account_password_encrypted': {'write_only': True}
        }
    
    def create(self, validated_data):
        password = validated_data.pop('service_account_password', None)
        instance = super().create(validated_data)
        if password:
            instance.set_password(password)
            instance.save()
        return instance
    
    def update(self, instance, validated_data):
        password = validated_data.pop('service_account_password', None)
        instance = super().update(instance, validated_data)
        if password:
            instance.set_password(password)
            instance.save()
        return instance


class M365ConfigurationSerializer(serializers.ModelSerializer):
    """Serializer para configuração do Microsoft 365"""
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    client_secret = serializers.CharField(write_only=True, required=False)
    connection_status_display = serializers.CharField(source='get_connection_status_display', read_only=True)
    
    class Meta:
        model = M365Configuration
        fields = [
            'id', 'tenant', 'tenant_name', 'client_id', 'client_secret',
            'tenant_id', 'sync_enabled', 'sync_interval_minutes',
            'default_usage_location', 'default_password_profile',
            'last_sync', 'connection_status', 'connection_status_display',
            'last_error', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'last_sync', 'connection_status', 'last_error',
            'created_at', 'updated_at'
        ]
        extra_kwargs = {
            'client_secret_encrypted': {'write_only': True}
        }
    
    def create(self, validated_data):
        client_secret = validated_data.pop('client_secret', None)
        instance = super().create(validated_data)
        if client_secret:
            instance.set_client_secret(client_secret)
            instance.save()
        return instance
    
    def update(self, instance, validated_data):
        client_secret = validated_data.pop('client_secret', None)
        instance = super().update(instance, validated_data)
        if client_secret:
            instance.set_client_secret(client_secret)
            instance.save()
        return instance


class ManagedUserSerializer(serializers.ModelSerializer):
    """Serializer para usuários gerenciados"""
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    sync_status_display = serializers.CharField(source='get_sync_status_display', read_only=True)
    
    class Meta:
        model = ManagedUser
        fields = [
            'id', 'tenant', 'tenant_name', 'username', 'email',
            'first_name', 'last_name', 'display_name', 'is_active',
            'ad_object_guid', 'm365_object_id', 'last_ad_sync',
            'last_m365_sync', 'sync_status', 'sync_status_display',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'ad_object_guid', 'm365_object_id', 'last_ad_sync',
            'last_m365_sync', 'sync_status', 'created_at', 'updated_at'
        ]
    
    def validate(self, data):
        """Valida se o tenant pode adicionar mais usuários"""
        tenant = data.get('tenant')
        if tenant and not self.instance:  # Novo usuário
            if not tenant.can_add_user():
                raise serializers.ValidationError(
                    f"Limite de usuários atingido ({tenant.max_users})"
                )
        return data
    
    def validate_username(self, value):
        """Valida se o username é único no tenant"""
        tenant = self.initial_data.get('tenant') or (self.instance.tenant if self.instance else None)
        if tenant:
            queryset = ManagedUser.objects.filter(tenant=tenant, username=value)
            if self.instance:
                queryset = queryset.exclude(id=self.instance.id)
            if queryset.exists():
                raise serializers.ValidationError(
                    "Este nome de usuário já existe neste tenant."
                )
        return value
    
    def validate_email(self, value):
        """Valida se o email é único no tenant"""
        tenant = self.initial_data.get('tenant') or (self.instance.tenant if self.instance else None)
        if tenant:
            queryset = ManagedUser.objects.filter(tenant=tenant, email=value)
            if self.instance:
                queryset = queryset.exclude(id=self.instance.id)
            if queryset.exists():
                raise serializers.ValidationError(
                    "Este email já existe neste tenant."
                )
        return value


class ManagedGroupSerializer(serializers.ModelSerializer):
    """Serializer para grupos gerenciados"""
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    members_count = serializers.ReadOnlyField()
    group_type_display = serializers.CharField(source='get_group_type_display', read_only=True)
    sync_status_display = serializers.CharField(source='get_sync_status_display', read_only=True)
    
    class Meta:
        model = ManagedGroup
        fields = [
            'id', 'tenant', 'tenant_name', 'name', 'description',
            'group_type', 'group_type_display', 'is_active',
            'ad_object_guid', 'm365_object_id', 'members', 'members_count',
            'last_ad_sync', 'last_m365_sync', 'sync_status',
            'sync_status_display', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'ad_object_guid', 'm365_object_id', 'last_ad_sync',
            'last_m365_sync', 'sync_status', 'created_at', 'updated_at'
        ]
    
    def validate(self, data):
        """Valida se o tenant pode adicionar mais grupos"""
        tenant = data.get('tenant')
        if tenant and not self.instance:  # Novo grupo
            if not tenant.can_add_group():
                raise serializers.ValidationError(
                    f"Limite de grupos atingido ({tenant.max_groups})"
                )
        return data
    
    def validate_name(self, value):
        """Valida se o nome do grupo é único no tenant"""
        tenant = self.initial_data.get('tenant') or (self.instance.tenant if self.instance else None)
        if tenant:
            queryset = ManagedGroup.objects.filter(tenant=tenant, name=value)
            if self.instance:
                queryset = queryset.exclude(id=self.instance.id)
            if queryset.exists():
                raise serializers.ValidationError(
                    "Este nome de grupo já existe neste tenant."
                )
        return value


class ManagedGroupMembersSerializer(serializers.ModelSerializer):
    """Serializer para gerenciar membros de grupos"""
    members = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=ManagedUser.objects.all()
    )
    
    class Meta:
        model = ManagedGroup
        fields = ['id', 'members']
    
    def validate_members(self, value):
        """Valida se todos os membros pertencem ao mesmo tenant do grupo"""
        if self.instance:
            for user in value:
                if user.tenant != self.instance.tenant:
                    raise serializers.ValidationError(
                        f"O usuário {user.username} não pertence ao mesmo tenant do grupo."
                    )
        return value