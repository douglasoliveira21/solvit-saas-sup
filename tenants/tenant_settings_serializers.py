from rest_framework import serializers
from .tenant_settings import TenantSettings


class TenantSettingsSerializer(serializers.ModelSerializer):
    """Serializer para configurações de tenant"""
    
    password_policy = serializers.SerializerMethodField()
    lockout_policy = serializers.SerializerMethodField()
    audit_settings = serializers.SerializerMethodField()
    sync_settings = serializers.SerializerMethodField()
    notification_settings = serializers.SerializerMethodField()
    
    class Meta:
        model = TenantSettings
        fields = [
            'id', 'tenant', 'created_at', 'updated_at',
            # Configurações de Segurança
            'password_min_length', 'password_require_uppercase', 'password_require_lowercase',
            'password_require_numbers', 'password_require_special_chars', 'password_expiry_days',
            # Configurações de Bloqueio
            'account_lockout_enabled', 'account_lockout_threshold', 'account_lockout_duration_minutes',
            # Configurações de Sessão
            'session_timeout_minutes', 'max_concurrent_sessions',
            # Configurações de Auditoria
            'audit_log_retention_days', 'audit_failed_logins', 'audit_user_changes',
            'audit_group_changes', 'audit_permission_changes',
            # Configurações de Sincronização
            'sync_user_photos', 'sync_user_attributes', 'sync_group_attributes',
            'auto_create_users', 'auto_disable_users',
            # Configurações de Notificação
            'email_notifications_enabled', 'notify_user_creation', 'notify_user_deactivation',
            'notify_password_expiry', 'notify_sync_errors', 'notification_email_from',
            # Configurações de Interface
            'ui_theme', 'ui_language', 'ui_timezone',
            # Configurações de Limites
            'max_users_limit', 'max_groups_limit',
            # Configurações Customizadas
            'custom_settings',
            # Campos calculados
            'password_policy', 'lockout_policy', 'audit_settings', 'sync_settings', 'notification_settings'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'tenant']
    
    def get_password_policy(self, obj):
        """Retorna política de senhas agrupada"""
        return obj.get_password_policy()
    
    def get_lockout_policy(self, obj):
        """Retorna política de bloqueio agrupada"""
        return obj.get_lockout_policy()
    
    def get_audit_settings(self, obj):
        """Retorna configurações de auditoria agrupadas"""
        return obj.get_audit_settings()
    
    def get_sync_settings(self, obj):
        """Retorna configurações de sincronização agrupadas"""
        return obj.get_sync_settings()
    
    def get_notification_settings(self, obj):
        """Retorna configurações de notificação agrupadas"""
        return obj.get_notification_settings()
    
    def validate_sync_user_attributes(self, value):
        """Valida atributos de usuário para sincronização"""
        if not isinstance(value, list):
            raise serializers.ValidationError("Deve ser uma lista de atributos")
        
        valid_attributes = [
            'department', 'job_title', 'manager', 'office_location',
            'phone_number', 'mobile_phone', 'employee_id', 'cost_center'
        ]
        
        for attr in value:
            if attr not in valid_attributes:
                raise serializers.ValidationError(
                    f"Atributo '{attr}' não é válido. Atributos válidos: {', '.join(valid_attributes)}"
                )
        
        return value
    
    def validate_sync_group_attributes(self, value):
        """Valida atributos de grupo para sincronização"""
        if not isinstance(value, list):
            raise serializers.ValidationError("Deve ser uma lista de atributos")
        
        valid_attributes = [
            'description', 'email', 'owner', 'group_type', 'visibility'
        ]
        
        for attr in value:
            if attr not in valid_attributes:
                raise serializers.ValidationError(
                    f"Atributo '{attr}' não é válido. Atributos válidos: {', '.join(valid_attributes)}"
                )
        
        return value
    
    def validate_custom_settings(self, value):
        """Valida configurações customizadas"""
        if not isinstance(value, dict):
            raise serializers.ValidationError("Deve ser um objeto JSON válido")
        
        # Limita o tamanho das configurações customizadas
        if len(str(value)) > 10000:  # 10KB
            raise serializers.ValidationError("Configurações customizadas muito grandes (máximo 10KB)")
        
        return value
    
    def validate(self, attrs):
        """Validações gerais"""
        # Valida que o timeout de sessão não seja menor que 30 minutos
        if 'session_timeout_minutes' in attrs and attrs['session_timeout_minutes'] < 30:
            raise serializers.ValidationError({
                'session_timeout_minutes': 'Timeout de sessão deve ser pelo menos 30 minutos'
            })
        
        # Valida que o comprimento mínimo da senha seja razoável
        if 'password_min_length' in attrs and attrs['password_min_length'] < 6:
            raise serializers.ValidationError({
                'password_min_length': 'Comprimento mínimo da senha deve ser pelo menos 6 caracteres'
            })
        
        # Valida que o threshold de bloqueio seja razoável
        if 'account_lockout_threshold' in attrs and attrs['account_lockout_threshold'] < 3:
            raise serializers.ValidationError({
                'account_lockout_threshold': 'Threshold de bloqueio deve ser pelo menos 3 tentativas'
            })
        
        return attrs


class TenantSettingsUpdateSerializer(serializers.ModelSerializer):
    """Serializer simplificado para atualizações parciais"""
    
    class Meta:
        model = TenantSettings
        fields = [
            # Configurações de Segurança
            'password_min_length', 'password_require_uppercase', 'password_require_lowercase',
            'password_require_numbers', 'password_require_special_chars', 'password_expiry_days',
            # Configurações de Bloqueio
            'account_lockout_enabled', 'account_lockout_threshold', 'account_lockout_duration_minutes',
            # Configurações de Sessão
            'session_timeout_minutes', 'max_concurrent_sessions',
            # Configurações de Auditoria
            'audit_log_retention_days', 'audit_failed_logins', 'audit_user_changes',
            'audit_group_changes', 'audit_permission_changes',
            # Configurações de Sincronização
            'sync_user_photos', 'sync_user_attributes', 'sync_group_attributes',
            'auto_create_users', 'auto_disable_users',
            # Configurações de Notificação
            'email_notifications_enabled', 'notify_user_creation', 'notify_user_deactivation',
            'notify_password_expiry', 'notify_sync_errors', 'notification_email_from',
            # Configurações de Interface
            'ui_theme', 'ui_language', 'ui_timezone',
            # Configurações de Limites
            'max_users_limit', 'max_groups_limit',
            # Configurações Customizadas
            'custom_settings',
        ]
    
    def validate_sync_user_attributes(self, value):
        """Valida atributos de usuário para sincronização"""
        if not isinstance(value, list):
            raise serializers.ValidationError("Deve ser uma lista de atributos")
        
        valid_attributes = [
            'department', 'job_title', 'manager', 'office_location',
            'phone_number', 'mobile_phone', 'employee_id', 'cost_center'
        ]
        
        for attr in value:
            if attr not in valid_attributes:
                raise serializers.ValidationError(
                    f"Atributo '{attr}' não é válido. Atributos válidos: {', '.join(valid_attributes)}"
                )
        
        return value
    
    def validate_sync_group_attributes(self, value):
        """Valida atributos de grupo para sincronização"""
        if not isinstance(value, list):
            raise serializers.ValidationError("Deve ser uma lista de atributos")
        
        valid_attributes = [
            'description', 'email', 'owner', 'group_type', 'visibility'
        ]
        
        for attr in value:
            if attr not in valid_attributes:
                raise serializers.ValidationError(
                    f"Atributo '{attr}' não é válido. Atributos válidos: {', '.join(valid_attributes)}"
                )
        
        return value
    
    def validate_custom_settings(self, value):
        """Valida configurações customizadas"""
        if not isinstance(value, dict):
            raise serializers.ValidationError("Deve ser um objeto JSON válido")
        
        # Limita o tamanho das configurações customizadas
        if len(str(value)) > 10000:  # 10KB
            raise serializers.ValidationError("Configurações customizadas muito grandes (máximo 10KB)")
        
        return value