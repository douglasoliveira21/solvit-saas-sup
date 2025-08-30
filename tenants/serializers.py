from rest_framework import serializers
from .models import AuditLog, SystemConfiguration, APIKey


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