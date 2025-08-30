from rest_framework import serializers
from django.utils import timezone
from tenants.models import ADConfiguration, ManagedUser, ManagedGroup
from core.models import AuditLog


class AgentHeartbeatSerializer(serializers.Serializer):
    """
    Serializer para heartbeat do agente.
    """
    agent_version = serializers.CharField(max_length=50)
    status = serializers.ChoiceField(choices=['online', 'busy', 'error', 'offline'])
    last_sync = serializers.DateTimeField(required=False, allow_null=True)
    error_message = serializers.CharField(max_length=500, required=False, allow_blank=True)
    system_info = serializers.JSONField(required=False)
    
    def validate_system_info(self, value):
        """
        Valida informações do sistema.
        """
        if value is None:
            return {}
        
        # Campos esperados nas informações do sistema
        allowed_fields = [
            'hostname', 'os_version', 'python_version', 'memory_usage',
            'cpu_usage', 'disk_usage', 'network_status'
        ]
        
        # Filtra apenas campos permitidos
        filtered_info = {k: v for k, v in value.items() if k in allowed_fields}
        
        return filtered_info


class ADUserSyncSerializer(serializers.Serializer):
    """
    Serializer para sincronização de usuários do AD.
    """
    ad_object_guid = serializers.UUIDField()
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    display_name = serializers.CharField(max_length=300, required=False, allow_blank=True)
    is_active = serializers.BooleanField(default=True)
    ad_attributes = serializers.JSONField(required=False)
    
    def validate_username(self, value):
        """
        Valida se o username é único dentro do tenant.
        """
        tenant = self.context['tenant']
        
        # Verifica se já existe um usuário com este username no tenant
        existing_user = ManagedUser.objects.filter(
            tenant=tenant,
            username=value
        ).exclude(
            ad_object_guid=self.initial_data.get('ad_object_guid')
        ).first()
        
        if existing_user:
            raise serializers.ValidationError(
                f"Usuário com username '{value}' já existe no tenant."
            )
        
        return value
    
    def validate_email(self, value):
        """
        Valida se o email é único dentro do tenant.
        """
        tenant = self.context['tenant']
        
        # Verifica se já existe um usuário com este email no tenant
        existing_user = ManagedUser.objects.filter(
            tenant=tenant,
            email=value
        ).exclude(
            ad_object_guid=self.initial_data.get('ad_object_guid')
        ).first()
        
        if existing_user:
            raise serializers.ValidationError(
                f"Usuário com email '{value}' já existe no tenant."
            )
        
        return value


class ADGroupSyncSerializer(serializers.Serializer):
    """
    Serializer para sincronização de grupos do AD.
    """
    ad_object_guid = serializers.UUIDField()
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=500, required=False, allow_blank=True)
    group_type = serializers.ChoiceField(
        choices=['security', 'distribution'],
        default='security'
    )
    is_active = serializers.BooleanField(default=True)
    member_guids = serializers.ListField(
        child=serializers.UUIDField(),
        required=False,
        allow_empty=True
    )
    ad_attributes = serializers.JSONField(required=False)
    
    def validate_name(self, value):
        """
        Valida se o nome do grupo é único dentro do tenant.
        """
        tenant = self.context['tenant']
        
        # Verifica se já existe um grupo com este nome no tenant
        existing_group = ManagedGroup.objects.filter(
            tenant=tenant,
            name=value
        ).exclude(
            ad_object_guid=self.initial_data.get('ad_object_guid')
        ).first()
        
        if existing_group:
            raise serializers.ValidationError(
                f"Grupo com nome '{value}' já existe no tenant."
            )
        
        return value


class ADConfigurationResponseSerializer(serializers.ModelSerializer):
    """
    Serializer para resposta de configuração do AD (sem dados sensíveis).
    """
    
    class Meta:
        model = ADConfiguration
        fields = [
            'domain_controller', 'domain_name', 'base_dn',
            'service_account_username', 'users_ou', 'groups_ou',
            'sync_enabled', 'sync_interval_minutes'
        ]


class AgentLogSerializer(serializers.Serializer):
    """
    Serializer para logs enviados pelo agente.
    """
    level = serializers.ChoiceField(
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    )
    message = serializers.CharField(max_length=1000)
    timestamp = serializers.DateTimeField()
    module = serializers.CharField(max_length=100, required=False)
    function = serializers.CharField(max_length=100, required=False)
    line_number = serializers.IntegerField(required=False, allow_null=True)
    extra_data = serializers.JSONField(required=False)
    
    def validate_timestamp(self, value):
        """
        Valida se o timestamp não é muito antigo ou futuro.
        """
        now = timezone.now()
        
        # Não aceita logs com mais de 24 horas de diferença
        if abs((now - value).total_seconds()) > 86400:  # 24 horas
            raise serializers.ValidationError(
                "Timestamp do log está muito distante do horário atual."
            )
        
        return value


class SyncResultSerializer(serializers.Serializer):
    """
    Serializer para resultado de sincronização.
    """
    operation = serializers.ChoiceField(
        choices=['create', 'update', 'delete', 'sync']
    )
    resource_type = serializers.ChoiceField(
        choices=['user', 'group']
    )
    resource_id = serializers.CharField(max_length=255)
    success = serializers.BooleanField()
    message = serializers.CharField(max_length=500, required=False, allow_blank=True)
    details = serializers.JSONField(required=False)
    timestamp = serializers.DateTimeField(default=timezone.now)


class BulkSyncResultSerializer(serializers.Serializer):
    """
    Serializer para resultado de sincronização em lote.
    """
    sync_type = serializers.ChoiceField(
        choices=['users', 'groups', 'full']
    )
    total_processed = serializers.IntegerField(min_value=0)
    successful = serializers.IntegerField(min_value=0)
    failed = serializers.IntegerField(min_value=0)
    start_time = serializers.DateTimeField()
    end_time = serializers.DateTimeField()
    results = SyncResultSerializer(many=True, required=False)
    
    def validate(self, data):
        """
        Valida consistência dos dados.
        """
        if data['successful'] + data['failed'] != data['total_processed']:
            raise serializers.ValidationError(
                "A soma de sucessos e falhas deve ser igual ao total processado."
            )
        
        if data['start_time'] > data['end_time']:
            raise serializers.ValidationError(
                "Horário de início deve ser anterior ao horário de fim."
            )
        
        return data


class AgentStatusResponseSerializer(serializers.Serializer):
    """
    Serializer para resposta de status do agente.
    """
    agent_id = serializers.CharField()
    tenant_name = serializers.CharField()
    status = serializers.CharField()
    last_heartbeat = serializers.DateTimeField()
    configuration_updated = serializers.BooleanField()
    pending_tasks = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )
    message = serializers.CharField(required=False)