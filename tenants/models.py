from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import RegexValidator


class TimeStampedModel(models.Model):
    """Modelo base com campos de timestamp"""
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True


class AuditLog(TimeStampedModel):
    """Log de auditoria para todas as operações do sistema"""
    ACTION_CHOICES = [
        ('CREATE', 'Criar'),
        ('UPDATE', 'Atualizar'),
        ('DELETE', 'Deletar'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('SYNC', 'Sincronização'),
        ('ERROR', 'Erro'),
    ]
    
    RESOURCE_CHOICES = [
        ('USER', 'Usuário'),
        ('GROUP', 'Grupo'),
        ('TENANT', 'Tenant'),
        ('AGENT', 'Agente'),
        ('SYSTEM', 'Sistema'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='tenants_auditlog_set')
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, null=True, blank=True, related_name='tenants_auditlog_set')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    resource_type = models.CharField(max_length=20, choices=RESOURCE_CHOICES)
    resource_id = models.CharField(max_length=255, null=True, blank=True)
    resource_name = models.CharField(max_length=255, null=True, blank=True)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    success = models.BooleanField(default=True)
    error_message = models.TextField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['tenant', 'action']),
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['created_at']),
            models.Index(fields=['user']),
        ]
    
    def __str__(self):
        return f"{self.action} {self.resource_type} - {self.created_at}"


class SystemConfiguration(TimeStampedModel):
    """Configurações globais do sistema"""
    key = models.CharField(max_length=255, unique=True)
    value = models.TextField()
    description = models.TextField(blank=True)
    is_sensitive = models.BooleanField(default=False)  # Para senhas e chaves
    
    class Meta:
        ordering = ['key']
    
    def __str__(self):
        return self.key


class APIKey(TimeStampedModel):
    """Chaves de API para autenticação de agentes"""
    name = models.CharField(max_length=255)
    key = models.CharField(max_length=255, unique=True)
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='tenants_apikey_set')
    is_active = models.BooleanField(default=True)
    last_used = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    permissions = models.JSONField(default=list)  # Lista de permissões
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} - {self.tenant.name}"
    
    def is_expired(self):
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False
    
    def update_last_used(self):
        self.last_used = timezone.now()
        self.save(update_fields=['last_used'])


class Tenant(TimeStampedModel):
    """Modelo para representar um tenant (organização)"""
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255, unique=True)
    domain = models.CharField(max_length=255, blank=True)
    contact_name = models.CharField(max_length=255, blank=True)
    contact_email = models.EmailField(blank=True)
    contact_phone = models.CharField(max_length=20, blank=True)
    is_active = models.BooleanField(default=True)
    
    # Configurações de integração
    has_ad_integration = models.BooleanField(default=False)
    has_m365_integration = models.BooleanField(default=False)
    
    # Configurações
    settings = models.JSONField(default=dict, blank=True)
    
    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return self.name


class M365Configuration(TimeStampedModel):
    """Configuração de integração com Microsoft 365"""
    tenant = models.OneToOneField(Tenant, on_delete=models.CASCADE, related_name='m365_config')
    azure_tenant_id = models.CharField(max_length=255, help_text="Azure AD Tenant ID")
    client_id = models.CharField(max_length=255, help_text="Application (client) ID")
    client_secret = models.CharField(max_length=500, help_text="Client secret")
    redirect_uri = models.URLField(help_text="Redirect URI configurado no Azure AD")
    
    # Configurações de sincronização
    sync_enabled = models.BooleanField(default=False)
    sync_interval_minutes = models.PositiveIntegerField(default=60)
    sync_users = models.BooleanField(default=True)
    sync_groups = models.BooleanField(default=True)
    
    # Filtros de sincronização
    user_filter = models.TextField(blank=True, help_text="Filtro OData para usuários")
    group_filter = models.TextField(blank=True, help_text="Filtro OData para grupos")
    
    # Status da última sincronização
    last_sync_at = models.DateTimeField(null=True, blank=True)
    last_sync_status = models.CharField(max_length=20, choices=[
        ('SUCCESS', 'Sucesso'),
        ('ERROR', 'Erro'),
        ('RUNNING', 'Executando'),
    ], null=True, blank=True)
    last_sync_message = models.TextField(blank=True)
    
    class Meta:
        ordering = ['tenant__name']
    
    def __str__(self):
        return f"M365 Config - {self.tenant.name}"


class ADConfiguration(TimeStampedModel):
    """Configuração de integração com Active Directory local"""
    tenant = models.OneToOneField(Tenant, on_delete=models.CASCADE, related_name='ad_config')
    domain_controller = models.CharField(max_length=255, help_text="Endereço do Domain Controller")
    domain_name = models.CharField(max_length=255, help_text="Nome do domínio AD")
    base_dn = models.CharField(max_length=500, help_text="Base DN para pesquisas LDAP")
    service_account_username = models.CharField(max_length=255, help_text="Usuário de serviço para conexão")
    service_account_password = models.CharField(max_length=500, help_text="Senha do usuário de serviço")
    
    # Configurações de sincronização
    sync_enabled = models.BooleanField(default=False)
    sync_interval_minutes = models.PositiveIntegerField(default=60)
    sync_users = models.BooleanField(default=True)
    sync_groups = models.BooleanField(default=True)
    
    # OUs para sincronização
    users_ou = models.CharField(max_length=500, blank=True, help_text="OU dos usuários")
    groups_ou = models.CharField(max_length=500, blank=True, help_text="OU dos grupos")
    
    # Status do agente
    agent_status = models.CharField(max_length=20, choices=[
        ('OFFLINE', 'Offline'),
        ('ONLINE', 'Online'),
        ('ERROR', 'Erro'),
        ('SYNCING', 'Sincronizando'),
    ], default='OFFLINE')
    agent_last_seen = models.DateTimeField(null=True, blank=True)
    agent_version = models.CharField(max_length=50, blank=True)
    
    # Status da última sincronização
    last_sync_at = models.DateTimeField(null=True, blank=True)
    last_sync_status = models.CharField(max_length=20, choices=[
        ('SUCCESS', 'Sucesso'),
        ('ERROR', 'Erro'),
        ('RUNNING', 'Executando'),
    ], null=True, blank=True)
    last_sync_message = models.TextField(blank=True)
    
    class Meta:
        ordering = ['tenant__name']
    
    def __str__(self):
        return f"AD Config - {self.tenant.name}"


class ManagedUser(TimeStampedModel):
    """Usuários sincronizados do Microsoft 365 ou AD local"""
    SOURCE_CHOICES = [
        ('M365', 'Microsoft 365'),
        ('AD', 'Active Directory Local'),
        ('MANUAL', 'Criado Manualmente'),
    ]
    
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='managed_users')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='managed_profiles')
    
    # Identificadores externos
    external_id = models.CharField(max_length=255, blank=True, help_text="ID no sistema externo")
    source = models.CharField(max_length=10, choices=SOURCE_CHOICES, default='MANUAL')
    
    # Dados de sincronização
    last_synced_at = models.DateTimeField(null=True, blank=True)
    sync_enabled = models.BooleanField(default=True)
    
    # Metadados do usuário
    department = models.CharField(max_length=255, blank=True)
    job_title = models.CharField(max_length=255, blank=True)
    manager_email = models.EmailField(blank=True)
    office_location = models.CharField(max_length=255, blank=True)
    
    class Meta:
        unique_together = ['tenant', 'user']
        ordering = ['user__username']
        indexes = [
            models.Index(fields=['tenant', 'source']),
            models.Index(fields=['external_id']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.tenant.name} ({self.source})"


class ManagedGroup(TimeStampedModel):
    """Grupos sincronizados do Microsoft 365 ou AD local"""
    SOURCE_CHOICES = [
        ('M365', 'Microsoft 365'),
        ('AD', 'Active Directory Local'),
        ('MANUAL', 'Criado Manualmente'),
    ]
    
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='managed_groups')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    
    # Identificadores externos
    external_id = models.CharField(max_length=255, blank=True, help_text="ID no sistema externo")
    source = models.CharField(max_length=10, choices=SOURCE_CHOICES, default='MANUAL')
    
    # Dados de sincronização
    last_synced_at = models.DateTimeField(null=True, blank=True)
    sync_enabled = models.BooleanField(default=True)
    
    # Membros do grupo
    members = models.ManyToManyField(ManagedUser, through='GroupMembership', related_name='groups')
    
    class Meta:
        unique_together = ['tenant', 'name']
        ordering = ['name']
        indexes = [
            models.Index(fields=['tenant', 'source']),
            models.Index(fields=['external_id']),
        ]
    
    def __str__(self):
        return f"{self.name} - {self.tenant.name} ({self.source})"


class GroupMembership(TimeStampedModel):
    """Relacionamento entre usuários e grupos"""
    group = models.ForeignKey(ManagedGroup, on_delete=models.CASCADE)
    user = models.ForeignKey(ManagedUser, on_delete=models.CASCADE)
    
    # Dados de sincronização
    last_synced_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ['group', 'user']
        ordering = ['group__name', 'user__user__username']
    
    def __str__(self):
        return f"{self.user.user.username} in {self.group.name}"


class TenantUser(TimeStampedModel):
    """Relacionamento entre usuários e tenants com roles"""
    ROLE_CHOICES = [
        ('ADMIN', 'Administrador'),
        ('OPERATOR', 'Operador'),
        ('USER', 'Usuário'),
    ]
    
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='tenant_users')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tenant_users')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='USER')
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['tenant', 'user']
        ordering = ['tenant', 'user__username']
        indexes = [
            models.Index(fields=['tenant', 'is_active']),
            models.Index(fields=['user', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.tenant.name} ({self.role})"