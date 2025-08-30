from django.db import models
from django.contrib.auth.models import User
from core.models import TimeStampedModel
from cryptography.fernet import Fernet
from django.conf import settings
import base64


class Tenant(TimeStampedModel):
    """Modelo para representar um cliente/tenant do SaaS"""
    name = models.CharField(max_length=255, verbose_name="Nome")
    slug = models.SlugField(max_length=255, unique=True, verbose_name="Slug")
    domain = models.CharField(max_length=255, unique=True, verbose_name="Domínio")
    description = models.TextField(blank=True, verbose_name="Descrição")
    is_active = models.BooleanField(default=True, verbose_name="Ativo")
    
    # Configurações de limite
    max_users = models.PositiveIntegerField(default=100, verbose_name="Máximo de usuários")
    max_groups = models.PositiveIntegerField(default=50, verbose_name="Máximo de grupos")
    
    # Configurações de integração
    has_ad_integration = models.BooleanField(default=False, verbose_name="Integração com AD")
    has_m365_integration = models.BooleanField(default=False, verbose_name="Integração com M365")
    
    # Configurações de contato
    contact_name = models.CharField(max_length=255, blank=True, verbose_name="Nome do contato")
    contact_email = models.EmailField(blank=True, verbose_name="Email do contato")
    contact_phone = models.CharField(max_length=20, blank=True, verbose_name="Telefone do contato")
    
    class Meta:
        ordering = ['name']
        verbose_name = "Tenant"
        verbose_name_plural = "Tenants"
    
    def __str__(self):
        return self.name
    
    @property
    def current_users_count(self):
        """Retorna o número atual de usuários gerenciados"""
        return self.managed_users.count()
    
    @property
    def current_groups_count(self):
        """Retorna o número atual de grupos gerenciados"""
        return self.managed_groups.count()
    
    def can_add_user(self):
        """Verifica se pode adicionar mais usuários"""
        return self.current_users_count < self.max_users
    
    def can_add_group(self):
        """Verifica se pode adicionar mais grupos"""
        return self.current_groups_count < self.max_groups


class TenantUser(TimeStampedModel):
    """Relacionamento entre usuários do sistema e tenants"""
    ROLE_CHOICES = [
        ('ADMIN', 'Administrador'),
        ('OPERATOR', 'Operador'),
        ('VIEWER', 'Visualizador'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tenant_memberships')
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='user_memberships')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='VIEWER')
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['user', 'tenant']
        ordering = ['tenant', 'user']
    
    def __str__(self):
        return f"{self.user.username} - {self.tenant.name} ({self.role})"


class ADConfiguration(TimeStampedModel):
    """Configurações para integração com Active Directory"""
    tenant = models.OneToOneField(Tenant, on_delete=models.CASCADE, related_name='ad_config')
    
    # Configurações de conexão
    domain_controller = models.CharField(max_length=255, verbose_name="Controlador de Domínio")
    domain_name = models.CharField(max_length=255, verbose_name="Nome do Domínio")
    base_dn = models.CharField(max_length=500, verbose_name="Base DN")
    
    # Credenciais (criptografadas)
    service_account_username = models.CharField(max_length=255, verbose_name="Usuário de Serviço")
    service_account_password_encrypted = models.TextField(verbose_name="Senha Criptografada")
    
    # Configurações de sincronização
    users_ou = models.CharField(max_length=500, blank=True, verbose_name="OU de Usuários")
    groups_ou = models.CharField(max_length=500, blank=True, verbose_name="OU de Grupos")
    sync_enabled = models.BooleanField(default=True, verbose_name="Sincronização Habilitada")
    sync_interval_minutes = models.PositiveIntegerField(default=60, verbose_name="Intervalo de Sincronização (min)")
    
    # Status do agente
    agent_last_heartbeat = models.DateTimeField(null=True, blank=True, verbose_name="Último Heartbeat")
    agent_version = models.CharField(max_length=50, blank=True, verbose_name="Versão do Agente")
    agent_status = models.CharField(
        max_length=20,
        choices=[
            ('ONLINE', 'Online'),
            ('OFFLINE', 'Offline'),
            ('ERROR', 'Erro'),
            ('UNKNOWN', 'Desconhecido'),
        ],
        default='UNKNOWN',
        verbose_name="Status do Agente"
    )
    
    class Meta:
        verbose_name = "Configuração AD"
        verbose_name_plural = "Configurações AD"
    
    def __str__(self):
        return f"AD Config - {self.tenant.name}"
    
    def set_password(self, password):
        """Criptografa e armazena a senha"""
        key = base64.urlsafe_b64encode(settings.SECRET_KEY[:32].encode())
        f = Fernet(key)
        self.service_account_password_encrypted = f.encrypt(password.encode()).decode()
    
    def get_password(self):
        """Descriptografa e retorna a senha"""
        if not self.service_account_password_encrypted:
            return None
        key = base64.urlsafe_b64encode(settings.SECRET_KEY[:32].encode())
        f = Fernet(key)
        return f.decrypt(self.service_account_password_encrypted.encode()).decode()
    
    @property
    def is_agent_online(self):
        """Verifica se o agente está online baseado no último heartbeat"""
        if not self.agent_last_heartbeat:
            return False
        from django.utils import timezone
        from datetime import timedelta
        return timezone.now() - self.agent_last_heartbeat < timedelta(minutes=5)


class M365Configuration(TimeStampedModel):
    """Configurações para integração com Microsoft 365"""
    tenant = models.OneToOneField(Tenant, on_delete=models.CASCADE, related_name='m365_config')
    
    # Configurações da aplicação Azure AD
    client_id = models.CharField(max_length=255, verbose_name="Client ID")
    client_secret_encrypted = models.TextField(verbose_name="Client Secret Criptografado")
    tenant_id = models.CharField(max_length=255, verbose_name="Tenant ID")
    
    # Configurações de sincronização
    sync_enabled = models.BooleanField(default=True, verbose_name="Sincronização Habilitada")
    sync_interval_minutes = models.PositiveIntegerField(default=30, verbose_name="Intervalo de Sincronização (min)")
    
    # Configurações de usuário
    default_usage_location = models.CharField(
        max_length=2, 
        default='BR', 
        verbose_name="Localização Padrão",
        help_text="Código de país de 2 letras (ex: BR, US)"
    )
    default_password_profile = models.JSONField(
        default=dict,
        verbose_name="Perfil de Senha Padrão",
        help_text="Configurações padrão para senhas de novos usuários"
    )
    
    # Status da conexão
    last_sync = models.DateTimeField(null=True, blank=True, verbose_name="Última Sincronização")
    connection_status = models.CharField(
        max_length=20,
        choices=[
            ('CONNECTED', 'Conectado'),
            ('DISCONNECTED', 'Desconectado'),
            ('ERROR', 'Erro'),
            ('TESTING', 'Testando'),
        ],
        default='DISCONNECTED',
        verbose_name="Status da Conexão"
    )
    last_error = models.TextField(blank=True, verbose_name="Último Erro")
    
    class Meta:
        verbose_name = "Configuração M365"
        verbose_name_plural = "Configurações M365"
    
    def __str__(self):
        return f"M365 Config - {self.tenant.name}"
    
    def set_client_secret(self, secret):
        """Criptografa e armazena o client secret"""
        key = base64.urlsafe_b64encode(settings.SECRET_KEY[:32].encode())
        f = Fernet(key)
        self.client_secret_encrypted = f.encrypt(secret.encode()).decode()
    
    def get_client_secret(self):
        """Descriptografa e retorna o client secret"""
        if not self.client_secret_encrypted:
            return None
        key = base64.urlsafe_b64encode(settings.SECRET_KEY[:32].encode())
        f = Fernet(key)
        return f.decrypt(self.client_secret_encrypted.encode()).decode()
    
    def save(self, *args, **kwargs):
        """Configura perfil de senha padrão se não existir"""
        if not self.default_password_profile:
            self.default_password_profile = {
                'forceChangePasswordNextSignIn': True,
                'forceChangePasswordNextSignInWithMfa': False
            }
        super().save(*args, **kwargs)


class ManagedUser(TimeStampedModel):
    """Usuários gerenciados pelo sistema"""
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='managed_users')
    
    # Informações básicas
    username = models.CharField(max_length=255, verbose_name="Nome de usuário")
    email = models.EmailField(verbose_name="Email")
    first_name = models.CharField(max_length=255, verbose_name="Nome")
    last_name = models.CharField(max_length=255, verbose_name="Sobrenome")
    display_name = models.CharField(max_length=255, verbose_name="Nome de exibição")
    
    # Status
    is_active = models.BooleanField(default=True, verbose_name="Ativo")
    
    # IDs externos
    ad_object_guid = models.CharField(max_length=255, blank=True, verbose_name="GUID do AD")
    m365_object_id = models.CharField(max_length=255, blank=True, verbose_name="ID do M365")
    
    # Sincronização
    last_ad_sync = models.DateTimeField(null=True, blank=True, verbose_name="Última Sync AD")
    last_m365_sync = models.DateTimeField(null=True, blank=True, verbose_name="Última Sync M365")
    sync_status = models.CharField(
        max_length=20,
        choices=[
            ('SYNCED', 'Sincronizado'),
            ('PENDING', 'Pendente'),
            ('ERROR', 'Erro'),
            ('MANUAL', 'Manual'),
        ],
        default='PENDING',
        verbose_name="Status de Sincronização"
    )
    
    class Meta:
        unique_together = [['tenant', 'username'], ['tenant', 'email']]
        ordering = ['tenant', 'display_name']
        verbose_name = "Usuário Gerenciado"
        verbose_name_plural = "Usuários Gerenciados"
    
    def __str__(self):
        return f"{self.display_name} ({self.tenant.name})"


class ManagedGroup(TimeStampedModel):
    """Grupos gerenciados pelo sistema"""
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='managed_groups')
    
    # Informações básicas
    name = models.CharField(max_length=255, verbose_name="Nome")
    description = models.TextField(blank=True, verbose_name="Descrição")
    
    # Tipo de grupo
    group_type = models.CharField(
        max_length=20,
        choices=[
            ('SECURITY', 'Segurança'),
            ('DISTRIBUTION', 'Distribuição'),
            ('M365', 'Microsoft 365'),
        ],
        default='SECURITY',
        verbose_name="Tipo de Grupo"
    )
    
    # Status
    is_active = models.BooleanField(default=True, verbose_name="Ativo")
    
    # IDs externos
    ad_object_guid = models.CharField(max_length=255, blank=True, verbose_name="GUID do AD")
    m365_object_id = models.CharField(max_length=255, blank=True, verbose_name="ID do M365")
    
    # Membros
    members = models.ManyToManyField(ManagedUser, blank=True, verbose_name="Membros")
    
    # Sincronização
    last_ad_sync = models.DateTimeField(null=True, blank=True, verbose_name="Última Sync AD")
    last_m365_sync = models.DateTimeField(null=True, blank=True, verbose_name="Última Sync M365")
    sync_status = models.CharField(
        max_length=20,
        choices=[
            ('SYNCED', 'Sincronizado'),
            ('PENDING', 'Pendente'),
            ('ERROR', 'Erro'),
            ('MANUAL', 'Manual'),
        ],
        default='PENDING',
        verbose_name="Status de Sincronização"
    )
    
    class Meta:
        unique_together = ['tenant', 'name']
        ordering = ['tenant', 'name']
        verbose_name = "Grupo Gerenciado"
        verbose_name_plural = "Grupos Gerenciados"
    
    def __str__(self):
        return f"{self.name} ({self.tenant.name})"
    
    @property
    def members_count(self):
        """Retorna o número de membros do grupo"""
        return self.members.count()