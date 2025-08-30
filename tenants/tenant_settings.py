from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from .models import Tenant, TimeStampedModel


class TenantSettings(TimeStampedModel):
    """Configurações específicas por tenant"""
    
    tenant = models.OneToOneField(
        Tenant, 
        on_delete=models.CASCADE, 
        related_name='tenant_settings'
    )
    
    # Configurações de Segurança
    password_min_length = models.PositiveIntegerField(
        default=8,
        validators=[MinValueValidator(6), MaxValueValidator(32)],
        help_text="Comprimento mínimo da senha"
    )
    password_require_uppercase = models.BooleanField(
        default=True,
        help_text="Exigir pelo menos uma letra maiúscula"
    )
    password_require_lowercase = models.BooleanField(
        default=True,
        help_text="Exigir pelo menos uma letra minúscula"
    )
    password_require_numbers = models.BooleanField(
        default=True,
        help_text="Exigir pelo menos um número"
    )
    password_require_special_chars = models.BooleanField(
        default=True,
        help_text="Exigir pelo menos um caractere especial"
    )
    password_expiry_days = models.PositiveIntegerField(
        default=90,
        validators=[MinValueValidator(0), MaxValueValidator(365)],
        help_text="Dias para expiração da senha (0 = nunca expira)"
    )
    
    # Configurações de Bloqueio de Conta
    account_lockout_enabled = models.BooleanField(
        default=True,
        help_text="Habilitar bloqueio de conta após tentativas falhadas"
    )
    account_lockout_threshold = models.PositiveIntegerField(
        default=5,
        validators=[MinValueValidator(3), MaxValueValidator(20)],
        help_text="Número de tentativas falhadas antes do bloqueio"
    )
    account_lockout_duration_minutes = models.PositiveIntegerField(
        default=30,
        validators=[MinValueValidator(5), MaxValueValidator(1440)],
        help_text="Duração do bloqueio em minutos"
    )
    
    # Configurações de Sessão
    session_timeout_minutes = models.PositiveIntegerField(
        default=480,  # 8 horas
        validators=[MinValueValidator(30), MaxValueValidator(1440)],
        help_text="Timeout da sessão em minutos"
    )
    max_concurrent_sessions = models.PositiveIntegerField(
        default=3,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
        help_text="Número máximo de sessões simultâneas por usuário"
    )
    
    # Configurações de Auditoria
    audit_log_retention_days = models.PositiveIntegerField(
        default=365,
        validators=[MinValueValidator(30), MaxValueValidator(2555)],  # 7 anos
        help_text="Dias para retenção dos logs de auditoria"
    )
    audit_failed_logins = models.BooleanField(
        default=True,
        help_text="Registrar tentativas de login falhadas"
    )
    audit_user_changes = models.BooleanField(
        default=True,
        help_text="Registrar alterações de usuários"
    )
    audit_group_changes = models.BooleanField(
        default=True,
        help_text="Registrar alterações de grupos"
    )
    audit_permission_changes = models.BooleanField(
        default=True,
        help_text="Registrar alterações de permissões"
    )
    
    # Configurações de Sincronização
    sync_user_photos = models.BooleanField(
        default=False,
        help_text="Sincronizar fotos de usuários do AD/M365"
    )
    sync_user_attributes = models.JSONField(
        default=list,
        blank=True,
        help_text="Lista de atributos de usuário para sincronizar"
    )
    sync_group_attributes = models.JSONField(
        default=list,
        blank=True,
        help_text="Lista de atributos de grupo para sincronizar"
    )
    auto_create_users = models.BooleanField(
        default=True,
        help_text="Criar automaticamente usuários durante sincronização"
    )
    auto_disable_users = models.BooleanField(
        default=True,
        help_text="Desabilitar automaticamente usuários removidos do AD/M365"
    )
    
    # Configurações de Notificação
    email_notifications_enabled = models.BooleanField(
        default=True,
        help_text="Habilitar notificações por email"
    )
    notify_user_creation = models.BooleanField(
        default=True,
        help_text="Notificar sobre criação de usuários"
    )
    notify_user_deactivation = models.BooleanField(
        default=True,
        help_text="Notificar sobre desativação de usuários"
    )
    notify_password_expiry = models.BooleanField(
        default=True,
        help_text="Notificar sobre expiração de senhas"
    )
    notify_sync_errors = models.BooleanField(
        default=True,
        help_text="Notificar sobre erros de sincronização"
    )
    notification_email_from = models.EmailField(
        blank=True,
        help_text="Email remetente para notificações (deixe vazio para usar padrão)"
    )
    
    # Configurações de Interface
    ui_theme = models.CharField(
        max_length=20,
        choices=[
            ('light', 'Claro'),
            ('dark', 'Escuro'),
            ('auto', 'Automático'),
        ],
        default='light',
        help_text="Tema da interface"
    )
    ui_language = models.CharField(
        max_length=10,
        choices=[
            ('pt-BR', 'Português (Brasil)'),
            ('en-US', 'English (US)'),
            ('es-ES', 'Español'),
        ],
        default='pt-BR',
        help_text="Idioma da interface"
    )
    ui_timezone = models.CharField(
        max_length=50,
        default='America/Sao_Paulo',
        help_text="Fuso horário para exibição de datas"
    )
    
    # Configurações de Limites
    max_users_limit = models.PositiveIntegerField(
        default=1000,
        validators=[MinValueValidator(1)],
        help_text="Limite máximo de usuários"
    )
    max_groups_limit = models.PositiveIntegerField(
        default=100,
        validators=[MinValueValidator(1)],
        help_text="Limite máximo de grupos"
    )
    
    # Configurações Customizadas (JSON flexível)
    custom_settings = models.JSONField(
        default=dict,
        blank=True,
        help_text="Configurações customizadas específicas do tenant"
    )
    
    class Meta:
        ordering = ['tenant__name']
        verbose_name = 'Configuração do Tenant'
        verbose_name_plural = 'Configurações dos Tenants'
    
    def __str__(self):
        return f"Configurações - {self.tenant.name}"
    
    def get_password_policy(self):
        """Retorna a política de senhas como dicionário"""
        return {
            'min_length': self.password_min_length,
            'require_uppercase': self.password_require_uppercase,
            'require_lowercase': self.password_require_lowercase,
            'require_numbers': self.password_require_numbers,
            'require_special_chars': self.password_require_special_chars,
            'expiry_days': self.password_expiry_days,
        }
    
    def get_lockout_policy(self):
        """Retorna a política de bloqueio como dicionário"""
        return {
            'enabled': self.account_lockout_enabled,
            'threshold': self.account_lockout_threshold,
            'duration_minutes': self.account_lockout_duration_minutes,
        }
    
    def get_audit_settings(self):
        """Retorna as configurações de auditoria como dicionário"""
        return {
            'retention_days': self.audit_log_retention_days,
            'log_failed_logins': self.audit_failed_logins,
            'log_user_changes': self.audit_user_changes,
            'log_group_changes': self.audit_group_changes,
            'log_permission_changes': self.audit_permission_changes,
        }
    
    def get_sync_settings(self):
        """Retorna as configurações de sincronização como dicionário"""
        return {
            'sync_user_photos': self.sync_user_photos,
            'sync_user_attributes': self.sync_user_attributes,
            'sync_group_attributes': self.sync_group_attributes,
            'auto_create_users': self.auto_create_users,
            'auto_disable_users': self.auto_disable_users,
        }
    
    def get_notification_settings(self):
        """Retorna as configurações de notificação como dicionário"""
        return {
            'enabled': self.email_notifications_enabled,
            'notify_user_creation': self.notify_user_creation,
            'notify_user_deactivation': self.notify_user_deactivation,
            'notify_password_expiry': self.notify_password_expiry,
            'notify_sync_errors': self.notify_sync_errors,
            'email_from': self.notification_email_from,
        }