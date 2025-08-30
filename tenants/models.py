from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


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
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, null=True, blank=True)
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
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE)
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