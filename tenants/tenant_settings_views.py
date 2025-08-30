from rest_framework import viewsets, status, permissions, serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.utils import timezone
from .models import Tenant, TenantUser, AuditLog
from .tenant_settings import TenantSettings
from .tenant_settings_serializers import TenantSettingsSerializer, TenantSettingsUpdateSerializer
from .permissions import IsTenantAdmin
import logging

logger = logging.getLogger(__name__)


class TenantSettingsViewSet(viewsets.ModelViewSet):
    """ViewSet para gerenciamento de configurações de tenant"""
    
    queryset = TenantSettings.objects.all()
    serializer_class = TenantSettingsSerializer
    permission_classes = [permissions.IsAuthenticated, IsTenantAdmin]
    
    def get_queryset(self):
        """Filtra configurações baseado nas permissões do usuário"""
        queryset = super().get_queryset()
        
        # Se não é staff, mostra apenas configurações dos tenants que o usuário administra
        if not self.request.user.is_staff:
            admin_tenants = TenantUser.objects.filter(
                user=self.request.user,
                role='ADMIN',
                is_active=True
            ).values_list('tenant_id', flat=True)
            queryset = queryset.filter(tenant_id__in=admin_tenants)
        
        return queryset.select_related('tenant')
    
    def get_serializer_class(self):
        """Retorna o serializer apropriado baseado na ação"""
        if self.action in ['update', 'partial_update']:
            return TenantSettingsUpdateSerializer
        return TenantSettingsSerializer
    
    def perform_create(self, serializer):
        """Cria configurações para um tenant"""
        tenant_id = self.request.data.get('tenant_id')
        
        if not tenant_id:
            raise serializers.ValidationError({'tenant_id': 'ID do tenant é obrigatório'})
        
        tenant = get_object_or_404(Tenant, id=tenant_id)
        
        # Verifica se o usuário é admin do tenant
        if not self.request.user.is_staff:
            if not TenantUser.objects.filter(
                user=self.request.user,
                tenant=tenant,
                role='ADMIN',
                is_active=True
            ).exists():
                raise permissions.PermissionDenied("Você não tem permissão para configurar este tenant")
        
        # Verifica se já existem configurações para este tenant
        if TenantSettings.objects.filter(tenant=tenant).exists():
            raise serializers.ValidationError({'tenant': 'Configurações já existem para este tenant'})
        
        with transaction.atomic():
            settings = serializer.save(tenant=tenant)
            
            # Cria log de auditoria
            AuditLog.objects.create(
                tenant=tenant,
                user=self.request.user,
                action='CREATE',
                resource_type='TENANT_SETTINGS',
                resource_id=str(settings.id),
                resource_name=f"Configurações - {tenant.name}",
                description=f"Configurações criadas para o tenant {tenant.name}",
                ip_address=self.get_client_ip(),
                metadata={'tenant_id': tenant.id}
            )
    
    def perform_update(self, serializer):
        """Atualiza configurações do tenant"""
        settings = self.get_object()
        old_data = {
            'password_min_length': settings.password_min_length,
            'account_lockout_enabled': settings.account_lockout_enabled,
            'session_timeout_minutes': settings.session_timeout_minutes,
            'audit_log_retention_days': settings.audit_log_retention_days,
        }
        
        with transaction.atomic():
            updated_settings = serializer.save()
            
            # Identifica mudanças importantes
            changes = []
            if old_data['password_min_length'] != updated_settings.password_min_length:
                changes.append(f"Comprimento mínimo da senha: {old_data['password_min_length']} → {updated_settings.password_min_length}")
            
            if old_data['account_lockout_enabled'] != updated_settings.account_lockout_enabled:
                status_old = "habilitado" if old_data['account_lockout_enabled'] else "desabilitado"
                status_new = "habilitado" if updated_settings.account_lockout_enabled else "desabilitado"
                changes.append(f"Bloqueio de conta: {status_old} → {status_new}")
            
            if old_data['session_timeout_minutes'] != updated_settings.session_timeout_minutes:
                changes.append(f"Timeout de sessão: {old_data['session_timeout_minutes']}min → {updated_settings.session_timeout_minutes}min")
            
            if old_data['audit_log_retention_days'] != updated_settings.audit_log_retention_days:
                changes.append(f"Retenção de logs: {old_data['audit_log_retention_days']} → {updated_settings.audit_log_retention_days} dias")
            
            # Cria log de auditoria
            AuditLog.objects.create(
                tenant=settings.tenant,
                user=self.request.user,
                action='UPDATE',
                resource_type='TENANT_SETTINGS',
                resource_id=str(settings.id),
                resource_name=f"Configurações - {settings.tenant.name}",
                description=f"Configurações atualizadas: {'; '.join(changes)}" if changes else "Configurações atualizadas",
                ip_address=self.get_client_ip(),
                metadata={
                    'tenant_id': settings.tenant.id,
                    'changes': changes
                }
            )
    
    @action(detail=True, methods=['post'])
    def reset_to_defaults(self, request, pk=None):
        """Reseta configurações para os valores padrão"""
        settings = self.get_object()
        
        with transaction.atomic():
            # Salva valores atuais para log
            old_values = {
                'password_min_length': settings.password_min_length,
                'account_lockout_enabled': settings.account_lockout_enabled,
                'session_timeout_minutes': settings.session_timeout_minutes,
            }
            
            # Reseta para valores padrão
            settings.password_min_length = 8
            settings.password_require_uppercase = True
            settings.password_require_lowercase = True
            settings.password_require_numbers = True
            settings.password_require_special_chars = True
            settings.password_expiry_days = 90
            settings.account_lockout_enabled = True
            settings.account_lockout_threshold = 5
            settings.account_lockout_duration_minutes = 30
            settings.session_timeout_minutes = 480
            settings.max_concurrent_sessions = 3
            settings.audit_log_retention_days = 365
            settings.audit_failed_logins = True
            settings.audit_user_changes = True
            settings.audit_group_changes = True
            settings.audit_permission_changes = True
            settings.sync_user_photos = False
            settings.sync_user_attributes = []
            settings.sync_group_attributes = []
            settings.auto_create_users = True
            settings.auto_disable_users = True
            settings.email_notifications_enabled = True
            settings.notify_user_creation = True
            settings.notify_user_deactivation = True
            settings.notify_password_expiry = True
            settings.notify_sync_errors = True
            settings.notification_email_from = ''
            settings.ui_theme = 'light'
            settings.ui_language = 'pt-BR'
            settings.ui_timezone = 'America/Sao_Paulo'
            settings.max_users_limit = 1000
            settings.max_groups_limit = 100
            settings.custom_settings = {}
            
            settings.save()
            
            # Cria log de auditoria
            AuditLog.objects.create(
                tenant=settings.tenant,
                user=request.user,
                action='RESET',
                resource_type='TENANT_SETTINGS',
                resource_id=str(settings.id),
                resource_name=f"Configurações - {settings.tenant.name}",
                description="Configurações resetadas para valores padrão",
                ip_address=self.get_client_ip(),
                metadata={
                    'tenant_id': settings.tenant.id,
                    'old_values': old_values
                }
            )
            
            serializer = self.get_serializer(settings)
            return Response({
                'success': True,
                'message': 'Configurações resetadas para valores padrão',
                'data': serializer.data
            })
    
    @action(detail=True, methods=['get'])
    def export_settings(self, request, pk=None):
        """Exporta configurações como JSON"""
        settings = self.get_object()
        
        export_data = {
            'tenant_name': settings.tenant.name,
            'tenant_slug': settings.tenant.slug,
            'exported_at': timezone.now().isoformat(),
            'settings': {
                # Configurações de Segurança
                'password_policy': settings.get_password_policy(),
                'lockout_policy': settings.get_lockout_policy(),
                # Configurações de Sessão
                'session_timeout_minutes': settings.session_timeout_minutes,
                'max_concurrent_sessions': settings.max_concurrent_sessions,
                # Configurações de Auditoria
                'audit_settings': settings.get_audit_settings(),
                # Configurações de Sincronização
                'sync_settings': settings.get_sync_settings(),
                # Configurações de Notificação
                'notification_settings': settings.get_notification_settings(),
                # Configurações de Interface
                'ui_theme': settings.ui_theme,
                'ui_language': settings.ui_language,
                'ui_timezone': settings.ui_timezone,
                # Configurações de Limites
                'max_users_limit': settings.max_users_limit,
                'max_groups_limit': settings.max_groups_limit,
                # Configurações Customizadas
                'custom_settings': settings.custom_settings,
            }
        }
        
        # Cria log de auditoria
        AuditLog.objects.create(
            tenant=settings.tenant,
            user=request.user,
            action='EXPORT',
            resource_type='TENANT_SETTINGS',
            resource_id=str(settings.id),
            resource_name=f"Configurações - {settings.tenant.name}",
            description="Configurações exportadas",
            ip_address=self.get_client_ip(),
            metadata={'tenant_id': settings.tenant.id}
        )
        
        return Response(export_data)
    
    @action(detail=False, methods=['get'])
    def get_by_tenant(self, request):
        """Obtém configurações por ID do tenant"""
        tenant_id = request.query_params.get('tenant_id')
        
        if not tenant_id:
            return Response(
                {'error': 'tenant_id é obrigatório'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        tenant = get_object_or_404(Tenant, id=tenant_id)
        
        # Verifica permissões
        if not self.request.user.is_staff:
            if not TenantUser.objects.filter(
                user=self.request.user,
                tenant=tenant,
                role='ADMIN',
                is_active=True
            ).exists():
                return Response(
                    {'error': 'Você não tem permissão para acessar as configurações deste tenant'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        # Obtém ou cria configurações
        settings, created = TenantSettings.objects.get_or_create(
            tenant=tenant,
            defaults={}
        )
        
        if created:
            # Cria log de auditoria para criação automática
            AuditLog.objects.create(
                tenant=tenant,
                user=request.user,
                action='CREATE',
                resource_type='TENANT_SETTINGS',
                resource_id=str(settings.id),
                resource_name=f"Configurações - {tenant.name}",
                description=f"Configurações criadas automaticamente para o tenant {tenant.name}",
                ip_address=self.get_client_ip(),
                metadata={'tenant_id': tenant.id, 'auto_created': True}
            )
        
        serializer = self.get_serializer(settings)
        return Response({
            'created': created,
            'data': serializer.data
        })
    
    def get_client_ip(self):
        """Obtém IP do cliente"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip