from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.utils import timezone
from django.core.cache import cache
from .models import (
    Tenant, TenantUser, ADConfiguration, M365Configuration,
    ManagedUser, ManagedGroup, GroupMembership
)
from .serializers import (
    TenantSerializer, TenantUserSerializer, ADConfigurationSerializer,
    M365ConfigurationSerializer, ManagedUserSerializer, ManagedGroupSerializer
)
from core.models import AuditLog
from core.tasks import send_user_deactivation_email
from core.cache_service import CacheService, cache_result
import logging

logger = logging.getLogger(__name__)


class TenantViewSet(viewsets.ModelViewSet):
    """ViewSet para gerenciamento de tenants"""
    queryset = Tenant.objects.all()
    serializer_class = TenantSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ['is_active', 'has_ad_integration', 'has_m365_integration']
    search_fields = ['name', 'domain', 'contact_name', 'contact_email']
    ordering_fields = ['name', 'created_at', 'updated_at']
    ordering = ['name']
    
    def get_queryset(self):
        """Filtra tenants baseado nas permissões do usuário"""
        queryset = super().get_queryset()
        
        # Se não é staff, mostra apenas tenants que o usuário tem acesso
        if not self.request.user.is_staff:
            user_tenants = TenantUser.objects.filter(
                user=self.request.user,
                is_active=True
            ).values_list('tenant_id', flat=True)
            queryset = queryset.filter(id__in=user_tenants)
        
        return queryset
    
    def perform_create(self, serializer):
        """Cria tenant e adiciona o usuário como admin"""
        with transaction.atomic():
            tenant = serializer.save()
            
            # Adiciona o usuário criador como admin do tenant
            TenantUser.objects.create(
                user=self.request.user,
                tenant=tenant,
                role='ADMIN'
            )
            
            # Invalida cache relacionado
            CacheService.invalidate_tenant_cache(tenant.id)
            
            # Log de auditoria
            AuditLog.objects.create(
                user=self.request.user,
                tenant=tenant,
                action='CREATE',
                resource_type='TENANT',
                resource_id=str(tenant.id),
                resource_name=tenant.name,
                description=f"Tenant '{tenant.name}' criado",
                ip_address=self.get_client_ip(),
                user_agent=self.request.META.get('HTTP_USER_AGENT', '')
            )
    
    def perform_update(self, serializer):
        """Atualiza tenant com log de auditoria"""
        old_name = serializer.instance.name
        tenant = serializer.save()
        
        # Invalida cache relacionado
        CacheService.invalidate_tenant_cache(tenant.id)
        
        # Log de auditoria
        AuditLog.objects.create(
            user=self.request.user,
            tenant=tenant,
            action='UPDATE',
            resource_type='TENANT',
            resource_id=str(tenant.id),
            resource_name=tenant.name,
            description=f"Tenant atualizado de '{old_name}' para '{tenant.name}'",
            ip_address=self.get_client_ip(),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')
        )
    
    @action(detail=True, methods=['get'])
    def stats(self, request, pk=None):
        """Estatísticas do tenant com cache"""
        tenant = self.get_object()
        
        # Verifica cache primeiro
        cache_key = CacheService.get_tenant_cache_key(tenant.id, 'stats')
        cached_stats = CacheService.get(cache_key)
        
        if cached_stats is not None:
            return Response(cached_stats)
        
        stats = {
            'users': {
                'total': tenant.current_users_count,
                'active': tenant.managed_users.filter(is_active=True).count(),
                'inactive': tenant.managed_users.filter(is_active=False).count(),
                'limit': tenant.max_users,
                'can_add': tenant.can_add_user()
            },
            'groups': {
                'total': tenant.current_groups_count,
                'active': tenant.managed_groups.filter(is_active=True).count(),
                'inactive': tenant.managed_groups.filter(is_active=False).count(),
                'limit': tenant.max_groups,
                'can_add': tenant.can_add_group()
            },
            'integrations': {
                'ad_enabled': tenant.has_ad_integration,
                'ad_agent_online': False,
                'm365_enabled': tenant.has_m365_integration,
                'm365_connected': False
            }
        }
        
        # Verifica status das integrações
        if tenant.has_ad_integration and hasattr(tenant, 'ad_config'):
            stats['integrations']['ad_agent_online'] = tenant.ad_config.is_agent_online
        
        if tenant.has_m365_integration and hasattr(tenant, 'm365_config'):
            stats['integrations']['m365_connected'] = tenant.m365_config.connection_status == 'CONNECTED'
        
        # Cacheia por 5 minutos
        CacheService.set(cache_key, stats, CacheService.TIMEOUT_SHORT)
        
        return Response(stats)
    
    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        """Ativa/desativa tenant"""
        tenant = self.get_object()
        tenant.is_active = not tenant.is_active
        tenant.save()
        
        action = 'ativado' if tenant.is_active else 'desativado'
        
        # Invalida cache relacionado
        CacheService.invalidate_tenant_cache(tenant.id)
        
        # Log de auditoria
        AuditLog.objects.create(
            user=request.user,
            tenant=tenant,
            action='UPDATE',
            resource_type='TENANT',
            resource_id=str(tenant.id),
            resource_name=tenant.name,
            description=f"Tenant '{tenant.name}' {action}",
            ip_address=self.get_client_ip(),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return Response({
            'id': tenant.id,
            'name': tenant.name,
            'is_active': tenant.is_active,
            'message': f"Tenant {action} com sucesso"
        })
    
    def get_client_ip(self):
        """Obtém o IP do cliente"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip


class TenantUserViewSet(viewsets.ModelViewSet):
    """ViewSet para gerenciamento de usuários de tenants"""
    queryset = TenantUser.objects.all()
    serializer_class = TenantUserSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ['tenant', 'role', 'is_active']
    search_fields = ['user__username', 'user__email', 'user__first_name', 'user__last_name']
    ordering = ['tenant', 'user__username']
    
    def get_queryset(self):
        """Filtra usuários baseado nas permissões"""
        queryset = super().get_queryset()
        
        if not self.request.user.is_staff:
            # Mostra apenas usuários dos tenants que o usuário tem acesso
            user_tenants = TenantUser.objects.filter(
                user=self.request.user,
                is_active=True
            ).values_list('tenant_id', flat=True)
            queryset = queryset.filter(tenant_id__in=user_tenants)
        
        return queryset
    
    def perform_create(self, serializer):
        """Cria usuário e registra log de auditoria"""
        with transaction.atomic():
            tenant_user = serializer.save()
            
            # Registra log de auditoria
            AuditLog.objects.create(
                tenant=tenant_user.tenant,
                user=self.request.user,
                action='CREATE_USER',
                resource_type='TenantUser',
                resource_id=tenant_user.id,
                resource_name=tenant_user.user.username,
                description=f'Usuário {tenant_user.user.username} adicionado ao tenant {tenant_user.tenant.name}',
                ip_address=self.get_client_ip(),
                metadata={
                    'role': tenant_user.role,
                    'user_email': tenant_user.user.email
                }
            )
    
    def perform_update(self, serializer):
        """Atualiza usuário e registra log de auditoria"""
        old_instance = self.get_object()
        old_role = old_instance.role
        old_active = old_instance.is_active
        
        with transaction.atomic():
            tenant_user = serializer.save()
            
            changes = []
            if old_role != tenant_user.role:
                changes.append(f'role: {old_role} → {tenant_user.role}')
            if old_active != tenant_user.is_active:
                status = 'ativado' if tenant_user.is_active else 'desativado'
                changes.append(f'status: {status}')
            
            if changes:
                AuditLog.objects.create(
                    tenant=tenant_user.tenant,
                    user=self.request.user,
                    action='UPDATE_USER',
                    resource_type='TenantUser',
                    resource_id=tenant_user.id,
                    resource_name=tenant_user.user.username,
                    description=f'Usuário {tenant_user.user.username} atualizado: {", ".join(changes)}',
                    ip_address=self.get_client_ip(),
                    metadata={
                        'changes': changes,
                        'new_role': tenant_user.role,
                        'new_active': tenant_user.is_active
                    }
                )
    
    def perform_destroy(self, instance):
        """Remove usuário e registra log de auditoria"""
        with transaction.atomic():
            AuditLog.objects.create(
                tenant=instance.tenant,
                user=self.request.user,
                action='DELETE_USER',
                resource_type='TenantUser',
                resource_id=instance.id,
                resource_name=instance.user.username,
                description=f'Usuário {instance.user.username} removido do tenant {instance.tenant.name}',
                ip_address=self.get_client_ip(),
                metadata={
                    'role': instance.role,
                    'user_email': instance.user.email
                }
            )
            super().perform_destroy(instance)
    
    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        """Ativa/desativa usuário"""
        tenant_user = self.get_object()
        
        with transaction.atomic():
            tenant_user.is_active = not tenant_user.is_active
            tenant_user.save()
            
            status_text = 'ativado' if tenant_user.is_active else 'desativado'
            
            AuditLog.objects.create(
                tenant=tenant_user.tenant,
                user=request.user,
                action='TOGGLE_USER_STATUS',
                resource_type='TenantUser',
                resource_id=tenant_user.id,
                resource_name=tenant_user.user.username,
                description=f'Usuário {tenant_user.user.username} {status_text}',
                ip_address=self.get_client_ip(),
                metadata={
                    'new_status': tenant_user.is_active
                }
            )
            
            return Response({
                'success': True,
                'message': f'Usuário {status_text} com sucesso',
                'is_active': tenant_user.is_active
            })
    
    @action(detail=True, methods=['post'])
    def change_role(self, request, pk=None):
        """Altera role do usuário"""
        tenant_user = self.get_object()
        new_role = request.data.get('role')
        
        if not new_role:
            return Response({
                'error': 'Role é obrigatório'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        valid_roles = ['ADMIN', 'OPERATOR', 'VIEWER']
        if new_role not in valid_roles:
            return Response({
                'error': f'Role inválido. Opções válidas: {", ".join(valid_roles)}'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        old_role = tenant_user.role
        
        with transaction.atomic():
            tenant_user.role = new_role
            tenant_user.save()
            
            AuditLog.objects.create(
                tenant=tenant_user.tenant,
                user=request.user,
                action='CHANGE_USER_ROLE',
                resource_type='TenantUser',
                resource_id=tenant_user.id,
                resource_name=tenant_user.user.username,
                description=f'Role do usuário {tenant_user.user.username} alterado de {old_role} para {new_role}',
                ip_address=self.get_client_ip(),
                metadata={
                    'old_role': old_role,
                    'new_role': new_role
                }
            )
            
            return Response({
                'success': True,
                'message': f'Role alterado de {old_role} para {new_role}',
                'role': new_role
            })
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Estatísticas de usuários"""
        queryset = self.get_queryset()
        
        total_users = queryset.count()
        active_users = queryset.filter(is_active=True).count()
        inactive_users = total_users - active_users
        
        roles_stats = {}
        for role_code, role_name in TenantUser.ROLE_CHOICES:
            roles_stats[role_code] = {
                'name': role_name,
                'count': queryset.filter(role=role_code).count()
            }
        
        return Response({
            'total_users': total_users,
            'active_users': active_users,
            'inactive_users': inactive_users,
            'roles': roles_stats
        })
    
    def get_client_ip(self):
        """Obtém IP do cliente"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip


class ADConfigurationViewSet(viewsets.ModelViewSet):
    """ViewSet para configurações do Active Directory"""
    queryset = ADConfiguration.objects.all()
    serializer_class = ADConfigurationSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ['tenant', 'sync_enabled', 'agent_status']
    
    def get_queryset(self):
        """Filtra configurações baseado nas permissões"""
        queryset = super().get_queryset()
        
        if not self.request.user.is_staff:
            user_tenants = TenantUser.objects.filter(
                user=self.request.user,
                is_active=True,
                role__in=['ADMIN', 'OPERATOR']
            ).values_list('tenant_id', flat=True)
            queryset = queryset.filter(tenant_id__in=user_tenants)
        
        return queryset
    
    @action(detail=True, methods=['post'])
    def test_connection(self, request, pk=None):
        """Testa a conexão com o AD"""
        config = self.get_object()
        
        # Aqui você implementaria a lógica de teste de conexão
        # Por enquanto, retorna um mock
        
        try:
            # Simula teste de conexão
            success = True  # Implementar lógica real
            
            if success:
                config.agent_status = 'ONLINE'
                config.agent_last_heartbeat = timezone.now()
                config.save()
                
                return Response({
                    'success': True,
                    'message': 'Conexão com AD estabelecida com sucesso',
                    'status': 'ONLINE'
                })
            else:
                config.agent_status = 'ERROR'
                config.save()
                
                return Response({
                    'success': False,
                    'message': 'Falha na conexão com AD',
                    'status': 'ERROR'
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Erro ao testar conexão AD: {str(e)}")
            return Response({
                'success': False,
                'message': f'Erro interno: {str(e)}',
                'status': 'ERROR'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class M365ConfigurationViewSet(viewsets.ModelViewSet):
    """ViewSet para configuração do Microsoft 365"""
    queryset = M365Configuration.objects.all()
    serializer_class = M365ConfigurationSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ['tenant', 'sync_enabled', 'last_sync_status']
    
    def get_queryset(self):
        """Filtra configurações baseado nas permissões"""
        queryset = super().get_queryset()
        
        if not self.request.user.is_staff:
            user_tenants = TenantUser.objects.filter(
                user=self.request.user,
                is_active=True,
                role__in=['ADMIN', 'OPERATOR']
            ).values_list('tenant_id', flat=True)
            queryset = queryset.filter(tenant_id__in=user_tenants)
        
        return queryset
    
    @action(detail=True, methods=['post'])
    def test_connection(self, request, pk=None):
        """Testa a conexão com Microsoft Graph"""
        config = self.get_object()
        
        try:
            # Aqui você implementaria a lógica de teste com Microsoft Graph
            # Por enquanto, retorna um mock
            
            success = True  # Implementar lógica real
            
            if success:
                config.connection_status = 'CONNECTED'
                config.last_sync = timezone.now()
                config.last_error = ''
                config.save()
                
                return Response({
                    'success': True,
                    'message': 'Conexão com Microsoft Graph estabelecida com sucesso',
                    'status': 'CONNECTED'
                })
            else:
                config.connection_status = 'ERROR'
                config.last_error = 'Falha na autenticação'
                config.save()
                
                return Response({
                    'success': False,
                    'message': 'Falha na conexão com Microsoft Graph',
                    'status': 'ERROR'
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Erro ao testar conexão M365: {str(e)}")
            config.connection_status = 'ERROR'
            config.last_error = str(e)
            config.save()
            
            return Response({
                'success': False,
                'message': f'Erro interno: {str(e)}',
                'status': 'ERROR'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ManagedUserViewSet(viewsets.ModelViewSet):
    """ViewSet para usuários gerenciados (sincronizados do AD/M365)"""
    queryset = ManagedUser.objects.all()
    serializer_class = ManagedUserSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ['tenant', 'is_active', 'sync_status', 'source']
    search_fields = ['username', 'email', 'first_name', 'last_name', 'display_name']
    ordering = ['tenant', 'display_name']
    
    def get_queryset(self):
        """Filtra usuários baseado nas permissões"""
        queryset = super().get_queryset()
        
        if not self.request.user.is_staff:
            user_tenants = TenantUser.objects.filter(
                user=self.request.user,
                is_active=True
            ).values_list('tenant_id', flat=True)
            queryset = queryset.filter(tenant_id__in=user_tenants)
        
        return queryset
    
    def perform_update(self, serializer):
        """Atualiza usuário gerenciado e registra log"""
        old_instance = self.get_object()
        old_active = old_instance.is_active
        
        with transaction.atomic():
            managed_user = serializer.save()
            
            # Invalida cache relacionado
            CacheService.invalidate_user_cache(managed_user.id)
            CacheService.invalidate_tenant_cache(managed_user.tenant.id)
            
            if old_active != managed_user.is_active:
                status_text = 'ativado' if managed_user.is_active else 'desativado'
                
                AuditLog.objects.create(
                    tenant=managed_user.tenant,
                    user=self.request.user,
                    action='UPDATE_MANAGED_USER',
                    resource_type='ManagedUser',
                    resource_id=managed_user.id,
                    resource_name=managed_user.username,
                    description=f'Usuário gerenciado {managed_user.username} {status_text}',
                    ip_address=self.get_client_ip(),
                    metadata={
                        'source': managed_user.source,
                        'new_active': managed_user.is_active
                    }
                )
    
    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        """Ativa/desativa usuário gerenciado"""
        managed_user = self.get_object()
        
        with transaction.atomic():
            managed_user.is_active = not managed_user.is_active
            managed_user.save()
            
            status_text = 'ativado' if managed_user.is_active else 'desativado'
            
            AuditLog.objects.create(
                tenant=managed_user.tenant,
                user=request.user,
                action='TOGGLE_MANAGED_USER_STATUS',
                resource_type='ManagedUser',
                resource_id=managed_user.id,
                resource_name=managed_user.username,
                description=f'Usuário gerenciado {managed_user.username} {status_text}',
                ip_address=self.get_client_ip(),
                metadata={
                    'source': managed_user.source,
                    'new_status': managed_user.is_active
                }
            )
            
            # Envia email de notificação se o usuário foi desativado
            if not managed_user.is_active and managed_user.email:
                try:
                    send_user_deactivation_email.delay(
                        user_email=managed_user.email,
                        user_name=managed_user.display_name or managed_user.username,
                        tenant_name=managed_user.tenant.name,
                        deactivated_by=request.user.get_full_name() or request.user.username
                    )
                    logger.info(f"Task de email de desativação enviada para: {managed_user.email}")
                except Exception as e:
                    logger.error(f"Erro ao enviar task de email de desativação: {e}")
            
            return Response({
                'success': True,
                'message': f'Usuário {status_text} com sucesso',
                'is_active': managed_user.is_active
            })
    
    @action(detail=True, methods=['post'])
    def force_sync(self, request, pk=None):
        """Força sincronização do usuário"""
        managed_user = self.get_object()
        
        try:
            # Atualiza status de sincronização
            managed_user.sync_status = 'PENDING'
            managed_user.last_sync_attempt = timezone.now()
            managed_user.save()
            
            AuditLog.objects.create(
                tenant=managed_user.tenant,
                user=request.user,
                action='FORCE_SYNC_USER',
                resource_type='ManagedUser',
                resource_id=managed_user.id,
                resource_name=managed_user.username,
                description=f'Sincronização forçada para usuário {managed_user.username}',
                ip_address=self.get_client_ip(),
                metadata={
                    'source': managed_user.source
                }
            )
            
            return Response({
                'success': True,
                'message': f'Sincronização iniciada para usuário {managed_user.username}',
                'sync_status': 'PENDING'
            })
            
        except Exception as e:
            logger.error(f"Erro ao forçar sincronização: {str(e)}")
            return Response({
                'success': False,
                'message': f'Erro ao iniciar sincronização: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['get'])
    def sync_stats(self, request):
        """Estatísticas de sincronização com cache"""
        # Verifica cache primeiro
        cache_key = 'managed_users_sync_stats'
        cached_stats = CacheService.get(cache_key)
        
        if cached_stats is not None:
            return Response(cached_stats)
        
        queryset = self.get_queryset()
        
        total_users = queryset.count()
        by_source = {}
        by_status = {}
        
        for source_code, source_name in ManagedUser.SOURCE_CHOICES:
            by_source[source_code] = {
                'name': source_name,
                'count': queryset.filter(source=source_code).count()
            }
        
        for status_code, status_name in ManagedUser.SYNC_STATUS_CHOICES:
            by_status[status_code] = {
                'name': status_name,
                'count': queryset.filter(sync_status=status_code).count()
            }
        
        stats_data = {
            'total_users': total_users,
            'active_users': queryset.filter(is_active=True).count(),
            'by_source': by_source,
            'by_sync_status': by_status
        }
        
        # Cacheia por 5 minutos
        CacheService.set(cache_key, stats_data, CacheService.TIMEOUT_SHORT)
        
        return Response(stats_data)
    
    def get_client_ip(self):
        """Obtém IP do cliente"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip


class ManagedGroupViewSet(viewsets.ModelViewSet):
    """ViewSet para grupos gerenciados (sincronizados do AD/M365)"""
    queryset = ManagedGroup.objects.all()
    serializer_class = ManagedGroupSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ['tenant', 'is_active', 'group_type', 'sync_status', 'source']
    search_fields = ['name', 'description']
    ordering = ['tenant', 'name']
    
    def get_queryset(self):
        """Filtra grupos baseado nas permissões"""
        queryset = super().get_queryset()
        
        if not self.request.user.is_staff:
            user_tenants = TenantUser.objects.filter(
                user=self.request.user,
                is_active=True
            ).values_list('tenant_id', flat=True)
            queryset = queryset.filter(tenant_id__in=user_tenants)
        
        return queryset
    
    def perform_update(self, serializer):
        """Atualiza grupo gerenciado e registra log"""
        old_instance = self.get_object()
        old_active = old_instance.is_active
        
        with transaction.atomic():
            managed_group = serializer.save()
            
            if old_active != managed_group.is_active:
                status_text = 'ativado' if managed_group.is_active else 'desativado'
                
                AuditLog.objects.create(
                    tenant=managed_group.tenant,
                    user=self.request.user,
                    action='UPDATE_MANAGED_GROUP',
                    resource_type='ManagedGroup',
                    resource_id=managed_group.id,
                    resource_name=managed_group.name,
                    description=f'Grupo gerenciado {managed_group.name} {status_text}',
                    ip_address=self.get_client_ip(),
                    metadata={
                        'source': managed_group.source,
                        'new_active': managed_group.is_active
                    }
                )
    
    @action(detail=True, methods=['get'])
    def members(self, request, pk=None):
        """Lista membros do grupo"""
        group = self.get_object()
        memberships = GroupMembership.objects.filter(group=group).select_related('user')
        
        members_data = []
        for membership in memberships:
            members_data.append({
                'id': membership.user.id,
                'username': membership.user.username,
                'email': membership.user.email,
                'display_name': membership.user.display_name,
                'is_active': membership.user.is_active,
                'added_at': membership.added_at
            })
        
        return Response({
            'group_id': group.id,
            'group_name': group.name,
            'members_count': len(members_data),
            'members': members_data
        })
    
    @action(detail=True, methods=['post'])
    def add_member(self, request, pk=None):
        """Adiciona membro ao grupo"""
        group = self.get_object()
        user_id = request.data.get('user_id')
        
        if not user_id:
            return Response({
                'error': 'user_id é obrigatório'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = ManagedUser.objects.get(id=user_id, tenant=group.tenant)
            
            # Verifica se já é membro
            if GroupMembership.objects.filter(group=group, user=user).exists():
                return Response({
                    'error': f'Usuário {user.username} já é membro do grupo {group.name}'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            with transaction.atomic():
                GroupMembership.objects.create(group=group, user=user)
                
                AuditLog.objects.create(
                    tenant=group.tenant,
                    user=request.user,
                    action='ADD_GROUP_MEMBER',
                    resource_type='ManagedGroup',
                    resource_id=group.id,
                    resource_name=group.name,
                    description=f'Usuário {user.username} adicionado ao grupo {group.name}',
                    ip_address=self.get_client_ip(),
                    metadata={
                        'user_id': user.id,
                        'username': user.username
                    }
                )
            
            return Response({
                'success': True,
                'message': f'Usuário {user.username} adicionado ao grupo {group.name}',
                'members_count': GroupMembership.objects.filter(group=group).count()
            })
            
        except ManagedUser.DoesNotExist:
            return Response({
                'error': 'Usuário não encontrado ou não pertence ao mesmo tenant'
            }, status=status.HTTP_404_NOT_FOUND)
    
    @action(detail=True, methods=['post'])
    def remove_member(self, request, pk=None):
        """Remove membro do grupo"""
        group = self.get_object()
        user_id = request.data.get('user_id')
        
        if not user_id:
            return Response({
                'error': 'user_id é obrigatório'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = ManagedUser.objects.get(id=user_id, tenant=group.tenant)
            membership = GroupMembership.objects.get(group=group, user=user)
            
            with transaction.atomic():
                membership.delete()
                
                AuditLog.objects.create(
                    tenant=group.tenant,
                    user=request.user,
                    action='REMOVE_GROUP_MEMBER',
                    resource_type='ManagedGroup',
                    resource_id=group.id,
                    resource_name=group.name,
                    description=f'Usuário {user.username} removido do grupo {group.name}',
                    ip_address=self.get_client_ip(),
                    metadata={
                        'user_id': user.id,
                        'username': user.username
                    }
                )
            
            return Response({
                'success': True,
                'message': f'Usuário {user.username} removido do grupo {group.name}',
                'members_count': GroupMembership.objects.filter(group=group).count()
            })
            
        except ManagedUser.DoesNotExist:
            return Response({
                'error': 'Usuário não encontrado ou não pertence ao mesmo tenant'
            }, status=status.HTTP_404_NOT_FOUND)
        except GroupMembership.DoesNotExist:
            return Response({
                'error': f'Usuário não é membro do grupo {group.name}'
            }, status=status.HTTP_404_NOT_FOUND)
    
    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        """Ativa/desativa grupo gerenciado"""
        managed_group = self.get_object()
        
        with transaction.atomic():
            managed_group.is_active = not managed_group.is_active
            managed_group.save()
            
            status_text = 'ativado' if managed_group.is_active else 'desativado'
            
            AuditLog.objects.create(
                tenant=managed_group.tenant,
                user=request.user,
                action='TOGGLE_MANAGED_GROUP_STATUS',
                resource_type='ManagedGroup',
                resource_id=managed_group.id,
                resource_name=managed_group.name,
                description=f'Grupo gerenciado {managed_group.name} {status_text}',
                ip_address=self.get_client_ip(),
                metadata={
                    'source': managed_group.source,
                    'new_status': managed_group.is_active
                }
            )
            
            return Response({
                'success': True,
                'message': f'Grupo {status_text} com sucesso',
                'is_active': managed_group.is_active
            })
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Estatísticas de grupos"""
        queryset = self.get_queryset()
        
        total_groups = queryset.count()
        by_source = {}
        by_type = {}
        by_status = {}
        
        for source_code, source_name in ManagedGroup.SOURCE_CHOICES:
            by_source[source_code] = {
                'name': source_name,
                'count': queryset.filter(source=source_code).count()
            }
        
        for type_code, type_name in ManagedGroup.GROUP_TYPE_CHOICES:
            by_type[type_code] = {
                'name': type_name,
                'count': queryset.filter(group_type=type_code).count()
            }
        
        for status_code, status_name in ManagedGroup.SYNC_STATUS_CHOICES:
            by_status[status_code] = {
                'name': status_name,
                'count': queryset.filter(sync_status=status_code).count()
            }
        
        return Response({
            'total_groups': total_groups,
            'active_groups': queryset.filter(is_active=True).count(),
            'by_source': by_source,
            'by_type': by_type,
            'by_sync_status': by_status
        })
    
    def get_client_ip(self):
        """Obtém IP do cliente"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip