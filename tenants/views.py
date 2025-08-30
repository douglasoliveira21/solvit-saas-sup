from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.utils import timezone
from .models import (
    Tenant, TenantUser, ADConfiguration, M365Configuration,
    ManagedUser, ManagedGroup
)
from .serializers import (
    TenantSerializer, TenantUserSerializer, ADConfigurationSerializer,
    M365ConfigurationSerializer, ManagedUserSerializer, ManagedGroupSerializer,
    ManagedGroupMembersSerializer
)
from core.models import AuditLog
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
        """Estatísticas do tenant"""
        tenant = self.get_object()
        
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
        
        return Response(stats)
    
    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        """Ativa/desativa tenant"""
        tenant = self.get_object()
        tenant.is_active = not tenant.is_active
        tenant.save()
        
        action = 'ativado' if tenant.is_active else 'desativado'
        
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


class ADConfigurationViewSet(viewsets.ModelViewSet):
    """ViewSet para configuração do Active Directory"""
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
    filterset_fields = ['tenant', 'sync_enabled', 'connection_status']
    
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
    """ViewSet para usuários gerenciados"""
    queryset = ManagedUser.objects.all()
    serializer_class = ManagedUserSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ['tenant', 'is_active', 'sync_status']
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
    
    @action(detail=True, methods=['post'])
    def sync_to_ad(self, request, pk=None):
        """Sincroniza usuário para AD"""
        user = self.get_object()
        
        # Implementar lógica de sincronização com AD
        # Por enquanto, retorna mock
        
        return Response({
            'success': True,
            'message': f'Usuário {user.username} sincronizado com AD',
            'sync_status': 'SYNCED'
        })
    
    @action(detail=True, methods=['post'])
    def sync_to_m365(self, request, pk=None):
        """Sincroniza usuário para M365"""
        user = self.get_object()
        
        # Implementar lógica de sincronização com M365
        # Por enquanto, retorna mock
        
        return Response({
            'success': True,
            'message': f'Usuário {user.username} sincronizado com M365',
            'sync_status': 'SYNCED'
        })


class ManagedGroupViewSet(viewsets.ModelViewSet):
    """ViewSet para grupos gerenciados"""
    queryset = ManagedGroup.objects.all()
    serializer_class = ManagedGroupSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ['tenant', 'is_active', 'group_type', 'sync_status']
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
    
    @action(detail=True, methods=['get', 'post'])
    def members(self, request, pk=None):
        """Gerencia membros do grupo"""
        group = self.get_object()
        
        if request.method == 'GET':
            members = group.members.all()
            serializer = ManagedUserSerializer(members, many=True)
            return Response(serializer.data)
        
        elif request.method == 'POST':
            serializer = ManagedGroupMembersSerializer(group, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'success': True,
                    'message': 'Membros do grupo atualizados com sucesso',
                    'members_count': group.members_count
                })
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
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
            group.members.add(user)
            
            return Response({
                'success': True,
                'message': f'Usuário {user.username} adicionado ao grupo {group.name}',
                'members_count': group.members_count
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
            group.members.remove(user)
            
            return Response({
                'success': True,
                'message': f'Usuário {user.username} removido do grupo {group.name}',
                'members_count': group.members_count
            })
        except ManagedUser.DoesNotExist:
            return Response({
                'error': 'Usuário não encontrado ou não pertence ao mesmo tenant'
            }, status=status.HTTP_404_NOT_FOUND)