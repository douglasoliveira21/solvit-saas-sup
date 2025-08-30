import logging
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from tenants.models import Tenant, M365Configuration, ManagedUser, ManagedGroup
from tenants.permissions import IsTenantMember
from .sync_service import M365SyncService
from .graph_client import GraphAPIError

logger = logging.getLogger('msgraph_integration')


class M365IntegrationViewSet(viewsets.ViewSet):
    """ViewSet para operações de integração com Microsoft 365"""
    
    permission_classes = [IsAuthenticated, IsTenantMember]
    
    def get_queryset(self):
        """Filtra por tenant do usuário"""
        user_tenants = self.request.user.tenant_users.values_list('tenant_id', flat=True)
        return M365Configuration.objects.filter(tenant_id__in=user_tenants)
    
    def get_tenant_from_request(self):
        """Obtém tenant da requisição"""
        tenant_id = self.request.data.get('tenant_id') or self.request.query_params.get('tenant_id')
        
        if not tenant_id:
            return None
        
        # Verifica se o usuário tem acesso ao tenant
        user_tenants = self.request.user.tenant_users.values_list('tenant_id', flat=True)
        
        if int(tenant_id) not in user_tenants:
            return None
        
        return get_object_or_404(Tenant, id=tenant_id)
    
    @action(detail=False, methods=['post'])
    def test_connection(self, request):
        """Testa conexão com Microsoft 365"""
        tenant = self.get_tenant_from_request()
        
        if not tenant:
            return Response(
                {'error': 'Tenant não encontrado ou acesso negado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            config = M365Configuration.objects.get(tenant=tenant)
            sync_service = M365SyncService(tenant)
            
            # Testa a conexão
            result = sync_service.test_connection()
            
            if result['success']:
                config.last_sync_status = 'SUCCESS'
                config.last_sync_message = 'Conexão testada com sucesso'
            else:
                config.last_sync_status = 'ERROR'
                config.last_sync_message = result.get('error', 'Erro desconhecido')
            
            config.save()
            
            return Response(result)
            
        except M365Configuration.DoesNotExist:
            return Response(
                {'error': 'Configuração M365 não encontrada para este tenant'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Erro ao testar conexão M365: {str(e)}")
            return Response(
                {'error': f'Erro interno: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def sync_users(self, request):
        """Sincroniza todos os usuários do tenant com M365"""
        tenant = self.get_tenant_from_request()
        
        if not tenant:
            return Response(
                {'error': 'Tenant não encontrado ou acesso negado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            config = M365Configuration.objects.get(tenant=tenant)
            sync_service = M365SyncService(tenant)
            
            # Executa sincronização de usuários
            result = sync_service.sync_users()
            
            return Response(result)
            
        except M365Configuration.DoesNotExist:
            return Response(
                {'error': 'Configuração M365 não encontrada para este tenant'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Erro ao sincronizar usuários M365: {str(e)}")
            return Response(
                {'error': f'Erro interno: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def sync_groups(self, request):
        """Sincroniza todos os grupos do tenant com M365"""
        tenant = self.get_tenant_from_request()
        
        if not tenant:
            return Response(
                {'error': 'Tenant não encontrado ou acesso negado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            config = M365Configuration.objects.get(tenant=tenant)
            sync_service = M365SyncService(tenant)
            
            # Executa sincronização de grupos
            result = sync_service.sync_groups()
            
            return Response(result)
            
        except M365Configuration.DoesNotExist:
            return Response(
                {'error': 'Configuração M365 não encontrada para este tenant'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Erro ao sincronizar grupos M365: {str(e)}")
            return Response(
                {'error': f'Erro interno: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def full_sync(self, request):
        """Executa sincronização completa (usuários e grupos)"""
        tenant = self.get_tenant_from_request()
        
        if not tenant:
            return Response(
                {'error': 'Tenant não encontrado ou acesso negado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            config = M365Configuration.objects.get(tenant=tenant)
            sync_service = M365SyncService(tenant)
            
            # Executa sincronização completa
            result = sync_service.full_sync()
            
            return Response(result)
            
        except M365Configuration.DoesNotExist:
            return Response(
                {'error': 'Configuração M365 não encontrada para este tenant'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Erro ao executar sincronização completa M365: {str(e)}")
            return Response(
                {'error': f'Erro interno: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def sync_status(self, request):
        """Obtém status de sincronização do tenant"""
        tenant = self.get_tenant_from_request()
        
        if not tenant:
            return Response(
                {'error': 'Tenant não encontrado ou acesso negado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            config = M365Configuration.objects.get(tenant=tenant)
            
            # Conta usuários e grupos sincronizados
            users_count = ManagedUser.objects.filter(tenant=tenant, source='M365').count()
            groups_count = ManagedGroup.objects.filter(tenant=tenant, source='M365').count()
            
            return Response({
                'success': True,
                'config': {
                    'sync_enabled': config.sync_enabled,
                    'sync_users': config.sync_users,
                    'sync_groups': config.sync_groups,
                    'sync_interval_hours': config.sync_interval_hours,
                    'last_sync_at': config.last_sync_at.isoformat() if config.last_sync_at else None,
                    'last_sync_status': config.last_sync_status,
                    'last_sync_message': config.last_sync_message
                },
                'stats': {
                    'synced_users': users_count,
                    'synced_groups': groups_count
                }
            })
            
        except M365Configuration.DoesNotExist:
            return Response(
                {'error': 'Configuração M365 não encontrada para este tenant'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Erro ao obter status de sincronização M365: {str(e)}")
            return Response(
                {'error': f'Erro interno: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def list_managed_users(self, request):
        """Lista usuários gerenciados do tenant"""
        tenant = self.get_tenant_from_request()
        
        if not tenant:
            return Response(
                {'error': 'Tenant não encontrado ou acesso negado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            users = ManagedUser.objects.filter(tenant=tenant).select_related('user')
            
            users_data = []
            for managed_user in users:
                users_data.append({
                    'id': managed_user.id,
                    'user_id': managed_user.user.id,
                    'username': managed_user.user.username,
                    'email': managed_user.user.email,
                    'first_name': managed_user.user.first_name,
                    'last_name': managed_user.user.last_name,
                    'external_id': managed_user.external_id,
                    'source': managed_user.source,
                    'department': managed_user.department,
                    'job_title': managed_user.job_title,
                    'office_location': managed_user.office_location,
                    'sync_enabled': managed_user.sync_enabled,
                    'last_synced_at': managed_user.last_synced_at.isoformat() if managed_user.last_synced_at else None,
                    'is_active': managed_user.user.is_active
                })
            
            return Response({
                'success': True,
                'users': users_data,
                'count': len(users_data)
            })
            
        except Exception as e:
            logger.error(f"Erro ao listar usuários gerenciados: {str(e)}")
            return Response(
                {'error': f'Erro interno: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def list_managed_groups(self, request):
        """Lista grupos gerenciados do tenant"""
        tenant = self.get_tenant_from_request()
        
        if not tenant:
            return Response(
                {'error': 'Tenant não encontrado ou acesso negado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            groups = ManagedGroup.objects.filter(tenant=tenant).prefetch_related('members__user')
            
            groups_data = []
            for group in groups:
                members = [{
                    'id': membership.user.id,
                    'username': membership.user.user.username,
                    'email': membership.user.user.email,
                    'first_name': membership.user.user.first_name,
                    'last_name': membership.user.user.last_name
                } for membership in group.members.all()]
                
                groups_data.append({
                    'id': group.id,
                    'name': group.name,
                    'description': group.description,
                    'external_id': group.external_id,
                    'source': group.source,
                    'sync_enabled': group.sync_enabled,
                    'last_synced_at': group.last_synced_at.isoformat() if group.last_synced_at else None,
                    'members_count': len(members),
                    'members': members
                })
            
            return Response({
                'success': True,
                'groups': groups_data,
                'count': len(groups_data)
            })
            
        except Exception as e:
            logger.error(f"Erro ao listar grupos gerenciados: {str(e)}")
            return Response(
                {'error': f'Erro interno: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )