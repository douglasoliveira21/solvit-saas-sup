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
            sync_service = M365SyncService(tenant)
            result = sync_service.test_connection()
            
            return Response(result)
            
        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Erro no teste de conexão M365: {e}")
            return Response(
                {'error': 'Erro interno do servidor'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def sync_user(self, request):
        """Sincroniza um usuário específico com M365"""
        tenant = self.get_tenant_from_request()
        user_id = request.data.get('user_id')
        operation = request.data.get('operation', 'create')
        
        if not tenant:
            return Response(
                {'error': 'Tenant não encontrado ou acesso negado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not user_id:
            return Response(
                {'error': 'ID do usuário é obrigatório'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if operation not in ['create', 'update', 'disable', 'enable']:
            return Response(
                {'error': 'Operação inválida. Use: create, update, disable, enable'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            managed_user = get_object_or_404(ManagedUser, id=user_id, tenant=tenant)
            sync_service = M365SyncService(tenant)
            
            result = sync_service.sync_user_to_m365(managed_user, operation)
            
            return Response(result)
            
        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Erro na sincronização do usuário: {e}")
            return Response(
                {'error': 'Erro interno do servidor'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def sync_group(self, request):
        """Sincroniza um grupo específico com M365"""
        tenant = self.get_tenant_from_request()
        group_id = request.data.get('group_id')
        operation = request.data.get('operation', 'create')
        
        if not tenant:
            return Response(
                {'error': 'Tenant não encontrado ou acesso negado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not group_id:
            return Response(
                {'error': 'ID do grupo é obrigatório'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if operation not in ['create', 'sync_members']:
            return Response(
                {'error': 'Operação inválida. Use: create, sync_members'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            managed_group = get_object_or_404(ManagedGroup, id=group_id, tenant=tenant)
            sync_service = M365SyncService(tenant)
            
            result = sync_service.sync_group_to_m365(managed_group, operation)
            
            return Response(result)
            
        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Erro na sincronização do grupo: {e}")
            return Response(
                {'error': 'Erro interno do servidor'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def sync_all_users(self, request):
        """Sincroniza todos os usuários do tenant com M365"""
        tenant = self.get_tenant_from_request()
        
        if not tenant:
            return Response(
                {'error': 'Tenant não encontrado ou acesso negado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            sync_service = M365SyncService(tenant)
            result = sync_service.sync_all_users()
            
            return Response(result)
            
        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Erro na sincronização em lote de usuários: {e}")
            return Response(
                {'error': 'Erro interno do servidor'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def sync_all_groups(self, request):
        """Sincroniza todos os grupos do tenant com M365"""
        tenant = self.get_tenant_from_request()
        
        if not tenant:
            return Response(
                {'error': 'Tenant não encontrado ou acesso negado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            sync_service = M365SyncService(tenant)
            result = sync_service.sync_all_groups()
            
            return Response(result)
            
        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Erro na sincronização em lote de grupos: {e}")
            return Response(
                {'error': 'Erro interno do servidor'},
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
            
            # Estatísticas de usuários
            users_stats = {
                'total': ManagedUser.objects.filter(tenant=tenant).count(),
                'synced': ManagedUser.objects.filter(
                    tenant=tenant, 
                    m365_object_id__isnull=False,
                    sync_status='synced'
                ).count(),
                'pending': ManagedUser.objects.filter(
                    tenant=tenant,
                    sync_status__in=['pending', 'error']
                ).count()
            }
            
            # Estatísticas de grupos
            groups_stats = {
                'total': ManagedGroup.objects.filter(tenant=tenant).count(),
                'synced': ManagedGroup.objects.filter(
                    tenant=tenant,
                    m365_object_id__isnull=False,
                    sync_status='synced'
                ).count(),
                'pending': ManagedGroup.objects.filter(
                    tenant=tenant,
                    sync_status__in=['pending', 'error']
                ).count()
            }
            
            return Response({
                'tenant_id': tenant.id,
                'tenant_name': tenant.name,
                'sync_enabled': config.sync_enabled,
                'connection_status': config.connection_status,
                'last_sync': config.last_sync,
                'last_error': config.last_error,
                'users': users_stats,
                'groups': groups_stats
            })
            
        except M365Configuration.DoesNotExist:
            return Response(
                {'error': 'Configuração M365 não encontrada'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Erro ao obter status de sincronização: {e}")
            return Response(
                {'error': 'Erro interno do servidor'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def create_user_in_m365(self, request):
        """Cria um usuário diretamente no M365 (sem criar ManagedUser)"""
        tenant = self.get_tenant_from_request()
        
        if not tenant:
            return Response(
                {'error': 'Tenant não encontrado ou acesso negado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        required_fields = ['displayName', 'userPrincipalName', 'mailNickname']
        user_data = {}
        
        for field in required_fields:
            value = request.data.get(field)
            if not value:
                return Response(
                    {'error': f'Campo obrigatório: {field}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            user_data[field] = value
        
        # Campos opcionais
        optional_fields = [
            'givenName', 'surname', 'jobTitle', 'department', 
            'officeLocation', 'password', 'accountEnabled'
        ]
        
        for field in optional_fields:
            if field in request.data:
                user_data[field] = request.data[field]
        
        try:
            sync_service = M365SyncService(tenant)
            result = sync_service.graph_client.create_user(user_data)
            
            return Response(result)
            
        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Erro ao criar usuário no M365: {e}")
            return Response(
                {'error': 'Erro interno do servidor'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def list_m365_users(self, request):
        """Lista usuários diretamente do M365"""
        tenant = self.get_tenant_from_request()
        
        if not tenant:
            return Response(
                {'error': 'Tenant não encontrado ou acesso negado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        filter_query = request.query_params.get('filter')
        select_fields = request.query_params.get('select')
        
        if select_fields:
            select_fields = select_fields.split(',')
        
        try:
            sync_service = M365SyncService(tenant)
            result = sync_service.graph_client.list_users(
                filter_query=filter_query,
                select_fields=select_fields
            )
            
            return Response(result)
            
        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Erro ao listar usuários do M365: {e}")
            return Response(
                {'error': 'Erro interno do servidor'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def list_m365_groups(self, request):
        """Lista grupos diretamente do M365"""
        tenant = self.get_tenant_from_request()
        
        if not tenant:
            return Response(
                {'error': 'Tenant não encontrado ou acesso negado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        filter_query = request.query_params.get('filter')
        
        try:
            sync_service = M365SyncService(tenant)
            result = sync_service.graph_client.list_groups(filter_query=filter_query)
            
            return Response(result)
            
        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Erro ao listar grupos do M365: {e}")
            return Response(
                {'error': 'Erro interno do servidor'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )