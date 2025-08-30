import logging
from datetime import timedelta
from django.utils import timezone
from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from tenants.models import ADConfiguration, ManagedUser, ManagedGroup
from core.models import AuditLog
from .authentication import AgentAPIKeyAuthentication, AgentUser
from .permissions import (
    IsAgent, HasAgentPermission, CanSyncUsers, CanSyncGroups,
    CanReadConfig, CanUpdateStatus, CanSendLogs
)
from .serializers import (
    AgentHeartbeatSerializer, ADUserSyncSerializer, ADGroupSyncSerializer,
    ADConfigurationResponseSerializer, AgentLogSerializer, SyncResultSerializer,
    BulkSyncResultSerializer, AgentStatusResponseSerializer
)

logger = logging.getLogger('agent_api')


class AgentHeartbeatView(APIView):
    """
    Endpoint para heartbeat do agente.
    """
    authentication_classes = [AgentAPIKeyAuthentication]
    permission_classes = [IsAgent, CanUpdateStatus]
    
    def post(self, request):
        """
        Recebe heartbeat do agente e atualiza status.
        """
        serializer = AgentHeartbeatSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Dados inválidos', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Obtém configuração AD do tenant
            ad_config = get_object_or_404(
                ADConfiguration,
                tenant=request.user.tenant
            )
            
            # Atualiza informações do agente
            validated_data = serializer.validated_data
            
            ad_config.agent_last_heartbeat = timezone.now()
            ad_config.agent_version = validated_data['agent_version']
            ad_config.agent_status = validated_data['status']
            
            if 'error_message' in validated_data:
                ad_config.last_error = validated_data['error_message']
            
            ad_config.save()
            
            # Cria log de auditoria
            AuditLog.objects.create(
                tenant=request.user.tenant,
                action='agent_heartbeat',
                resource_type='ad_config',
                resource_id=str(ad_config.id),
                success=True,
                details={
                    'agent_version': validated_data['agent_version'],
                    'status': validated_data['status'],
                    'system_info': validated_data.get('system_info', {})
                },
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Verifica se há tarefas pendentes ou configuração atualizada
            config_updated = self._check_config_updated(ad_config)
            pending_tasks = self._get_pending_tasks(request.user.tenant)
            
            response_data = {
                'agent_id': request.user.api_key.name,
                'tenant_name': request.user.tenant.name,
                'status': 'received',
                'last_heartbeat': ad_config.agent_last_heartbeat,
                'configuration_updated': config_updated,
                'pending_tasks': pending_tasks,
                'message': 'Heartbeat recebido com sucesso'
            }
            
            response_serializer = AgentStatusResponseSerializer(data=response_data)
            response_serializer.is_valid(raise_exception=True)
            
            logger.info(
                f"Heartbeat recebido do agente {request.user.api_key.name} "
                f"(Tenant: {request.user.tenant.name})"
            )
            
            return Response(response_serializer.data)
            
        except Exception as e:
            logger.error(f"Erro no processamento do heartbeat: {e}")
            return Response(
                {'error': 'Erro interno do servidor'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get_client_ip(self, request):
        """Obtém IP do cliente."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def _check_config_updated(self, ad_config):
        """Verifica se a configuração foi atualizada recentemente."""
        # Considera atualizada se foi modificada nas últimas 5 minutos
        threshold = timezone.now() - timedelta(minutes=5)
        return ad_config.updated_at > threshold
    
    def _get_pending_tasks(self, tenant):
        """Obtém lista de tarefas pendentes para o agente."""
        tasks = []
        
        # Verifica se há usuários pendentes de sincronização
        pending_users = ManagedUser.objects.filter(
            tenant=tenant,
            sync_status__in=['pending', 'error'],
            is_active=True
        ).count()
        
        if pending_users > 0:
            tasks.append(f'sync_users:{pending_users}')
        
        # Verifica se há grupos pendentes de sincronização
        pending_groups = ManagedGroup.objects.filter(
            tenant=tenant,
            sync_status__in=['pending', 'error'],
            is_active=True
        ).count()
        
        if pending_groups > 0:
            tasks.append(f'sync_groups:{pending_groups}')
        
        return tasks


class AgentConfigurationView(APIView):
    """
    Endpoint para obter configuração do AD.
    """
    authentication_classes = [AgentAPIKeyAuthentication]
    permission_classes = [IsAgent, CanReadConfig]
    
    def get(self, request):
        """
        Retorna configuração do AD para o agente.
        """
        try:
            ad_config = get_object_or_404(
                ADConfiguration,
                tenant=request.user.tenant
            )
            
            serializer = ADConfigurationResponseSerializer(ad_config)
            
            # Adiciona senha descriptografada (apenas para o agente)
            response_data = serializer.data.copy()
            response_data['service_account_password'] = ad_config.get_decrypted_password()
            
            logger.info(
                f"Configuração AD enviada para agente {request.user.api_key.name} "
                f"(Tenant: {request.user.tenant.name})"
            )
            
            return Response(response_data)
            
        except Exception as e:
            logger.error(f"Erro ao obter configuração AD: {e}")
            return Response(
                {'error': 'Erro interno do servidor'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AgentSyncViewSet(viewsets.ViewSet):
    """
    ViewSet para operações de sincronização do agente.
    """
    authentication_classes = [AgentAPIKeyAuthentication]
    permission_classes = [IsAgent]
    
    @action(detail=False, methods=['post'], permission_classes=[IsAgent, CanSyncUsers])
    def sync_users(self, request):
        """
        Sincroniza usuários do AD.
        """
        users_data = request.data.get('users', [])
        
        if not isinstance(users_data, list):
            return Response(
                {'error': 'Campo "users" deve ser uma lista'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        results = []
        successful = 0
        failed = 0
        
        try:
            with transaction.atomic():
                for user_data in users_data:
                    serializer = ADUserSyncSerializer(
                        data=user_data,
                        context={'tenant': request.user.tenant}
                    )
                    
                    if serializer.is_valid():
                        result = self._process_user_sync(serializer.validated_data, request.user.tenant)
                        if result['success']:
                            successful += 1
                        else:
                            failed += 1
                        results.append(result)
                    else:
                        failed += 1
                        results.append({
                            'operation': 'sync',
                            'resource_type': 'user',
                            'resource_id': user_data.get('username', 'unknown'),
                            'success': False,
                            'message': f"Dados inválidos: {serializer.errors}",
                            'timestamp': timezone.now()
                        })
                
                # Cria log de auditoria
                AuditLog.objects.create(
                    tenant=request.user.tenant,
                    action='agent_sync_users',
                    resource_type='tenant',
                    resource_id=str(request.user.tenant.id),
                    success=failed == 0,
                    details={
                        'total_processed': len(users_data),
                        'successful': successful,
                        'failed': failed,
                        'agent': request.user.api_key.name
                    },
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                return Response({
                    'sync_type': 'users',
                    'total_processed': len(users_data),
                    'successful': successful,
                    'failed': failed,
                    'results': results
                })
                
        except Exception as e:
            logger.error(f"Erro na sincronização de usuários: {e}")
            return Response(
                {'error': 'Erro interno do servidor'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'], permission_classes=[IsAgent, CanSyncGroups])
    def sync_groups(self, request):
        """
        Sincroniza grupos do AD.
        """
        groups_data = request.data.get('groups', [])
        
        if not isinstance(groups_data, list):
            return Response(
                {'error': 'Campo "groups" deve ser uma lista'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        results = []
        successful = 0
        failed = 0
        
        try:
            with transaction.atomic():
                for group_data in groups_data:
                    serializer = ADGroupSyncSerializer(
                        data=group_data,
                        context={'tenant': request.user.tenant}
                    )
                    
                    if serializer.is_valid():
                        result = self._process_group_sync(serializer.validated_data, request.user.tenant)
                        if result['success']:
                            successful += 1
                        else:
                            failed += 1
                        results.append(result)
                    else:
                        failed += 1
                        results.append({
                            'operation': 'sync',
                            'resource_type': 'group',
                            'resource_id': group_data.get('name', 'unknown'),
                            'success': False,
                            'message': f"Dados inválidos: {serializer.errors}",
                            'timestamp': timezone.now()
                        })
                
                # Cria log de auditoria
                AuditLog.objects.create(
                    tenant=request.user.tenant,
                    action='agent_sync_groups',
                    resource_type='tenant',
                    resource_id=str(request.user.tenant.id),
                    success=failed == 0,
                    details={
                        'total_processed': len(groups_data),
                        'successful': successful,
                        'failed': failed,
                        'agent': request.user.api_key.name
                    },
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                return Response({
                    'sync_type': 'groups',
                    'total_processed': len(groups_data),
                    'successful': successful,
                    'failed': failed,
                    'results': results
                })
                
        except Exception as e:
            logger.error(f"Erro na sincronização de grupos: {e}")
            return Response(
                {'error': 'Erro interno do servidor'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _process_user_sync(self, user_data, tenant):
        """Processa sincronização de um usuário."""
        try:
            # Busca usuário existente pelo GUID do AD
            user, created = ManagedUser.objects.get_or_create(
                tenant=tenant,
                ad_object_guid=user_data['ad_object_guid'],
                defaults={
                    'username': user_data['username'],
                    'email': user_data['email'],
                    'first_name': user_data.get('first_name', ''),
                    'last_name': user_data.get('last_name', ''),
                    'display_name': user_data.get('display_name', ''),
                    'is_active': user_data['is_active'],
                    'last_ad_sync': timezone.now(),
                    'sync_status': 'synced'
                }
            )
            
            if not created:
                # Atualiza usuário existente
                user.username = user_data['username']
                user.email = user_data['email']
                user.first_name = user_data.get('first_name', '')
                user.last_name = user_data.get('last_name', '')
                user.display_name = user_data.get('display_name', '')
                user.is_active = user_data['is_active']
                user.last_ad_sync = timezone.now()
                user.sync_status = 'synced'
                user.save()
            
            operation = 'create' if created else 'update'
            
            return {
                'operation': operation,
                'resource_type': 'user',
                'resource_id': str(user.id),
                'success': True,
                'message': f"Usuário {operation}d com sucesso",
                'timestamp': timezone.now()
            }
            
        except Exception as e:
            logger.error(f"Erro ao processar usuário {user_data.get('username')}: {e}")
            return {
                'operation': 'sync',
                'resource_type': 'user',
                'resource_id': user_data.get('username', 'unknown'),
                'success': False,
                'message': str(e),
                'timestamp': timezone.now()
            }
    
    def _process_group_sync(self, group_data, tenant):
        """Processa sincronização de um grupo."""
        try:
            # Busca grupo existente pelo GUID do AD
            group, created = ManagedGroup.objects.get_or_create(
                tenant=tenant,
                ad_object_guid=group_data['ad_object_guid'],
                defaults={
                    'name': group_data['name'],
                    'description': group_data.get('description', ''),
                    'group_type': group_data['group_type'],
                    'is_active': group_data['is_active'],
                    'last_ad_sync': timezone.now(),
                    'sync_status': 'synced'
                }
            )
            
            if not created:
                # Atualiza grupo existente
                group.name = group_data['name']
                group.description = group_data.get('description', '')
                group.group_type = group_data['group_type']
                group.is_active = group_data['is_active']
                group.last_ad_sync = timezone.now()
                group.sync_status = 'synced'
                group.save()
            
            # Atualiza membros do grupo
            if 'member_guids' in group_data:
                self._update_group_members(group, group_data['member_guids'], tenant)
            
            operation = 'create' if created else 'update'
            
            return {
                'operation': operation,
                'resource_type': 'group',
                'resource_id': str(group.id),
                'success': True,
                'message': f"Grupo {operation}d com sucesso",
                'timestamp': timezone.now()
            }
            
        except Exception as e:
            logger.error(f"Erro ao processar grupo {group_data.get('name')}: {e}")
            return {
                'operation': 'sync',
                'resource_type': 'group',
                'resource_id': group_data.get('name', 'unknown'),
                'success': False,
                'message': str(e),
                'timestamp': timezone.now()
            }
    
    def _update_group_members(self, group, member_guids, tenant):
        """Atualiza membros do grupo."""
        # Busca usuários pelos GUIDs do AD
        members = ManagedUser.objects.filter(
            tenant=tenant,
            ad_object_guid__in=member_guids
        )
        
        # Atualiza membros do grupo
        group.members.set(members)


class AgentLogsView(APIView):
    """
    Endpoint para receber logs do agente.
    """
    authentication_classes = [AgentAPIKeyAuthentication]
    permission_classes = [IsAgent, CanSendLogs]
    
    def post(self, request):
        """
        Recebe logs do agente.
        """
        logs_data = request.data.get('logs', [])
        
        if not isinstance(logs_data, list):
            return Response(
                {'error': 'Campo "logs" deve ser uma lista'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        processed = 0
        errors = 0
        
        for log_data in logs_data:
            serializer = AgentLogSerializer(data=log_data)
            
            if serializer.is_valid():
                # Processa o log (pode salvar em banco, enviar para sistema de logs, etc.)
                self._process_agent_log(serializer.validated_data, request.user)
                processed += 1
            else:
                errors += 1
                logger.warning(f"Log inválido recebido do agente: {serializer.errors}")
        
        return Response({
            'message': 'Logs processados',
            'processed': processed,
            'errors': errors
        })
    
    def _process_agent_log(self, log_data, agent_user):
        """Processa um log do agente."""
        # Aqui você pode implementar a lógica para processar os logs
        # Por exemplo: salvar em banco, enviar para sistema de monitoramento, etc.
        
        log_message = (
            f"[AGENT:{agent_user.api_key.name}] "
            f"[{log_data['level']}] "
            f"{log_data['message']}"
        )
        
        # Log usando o sistema de logging do Django
        if log_data['level'] == 'DEBUG':
            logger.debug(log_message)
        elif log_data['level'] == 'INFO':
            logger.info(log_message)
        elif log_data['level'] == 'WARNING':
            logger.warning(log_message)
        elif log_data['level'] == 'ERROR':
            logger.error(log_message)
        elif log_data['level'] == 'CRITICAL':
            logger.critical(log_message)