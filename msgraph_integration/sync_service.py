import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.models import User
from tenants.models import Tenant, M365Configuration, ManagedUser, ManagedGroup, GroupMembership
from core.models import AuditLog
from .graph_client import MicrosoftGraphClient, GraphAPIError

logger = logging.getLogger('msgraph_integration')


class M365SyncService:
    """Serviço para sincronização com Microsoft 365"""
    
    def __init__(self, tenant: Tenant):
        self.tenant = tenant
        self.config = None
        self.graph_client = None
        
        try:
            self.config = M365Configuration.objects.get(tenant=tenant)
            self.graph_client = MicrosoftGraphClient(self.config)
        except M365Configuration.DoesNotExist:
            raise ValueError(f"Configuração M365 não encontrada para o tenant {tenant.name}")
    
    def _create_audit_log(self, action: str, resource_type: str, resource_id: str = None, 
                         success: bool = True, metadata: Dict = None, error_message: str = None):
        """Cria log de auditoria para operações de sincronização"""
        AuditLog.objects.create(
            tenant=self.tenant,
            user=None,  # Operação do sistema
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=f"M365 Sync - {action}",
            description=f"Sincronização M365: {action} {resource_type}",
            success=success,
            metadata=metadata or {},
            error_message=error_message,
            ip_address='127.0.0.1',  # Sistema interno
            user_agent='M365SyncService'
        )
    
    def test_connection(self) -> Dict[str, Any]:
        """Testa a conexão com Microsoft 365"""
        try:
            if not self.graph_client:
                return {
                    'success': False,
                    'error': 'Cliente Graph não configurado'
                }
            
            # Tenta fazer uma chamada simples para testar a conexão
            result = self.graph_client.test_connection()
            
            self._create_audit_log(
                action='SYNC',
                resource_type='SYSTEM',
                success=result['success'],
                metadata={'test_connection': result}
            )
            
            return result
            
        except Exception as e:
            error_msg = f"Erro inesperado: {str(e)}"
            
            self._create_audit_log(
                action='SYNC',
                resource_type='SYSTEM',
                success=False,
                error_message=error_msg
            )
            
            return {
                'success': False,
                'error': error_msg
            }
    
    def sync_users(self) -> Dict[str, Any]:
        """Sincroniza usuários do Microsoft 365"""
        if not self.config.sync_enabled or not self.config.sync_users:
            return {'success': False, 'error': 'Sincronização de usuários desabilitada'}
        
        try:
            # Obtém usuários do Microsoft Graph
            filter_query = self.config.user_filter if self.config.user_filter else None
            select_fields = ['id', 'userPrincipalName', 'displayName', 'givenName', 'surname', 'mail', 'department', 'jobTitle', 'officeLocation', 'manager']
            
            ms_users = self.graph_client.get_users(filter_query=filter_query, select_fields=select_fields)
            
            synced_count = 0
            errors = []
            
            with transaction.atomic():
                for ms_user in ms_users:
                    try:
                        self._sync_single_user(ms_user)
                        synced_count += 1
                    except Exception as e:
                        errors.append(f"Erro ao sincronizar usuário {ms_user.get('userPrincipalName', 'N/A')}: {str(e)}")
                        logger.error(f"Erro ao sincronizar usuário: {str(e)}")
            
            # Atualiza status da configuração
            self.config.last_sync_at = timezone.now()
            self.config.last_sync_status = 'SUCCESS' if not errors else 'ERROR'
            self.config.last_sync_message = f"Sincronizados {synced_count} usuários. {len(errors)} erros."
            self.config.save()
            
            self._create_audit_log(
                action='SYNC',
                resource_type='USER',
                success=len(errors) == 0,
                metadata={
                    'synced_count': synced_count,
                    'error_count': len(errors),
                    'errors': errors[:5]  # Primeiros 5 erros
                }
            )
            
            return {
                'success': len(errors) == 0,
                'synced_count': synced_count,
                'error_count': len(errors),
                'errors': errors
            }
            
        except Exception as e:
            error_msg = f"Erro na sincronização de usuários: {str(e)}"
            logger.error(error_msg)
            
            self.config.last_sync_at = timezone.now()
            self.config.last_sync_status = 'ERROR'
            self.config.last_sync_message = error_msg
            self.config.save()
            
            self._create_audit_log(
                action='SYNC',
                resource_type='USER',
                success=False,
                error_message=error_msg
            )
            
            return {'success': False, 'error': error_msg}
    
    def _sync_single_user(self, ms_user: Dict[str, Any]):
        """Sincroniza um único usuário"""
        email = ms_user.get('mail') or ms_user.get('userPrincipalName')
        if not email:
            raise ValueError("Usuário sem email válido")
        
        # Busca ou cria o usuário Django
        user, created = User.objects.get_or_create(
            username=email,
            defaults={
                'email': email,
                'first_name': ms_user.get('givenName', ''),
                'last_name': ms_user.get('surname', ''),
                'is_active': True
            }
        )
        
        # Atualiza dados se não foi criado agora
        if not created:
            user.email = email
            user.first_name = ms_user.get('givenName', '')
            user.last_name = ms_user.get('surname', '')
            user.save()
        
        # Busca ou cria o ManagedUser
        managed_user, _ = ManagedUser.objects.get_or_create(
            tenant=self.tenant,
            user=user,
            defaults={
                'external_id': ms_user.get('id'),
                'source': 'M365',
                'sync_enabled': True
            }
        )
        
        # Atualiza metadados
        managed_user.external_id = ms_user.get('id')
        managed_user.department = ms_user.get('department', '')
        managed_user.job_title = ms_user.get('jobTitle', '')
        managed_user.office_location = ms_user.get('officeLocation', '')
        managed_user.last_synced_at = timezone.now()
        managed_user.save()
    
    def sync_groups(self) -> Dict[str, Any]:
        """Sincroniza grupos do Microsoft 365"""
        if not self.config.sync_enabled or not self.config.sync_groups:
            return {'success': False, 'error': 'Sincronização de grupos desabilitada'}
        
        try:
            # Obtém grupos do Microsoft Graph
            filter_query = self.config.group_filter if self.config.group_filter else None
            select_fields = ['id', 'displayName', 'description', 'mail']
            
            ms_groups = self.graph_client.get_groups(filter_query=filter_query, select_fields=select_fields)
            
            synced_count = 0
            errors = []
            
            with transaction.atomic():
                for ms_group in ms_groups:
                    try:
                        self._sync_single_group(ms_group)
                        synced_count += 1
                    except Exception as e:
                        errors.append(f"Erro ao sincronizar grupo {ms_group.get('displayName', 'N/A')}: {str(e)}")
                        logger.error(f"Erro ao sincronizar grupo: {str(e)}")
            
            self._create_audit_log(
                action='SYNC',
                resource_type='GROUP',
                success=len(errors) == 0,
                metadata={
                    'synced_count': synced_count,
                    'error_count': len(errors),
                    'errors': errors[:5]
                }
            )
            
            return {
                'success': len(errors) == 0,
                'synced_count': synced_count,
                'error_count': len(errors),
                'errors': errors
            }
            
        except Exception as e:
            error_msg = f"Erro na sincronização de grupos: {str(e)}"
            logger.error(error_msg)
            
            self._create_audit_log(
                action='SYNC',
                resource_type='GROUP',
                success=False,
                error_message=error_msg
            )
            
            return {'success': False, 'error': error_msg}
    
    def _sync_single_group(self, ms_group: Dict[str, Any]):
        """Sincroniza um único grupo"""
        group_name = ms_group.get('displayName')
        if not group_name:
            raise ValueError("Grupo sem nome válido")
        
        # Busca ou cria o grupo
        managed_group, _ = ManagedGroup.objects.get_or_create(
            tenant=self.tenant,
            name=group_name,
            defaults={
                'external_id': ms_group.get('id'),
                'source': 'M365',
                'description': ms_group.get('description', ''),
                'sync_enabled': True
            }
        )
        
        # Atualiza dados
        managed_group.external_id = ms_group.get('id')
        managed_group.description = ms_group.get('description', '')
        managed_group.last_synced_at = timezone.now()
        managed_group.save()
        
        # Sincroniza membros do grupo
        try:
            members = self.graph_client.get_group_members(ms_group.get('id'))
            self._sync_group_members(managed_group, members)
        except Exception as e:
            logger.warning(f"Erro ao sincronizar membros do grupo {group_name}: {str(e)}")
    
    def _sync_group_members(self, managed_group: ManagedGroup, members: List[Dict[str, Any]]):
        """Sincroniza membros de um grupo"""
        # Remove membros atuais
        GroupMembership.objects.filter(group=managed_group).delete()
        
        # Adiciona novos membros
        for member in members:
            if member.get('@odata.type') == '#microsoft.graph.user':
                email = member.get('mail') or member.get('userPrincipalName')
                if email:
                    try:
                        user = User.objects.get(username=email)
                        managed_user = ManagedUser.objects.get(tenant=self.tenant, user=user)
                        
                        GroupMembership.objects.create(
                            group=managed_group,
                            user=managed_user,
                            last_synced_at=timezone.now()
                        )
                    except (User.DoesNotExist, ManagedUser.DoesNotExist):
                        logger.warning(f"Usuário {email} não encontrado para adicionar ao grupo {managed_group.name}")
    
    def full_sync(self) -> Dict[str, Any]:
        """Executa sincronização completa de usuários e grupos"""
        results = {
            'users': self.sync_users(),
            'groups': self.sync_groups()
        }
        
        overall_success = results['users']['success'] and results['groups']['success']
        
        self._create_audit_log(
            action='SYNC',
            resource_type='SYSTEM',
            success=overall_success,
            metadata={'full_sync_results': results}
        )
        
        return {
            'success': overall_success,
            'results': results
        }