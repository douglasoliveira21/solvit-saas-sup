import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from django.utils import timezone
from django.db import transaction
from tenants.models import (
    Tenant, M365Configuration, ManagedUser, ManagedGroup
)
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
                         success: bool = True, details: Dict = None, error_message: str = None):
        """Cria log de auditoria para operações de sincronização"""
        try:
            AuditLog.objects.create(
                tenant=self.tenant,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                success=success,
                details=details or {},
                error_message=error_message,
                ip_address='127.0.0.1',  # Sistema interno
                user_agent='M365SyncService'
            )
        except Exception as e:
            logger.error(f"Erro ao criar log de auditoria: {e}")
    
    def test_connection(self) -> Dict[str, Any]:
        """Testa a conexão com Microsoft 365"""
        try:
            result = self.graph_client.test_connection()
            
            # Atualiza status da configuração
            if result['success']:
                self.config.connection_status = 'connected'
                self.config.last_error = None
            else:
                self.config.connection_status = 'error'
                self.config.last_error = result.get('message', 'Erro desconhecido')
            
            self.config.save()
            
            self._create_audit_log(
                action='test_connection',
                resource_type='m365_config',
                resource_id=str(self.config.id),
                success=result['success'],
                details=result,
                error_message=result.get('message') if not result['success'] else None
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Erro no teste de conexão M365: {e}")
            self.config.connection_status = 'error'
            self.config.last_error = str(e)
            self.config.save()
            
            return {
                'success': False,
                'message': f'Erro interno: {str(e)}'
            }
    
    def sync_user_to_m365(self, managed_user: ManagedUser, operation: str = 'create') -> Dict[str, Any]:
        """Sincroniza um usuário específico com M365"""
        if not self.config.sync_enabled:
            return {
                'success': False,
                'message': 'Sincronização M365 está desabilitada'
            }
        
        try:
            with transaction.atomic():
                if operation == 'create':
                    result = self._create_user_in_m365(managed_user)
                elif operation == 'update':
                    result = self._update_user_in_m365(managed_user)
                elif operation == 'disable':
                    result = self._disable_user_in_m365(managed_user)
                elif operation == 'enable':
                    result = self._enable_user_in_m365(managed_user)
                else:
                    raise ValueError(f"Operação inválida: {operation}")
                
                # Atualiza status de sincronização
                if result['success']:
                    managed_user.last_m365_sync = timezone.now()
                    managed_user.sync_status = 'synced'
                    
                    # Salva o ID do objeto M365 se for criação
                    if operation == 'create' and 'user_id' in result:
                        managed_user.m365_object_id = result['user_id']
                else:
                    managed_user.sync_status = 'error'
                
                managed_user.save()
                
                self._create_audit_log(
                    action=f'm365_user_{operation}',
                    resource_type='managed_user',
                    resource_id=str(managed_user.id),
                    success=result['success'],
                    details={
                        'user_id': managed_user.id,
                        'username': managed_user.username,
                        'operation': operation,
                        'result': result
                    },
                    error_message=result.get('message') if not result['success'] else None
                )
                
                return result
                
        except Exception as e:
            logger.error(f"Erro na sincronização do usuário {managed_user.username}: {e}")
            managed_user.sync_status = 'error'
            managed_user.save()
            
            return {
                'success': False,
                'message': f'Erro interno: {str(e)}'
            }
    
    def _create_user_in_m365(self, managed_user: ManagedUser) -> Dict[str, Any]:
        """Cria usuário no M365"""
        # Gera UPN baseado no domínio do tenant
        domain = self.tenant.domain or 'example.com'
        upn = f"{managed_user.username}@{domain}"
        
        user_data = {
            'displayName': managed_user.display_name or f"{managed_user.first_name} {managed_user.last_name}".strip(),
            'userPrincipalName': upn,
            'mailNickname': managed_user.username,
            'givenName': managed_user.first_name,
            'surname': managed_user.last_name,
            'accountEnabled': managed_user.is_active,
            'password': 'TempPassword123!',  # Senha temporária
            'forceChangePasswordNextSignIn': True
        }
        
        return self.graph_client.create_user(user_data)
    
    def _update_user_in_m365(self, managed_user: ManagedUser) -> Dict[str, Any]:
        """Atualiza usuário no M365"""
        if not managed_user.m365_object_id:
            return {
                'success': False,
                'message': 'Usuário não possui ID do M365'
            }
        
        user_data = {
            'displayName': managed_user.display_name or f"{managed_user.first_name} {managed_user.last_name}".strip(),
            'givenName': managed_user.first_name,
            'surname': managed_user.last_name,
            'accountEnabled': managed_user.is_active
        }
        
        return self.graph_client.update_user(managed_user.m365_object_id, user_data)
    
    def _disable_user_in_m365(self, managed_user: ManagedUser) -> Dict[str, Any]:
        """Desabilita usuário no M365"""
        if not managed_user.m365_object_id:
            return {
                'success': False,
                'message': 'Usuário não possui ID do M365'
            }
        
        return self.graph_client.disable_user(managed_user.m365_object_id)
    
    def _enable_user_in_m365(self, managed_user: ManagedUser) -> Dict[str, Any]:
        """Habilita usuário no M365"""
        if not managed_user.m365_object_id:
            return {
                'success': False,
                'message': 'Usuário não possui ID do M365'
            }
        
        return self.graph_client.enable_user(managed_user.m365_object_id)
    
    def sync_group_to_m365(self, managed_group: ManagedGroup, operation: str = 'create') -> Dict[str, Any]:
        """Sincroniza um grupo específico com M365"""
        if not self.config.sync_enabled:
            return {
                'success': False,
                'message': 'Sincronização M365 está desabilitada'
            }
        
        try:
            with transaction.atomic():
                if operation == 'create':
                    result = self._create_group_in_m365(managed_group)
                elif operation == 'sync_members':
                    result = self._sync_group_members_to_m365(managed_group)
                else:
                    raise ValueError(f"Operação inválida: {operation}")
                
                # Atualiza status de sincronização
                if result['success']:
                    managed_group.last_m365_sync = timezone.now()
                    managed_group.sync_status = 'synced'
                    
                    # Salva o ID do objeto M365 se for criação
                    if operation == 'create' and 'group_id' in result:
                        managed_group.m365_object_id = result['group_id']
                else:
                    managed_group.sync_status = 'error'
                
                managed_group.save()
                
                self._create_audit_log(
                    action=f'm365_group_{operation}',
                    resource_type='managed_group',
                    resource_id=str(managed_group.id),
                    success=result['success'],
                    details={
                        'group_id': managed_group.id,
                        'group_name': managed_group.name,
                        'operation': operation,
                        'result': result
                    },
                    error_message=result.get('message') if not result['success'] else None
                )
                
                return result
                
        except Exception as e:
            logger.error(f"Erro na sincronização do grupo {managed_group.name}: {e}")
            managed_group.sync_status = 'error'
            managed_group.save()
            
            return {
                'success': False,
                'message': f'Erro interno: {str(e)}'
            }
    
    def _create_group_in_m365(self, managed_group: ManagedGroup) -> Dict[str, Any]:
        """Cria grupo no M365"""
        group_data = {
            'displayName': managed_group.name,
            'mailNickname': managed_group.name.lower().replace(' ', ''),
            'description': managed_group.description or f'Grupo gerenciado: {managed_group.name}',
            'securityEnabled': True,
            'mailEnabled': False
        }
        
        # Define tipo do grupo
        if managed_group.group_type == 'security':
            group_data['groupTypes'] = []
        elif managed_group.group_type == 'distribution':
            group_data['mailEnabled'] = True
            group_data['securityEnabled'] = False
        
        return self.graph_client.create_group(group_data)
    
    def _sync_group_members_to_m365(self, managed_group: ManagedGroup) -> Dict[str, Any]:
        """Sincroniza membros do grupo com M365"""
        if not managed_group.m365_object_id:
            return {
                'success': False,
                'message': 'Grupo não possui ID do M365'
            }
        
        # Obtém membros atuais no M365
        current_members_result = self.graph_client.get_group_members(managed_group.m365_object_id)
        
        if not current_members_result['success']:
            return current_members_result
        
        current_m365_members = {member['id'] for member in current_members_result['members']}
        
        # Obtém membros desejados (usuários com M365 ID)
        desired_members = set()
        for user in managed_group.members.filter(m365_object_id__isnull=False):
            desired_members.add(user.m365_object_id)
        
        # Adiciona novos membros
        members_to_add = desired_members - current_m365_members
        add_results = []
        
        for user_id in members_to_add:
            result = self.graph_client.add_group_member(managed_group.m365_object_id, user_id)
            add_results.append(result)
        
        # Remove membros que não deveriam estar
        members_to_remove = current_m365_members - desired_members
        remove_results = []
        
        for user_id in members_to_remove:
            result = self.graph_client.remove_group_member(managed_group.m365_object_id, user_id)
            remove_results.append(result)
        
        # Verifica se todas as operações foram bem-sucedidas
        all_successful = all(r['success'] for r in add_results + remove_results)
        
        return {
            'success': all_successful,
            'message': f'Sincronização de membros concluída. Adicionados: {len(members_to_add)}, Removidos: {len(members_to_remove)}',
            'details': {
                'added': len(members_to_add),
                'removed': len(members_to_remove),
                'add_results': add_results,
                'remove_results': remove_results
            }
        }
    
    def sync_all_users(self) -> Dict[str, Any]:
        """Sincroniza todos os usuários do tenant com M365"""
        if not self.config.sync_enabled:
            return {
                'success': False,
                'message': 'Sincronização M365 está desabilitada'
            }
        
        users = ManagedUser.objects.filter(tenant=self.tenant, is_active=True)
        results = {
            'total': users.count(),
            'success': 0,
            'errors': 0,
            'details': []
        }
        
        for user in users:
            # Determina operação baseada no status atual
            if user.m365_object_id:
                operation = 'update'
            else:
                operation = 'create'
            
            result = self.sync_user_to_m365(user, operation)
            
            if result['success']:
                results['success'] += 1
            else:
                results['errors'] += 1
            
            results['details'].append({
                'user_id': user.id,
                'username': user.username,
                'operation': operation,
                'success': result['success'],
                'message': result.get('message')
            })
        
        # Atualiza timestamp da última sincronização
        self.config.last_sync = timezone.now()
        self.config.save()
        
        self._create_audit_log(
            action='m365_bulk_sync_users',
            resource_type='tenant',
            resource_id=str(self.tenant.id),
            success=results['errors'] == 0,
            details=results
        )
        
        return {
            'success': results['errors'] == 0,
            'message': f"Sincronização concluída. Sucessos: {results['success']}, Erros: {results['errors']}",
            'results': results
        }
    
    def sync_all_groups(self) -> Dict[str, Any]:
        """Sincroniza todos os grupos do tenant com M365"""
        if not self.config.sync_enabled:
            return {
                'success': False,
                'message': 'Sincronização M365 está desabilitada'
            }
        
        groups = ManagedGroup.objects.filter(tenant=self.tenant, is_active=True)
        results = {
            'total': groups.count(),
            'success': 0,
            'errors': 0,
            'details': []
        }
        
        for group in groups:
            # Determina operação baseada no status atual
            if group.m365_object_id:
                operation = 'sync_members'
            else:
                operation = 'create'
            
            result = self.sync_group_to_m365(group, operation)
            
            if result['success']:
                results['success'] += 1
            else:
                results['errors'] += 1
            
            results['details'].append({
                'group_id': group.id,
                'group_name': group.name,
                'operation': operation,
                'success': result['success'],
                'message': result.get('message')
            })
        
        # Atualiza timestamp da última sincronização
        self.config.last_sync = timezone.now()
        self.config.save()
        
        self._create_audit_log(
            action='m365_bulk_sync_groups',
            resource_type='tenant',
            resource_id=str(self.tenant.id),
            success=results['errors'] == 0,
            details=results
        )
        
        return {
            'success': results['errors'] == 0,
            'message': f"Sincronização concluída. Sucessos: {results['success']}, Erros: {results['errors']}",
            'results': results
        }