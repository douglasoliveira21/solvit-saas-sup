import logging
from rest_framework.permissions import BasePermission
from .authentication import AgentUser

logger = logging.getLogger('agent_api')


class IsAgent(BasePermission):
    """
    Permissão que verifica se o usuário é um agente autenticado.
    """
    
    def has_permission(self, request, view):
        return isinstance(request.user, AgentUser)


class HasAgentPermission(BasePermission):
    """
    Permissão que verifica se o agente tem uma permissão específica.
    
    Uso:
    permission_classes = [IsAgent, HasAgentPermission]
    required_permissions = ['ad.sync_users', 'ad.read_config']
    """
    
    def has_permission(self, request, view):
        if not isinstance(request.user, AgentUser):
            return False
        
        # Obtém as permissões necessárias da view
        required_permissions = getattr(view, 'required_permissions', [])
        
        if not required_permissions:
            return True
        
        # Verifica se o agente tem todas as permissões necessárias
        return request.user.has_perms(required_permissions)
    
    def has_object_permission(self, request, view, obj):
        # Para permissões de objeto, verifica se o objeto pertence ao tenant do agente
        if hasattr(obj, 'tenant'):
            return obj.tenant == request.user.tenant
        
        return True


class CanSyncUsers(BasePermission):
    """
    Permissão específica para sincronização de usuários.
    """
    
    def has_permission(self, request, view):
        if not isinstance(request.user, AgentUser):
            return False
        
        return request.user.has_perm('ad.sync_users')


class CanSyncGroups(BasePermission):
    """
    Permissão específica para sincronização de grupos.
    """
    
    def has_permission(self, request, view):
        if not isinstance(request.user, AgentUser):
            return False
        
        return request.user.has_perm('ad.sync_groups')


class CanReadConfig(BasePermission):
    """
    Permissão específica para leitura de configurações.
    """
    
    def has_permission(self, request, view):
        if not isinstance(request.user, AgentUser):
            return False
        
        return request.user.has_perm('ad.read_config')


class CanUpdateStatus(BasePermission):
    """
    Permissão específica para atualização de status do agente.
    """
    
    def has_permission(self, request, view):
        if not isinstance(request.user, AgentUser):
            return False
        
        return request.user.has_perm('agent.update_status')


class CanSendLogs(BasePermission):
    """
    Permissão específica para envio de logs.
    """
    
    def has_permission(self, request, view):
        if not isinstance(request.user, AgentUser):
            return False
        
        return request.user.has_perm('agent.send_logs')