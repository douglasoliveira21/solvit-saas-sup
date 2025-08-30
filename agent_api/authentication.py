import logging
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import AnonymousUser
from core.models import APIKey
from tenants.models import Tenant

logger = logging.getLogger('agent_api')


class AgentAPIKeyAuthentication(BaseAuthentication):
    """
    Autenticação baseada em API Key para agentes on-premises.
    
    O agente deve enviar a API Key no header:
    Authorization: Agent-Key <api_key>
    """
    
    keyword = 'Agent-Key'
    
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        
        if not auth_header:
            return None
        
        try:
            keyword, api_key = auth_header.split(' ', 1)
        except ValueError:
            return None
        
        if keyword != self.keyword:
            return None
        
        return self.authenticate_credentials(api_key, request)
    
    def authenticate_credentials(self, api_key, request):
        """
        Autentica as credenciais da API Key.
        """
        try:
            api_key_obj = APIKey.objects.select_related('tenant').get(
                key=api_key,
                is_active=True
            )
        except APIKey.DoesNotExist:
            logger.warning(f"Tentativa de acesso com API Key inválida: {api_key[:8]}...")
            raise AuthenticationFailed('API Key inválida')
        
        # Verifica se a API Key não expirou
        if api_key_obj.is_expired():
            logger.warning(f"Tentativa de acesso com API Key expirada: {api_key_obj.name}")
            raise AuthenticationFailed('API Key expirada')
        
        # Verifica se o tenant está ativo
        if not api_key_obj.tenant.is_active:
            logger.warning(f"Tentativa de acesso com tenant inativo: {api_key_obj.tenant.name}")
            raise AuthenticationFailed('Tenant inativo')
        
        # Atualiza último uso
        api_key_obj.update_last_used()
        
        # Cria um usuário fictício para representar o agente
        agent_user = AgentUser(api_key_obj)
        
        logger.info(f"Agente autenticado: {api_key_obj.name} (Tenant: {api_key_obj.tenant.name})")
        
        return (agent_user, api_key_obj)
    
    def authenticate_header(self, request):
        """
        Retorna o header de autenticação esperado.
        """
        return self.keyword


class AgentUser:
    """
    Classe que representa um usuário agente para fins de autenticação.
    """
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.tenant = api_key.tenant
        self.is_authenticated = True
        self.is_anonymous = False
        self.is_active = True
        self.is_staff = False
        self.is_superuser = False
        self.username = f"agent_{api_key.name}"
        self.id = None
    
    def __str__(self):
        return f"Agent: {self.api_key.name} (Tenant: {self.tenant.name})"
    
    def has_perm(self, perm, obj=None):
        """
        Verifica se o agente tem uma permissão específica.
        """
        # Implementa lógica de permissões baseada nas permissões da API Key
        if not self.api_key.permissions:
            return False
        
        return perm in self.api_key.permissions
    
    def has_perms(self, perm_list, obj=None):
        """
        Verifica se o agente tem todas as permissões da lista.
        """
        return all(self.has_perm(perm, obj) for perm in perm_list)
    
    def has_module_perms(self, app_label):
        """
        Verifica se o agente tem permissões para um módulo específico.
        """
        if not self.api_key.permissions:
            return False
        
        # Verifica se há alguma permissão que comece com o app_label
        return any(perm.startswith(f"{app_label}.") for perm in self.api_key.permissions)
    
    def get_all_permissions(self, obj=None):
        """
        Retorna todas as permissões do agente.
        """
        return set(self.api_key.permissions or [])