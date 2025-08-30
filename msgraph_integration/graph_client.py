import logging
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
from tenants.models import M365Configuration

logger = logging.getLogger('msgraph_integration')


class GraphAPIError(Exception):
    """Exceção customizada para erros da Graph API"""
    def __init__(self, message: str, status_code: int = None, error_code: str = None):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(self.message)


class MicrosoftGraphClient:
    """Cliente para interação com Microsoft Graph API"""
    
    BASE_URL = "https://graph.microsoft.com/v1.0"
    TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    
    def __init__(self, config: M365Configuration):
        self.config = config
        self.client_id = config.client_id
        self.client_secret = config.get_decrypted_client_secret()
        self.tenant_id = config.tenant_id
        self._access_token = None
        self._token_expires_at = None
    
    def _get_cache_key(self, suffix: str) -> str:
        """Gera chave de cache para o tenant"""
        return f"msgraph_token_{self.tenant_id}_{suffix}"
    
    def _get_access_token(self) -> str:
        """Obtém token de acesso, usando cache quando possível"""
        cache_key = self._get_cache_key("access_token")
        token = cache.get(cache_key)
        
        if token:
            logger.debug(f"Token obtido do cache para tenant {self.tenant_id}")
            return token
        
        # Solicita novo token
        token_url = self.TOKEN_URL.format(tenant_id=self.tenant_id)
        
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default',
            'grant_type': 'client_credentials'
        }
        
        try:
            response = requests.post(token_url, data=data, timeout=30)
            response.raise_for_status()
            
            token_data = response.json()
            access_token = token_data['access_token']
            expires_in = token_data.get('expires_in', 3600)
            
            # Cache o token por 90% do tempo de expiração
            cache_timeout = int(expires_in * 0.9)
            cache.set(cache_key, access_token, cache_timeout)
            
            logger.info(f"Novo token obtido para tenant {self.tenant_id}")
            return access_token
            
        except requests.RequestException as e:
            logger.error(f"Erro ao obter token para tenant {self.tenant_id}: {e}")
            raise GraphAPIError(f"Falha na autenticação: {str(e)}")
        except KeyError as e:
            logger.error(f"Resposta de token inválida para tenant {self.tenant_id}: {e}")
            raise GraphAPIError("Resposta de autenticação inválida")
    
    def _make_request(self, method: str, endpoint: str, data: Dict = None, params: Dict = None) -> Dict:
        """Faz requisição para a Graph API"""
        token = self._get_access_token()
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        url = f"{self.BASE_URL}{endpoint}"
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=data,
                params=params,
                timeout=30
            )
            
            # Log da requisição
            logger.debug(f"{method} {endpoint} - Status: {response.status_code}")
            
            if response.status_code == 204:  # No Content
                return {}
            
            response_data = response.json()
            
            if not response.ok:
                error_info = response_data.get('error', {})
                error_code = error_info.get('code', 'Unknown')
                error_message = error_info.get('message', 'Erro desconhecido')
                
                logger.error(f"Erro Graph API: {error_code} - {error_message}")
                raise GraphAPIError(
                    message=error_message,
                    status_code=response.status_code,
                    error_code=error_code
                )
            
            return response_data
            
        except requests.RequestException as e:
            logger.error(f"Erro de rede na requisição {method} {endpoint}: {e}")
            raise GraphAPIError(f"Erro de rede: {str(e)}")
        except ValueError as e:
            logger.error(f"Erro ao decodificar JSON da resposta: {e}")
            raise GraphAPIError("Resposta inválida da API")
    
    def test_connection(self) -> Dict[str, Any]:
        """Testa a conexão com a Graph API"""
        try:
            # Tenta obter informações da organização
            response = self._make_request('GET', '/organization')
            
            org_info = response.get('value', [{}])[0]
            
            return {
                'success': True,
                'organization_name': org_info.get('displayName', 'N/A'),
                'tenant_id': org_info.get('id', self.tenant_id),
                'verified_domains': len(org_info.get('verifiedDomains', [])),
                'message': 'Conexão estabelecida com sucesso'
            }
            
        except GraphAPIError as e:
            logger.error(f"Falha no teste de conexão: {e.message}")
            return {
                'success': False,
                'error_code': e.error_code,
                'message': e.message
            }
    
    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Cria um novo usuário no Microsoft 365"""
        required_fields = ['displayName', 'userPrincipalName', 'mailNickname']
        
        for field in required_fields:
            if field not in user_data:
                raise ValueError(f"Campo obrigatório ausente: {field}")
        
        # Configurações padrão
        payload = {
            'accountEnabled': user_data.get('accountEnabled', True),
            'displayName': user_data['displayName'],
            'userPrincipalName': user_data['userPrincipalName'],
            'mailNickname': user_data['mailNickname'],
            'usageLocation': user_data.get('usageLocation', self.config.default_usage_location or 'BR'),
        }
        
        # Adiciona senha se fornecida
        if 'password' in user_data:
            payload['passwordProfile'] = {
                'password': user_data['password'],
                'forceChangePasswordNextSignIn': user_data.get('forceChangePasswordNextSignIn', True)
            }
        elif self.config.default_password_profile:
            payload['passwordProfile'] = self.config.default_password_profile
        
        # Adiciona campos opcionais
        optional_fields = ['givenName', 'surname', 'jobTitle', 'department', 'officeLocation']
        for field in optional_fields:
            if field in user_data:
                payload[field] = user_data[field]
        
        try:
            response = self._make_request('POST', '/users', data=payload)
            
            logger.info(f"Usuário criado: {response.get('userPrincipalName')}")
            
            return {
                'success': True,
                'user_id': response.get('id'),
                'user_principal_name': response.get('userPrincipalName'),
                'display_name': response.get('displayName'),
                'message': 'Usuário criado com sucesso'
            }
            
        except GraphAPIError as e:
            logger.error(f"Erro ao criar usuário: {e.message}")
            return {
                'success': False,
                'error_code': e.error_code,
                'message': e.message
            }
    
    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Atualiza um usuário existente"""
        # Campos permitidos para atualização
        allowed_fields = [
            'displayName', 'givenName', 'surname', 'jobTitle', 'department',
            'officeLocation', 'accountEnabled', 'usageLocation'
        ]
        
        payload = {k: v for k, v in user_data.items() if k in allowed_fields}
        
        if not payload:
            raise ValueError("Nenhum campo válido fornecido para atualização")
        
        try:
            self._make_request('PATCH', f'/users/{user_id}', data=payload)
            
            logger.info(f"Usuário atualizado: {user_id}")
            
            return {
                'success': True,
                'user_id': user_id,
                'message': 'Usuário atualizado com sucesso'
            }
            
        except GraphAPIError as e:
            logger.error(f"Erro ao atualizar usuário {user_id}: {e.message}")
            return {
                'success': False,
                'error_code': e.error_code,
                'message': e.message
            }
    
    def disable_user(self, user_id: str) -> Dict[str, Any]:
        """Desabilita um usuário"""
        return self.update_user(user_id, {'accountEnabled': False})
    
    def enable_user(self, user_id: str) -> Dict[str, Any]:
        """Habilita um usuário"""
        return self.update_user(user_id, {'accountEnabled': True})
    
    def get_user(self, user_id: str) -> Dict[str, Any]:
        """Obtém informações de um usuário"""
        try:
            response = self._make_request('GET', f'/users/{user_id}')
            
            return {
                'success': True,
                'user': response
            }
            
        except GraphAPIError as e:
            logger.error(f"Erro ao obter usuário {user_id}: {e.message}")
            return {
                'success': False,
                'error_code': e.error_code,
                'message': e.message
            }
    
    def list_users(self, filter_query: str = None, select_fields: List[str] = None) -> Dict[str, Any]:
        """Lista usuários com filtros opcionais"""
        params = {}
        
        if filter_query:
            params['$filter'] = filter_query
        
        if select_fields:
            params['$select'] = ','.join(select_fields)
        
        try:
            response = self._make_request('GET', '/users', params=params)
            
            return {
                'success': True,
                'users': response.get('value', []),
                'count': len(response.get('value', []))
            }
            
        except GraphAPIError as e:
            logger.error(f"Erro ao listar usuários: {e.message}")
            return {
                'success': False,
                'error_code': e.error_code,
                'message': e.message
            }
    
    def create_group(self, group_data: Dict[str, Any]) -> Dict[str, Any]:
        """Cria um novo grupo"""
        required_fields = ['displayName', 'mailNickname']
        
        for field in required_fields:
            if field not in group_data:
                raise ValueError(f"Campo obrigatório ausente: {field}")
        
        payload = {
            'displayName': group_data['displayName'],
            'mailNickname': group_data['mailNickname'],
            'groupTypes': group_data.get('groupTypes', []),
            'securityEnabled': group_data.get('securityEnabled', True),
            'mailEnabled': group_data.get('mailEnabled', False)
        }
        
        if 'description' in group_data:
            payload['description'] = group_data['description']
        
        try:
            response = self._make_request('POST', '/groups', data=payload)
            
            logger.info(f"Grupo criado: {response.get('displayName')}")
            
            return {
                'success': True,
                'group_id': response.get('id'),
                'display_name': response.get('displayName'),
                'mail_nickname': response.get('mailNickname'),
                'message': 'Grupo criado com sucesso'
            }
            
        except GraphAPIError as e:
            logger.error(f"Erro ao criar grupo: {e.message}")
            return {
                'success': False,
                'error_code': e.error_code,
                'message': e.message
            }
    
    def list_groups(self, filter_query: str = None) -> Dict[str, Any]:
        """Lista grupos com filtros opcionais"""
        params = {}
        
        if filter_query:
            params['$filter'] = filter_query
        
        try:
            response = self._make_request('GET', '/groups', params=params)
            
            return {
                'success': True,
                'groups': response.get('value', []),
                'count': len(response.get('value', []))
            }
            
        except GraphAPIError as e:
            logger.error(f"Erro ao listar grupos: {e.message}")
            return {
                'success': False,
                'error_code': e.error_code,
                'message': e.message
            }
    
    def add_group_member(self, group_id: str, user_id: str) -> Dict[str, Any]:
        """Adiciona um usuário a um grupo"""
        payload = {
            '@odata.id': f"{self.BASE_URL}/users/{user_id}"
        }
        
        try:
            self._make_request('POST', f'/groups/{group_id}/members/$ref', data=payload)
            
            logger.info(f"Usuário {user_id} adicionado ao grupo {group_id}")
            
            return {
                'success': True,
                'message': 'Usuário adicionado ao grupo com sucesso'
            }
            
        except GraphAPIError as e:
            logger.error(f"Erro ao adicionar usuário ao grupo: {e.message}")
            return {
                'success': False,
                'error_code': e.error_code,
                'message': e.message
            }
    
    def remove_group_member(self, group_id: str, user_id: str) -> Dict[str, Any]:
        """Remove um usuário de um grupo"""
        try:
            self._make_request('DELETE', f'/groups/{group_id}/members/{user_id}/$ref')
            
            logger.info(f"Usuário {user_id} removido do grupo {group_id}")
            
            return {
                'success': True,
                'message': 'Usuário removido do grupo com sucesso'
            }
            
        except GraphAPIError as e:
            logger.error(f"Erro ao remover usuário do grupo: {e.message}")
            return {
                'success': False,
                'error_code': e.error_code,
                'message': e.message
            }
    
    def get_group_members(self, group_id: str) -> Dict[str, Any]:
        """Obtém membros de um grupo"""
        try:
            response = self._make_request('GET', f'/groups/{group_id}/members')
            
            return {
                'success': True,
                'members': response.get('value', []),
                'count': len(response.get('value', []))
            }
            
        except GraphAPIError as e:
            logger.error(f"Erro ao obter membros do grupo {group_id}: {e.message}")
            return {
                'success': False,
                'error_code': e.error_code,
                'message': e.message
            }