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
    """
    Cliente para interagir com a Microsoft Graph API
    """
    BASE_URL = "https://graph.microsoft.com/v1.0"
    TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    
    def __init__(self, config: M365Configuration):
        self.config = config
        self.client_id = config.client_id
        self.client_secret = config.client_secret
        self.tenant_id = config.azure_tenant_id
        self.redirect_uri = config.redirect_uri
        self._access_token = None
        self._token_expires_at = None
    
    def _get_access_token(self) -> str:
        """Obtém token de acesso usando Client Credentials Flow"""
        cache_key = f"msgraph_token_{self.tenant_id}"
        token = cache.get(cache_key)
        
        if token:
            return token
        
        token_url = self.TOKEN_URL.format(tenant_id=self.tenant_id)
        
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }
        
        try:
            response = requests.post(token_url, data=data)
            response.raise_for_status()
            
            token_data = response.json()
            access_token = token_data['access_token']
            expires_in = token_data.get('expires_in', 3600)
            
            # Cache token por 90% do tempo de expiração
            cache_timeout = int(expires_in * 0.9)
            cache.set(cache_key, access_token, cache_timeout)
            
            return access_token
            
        except requests.RequestException as e:
            logger.error(f"Erro ao obter token de acesso: {str(e)}")
            raise GraphAPIError(f"Falha na autenticação: {str(e)}")
    
    def _make_request(self, method: str, endpoint: str, params: Dict = None, data: Dict = None) -> Dict:
        """Faz requisição para a Graph API"""
        url = f"{self.BASE_URL}/{endpoint.lstrip('/')}"
        
        headers = {
            'Authorization': f'Bearer {self._get_access_token()}',
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=data
            )
            
            if response.status_code == 401:
                # Token expirado, limpa cache e tenta novamente
                cache_key = f"msgraph_token_{self.tenant_id}"
                cache.delete(cache_key)
                headers['Authorization'] = f'Bearer {self._get_access_token()}'
                
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=data
                )
            
            response.raise_for_status()
            return response.json() if response.content else {}
            
        except requests.RequestException as e:
            logger.error(f"Erro na requisição Graph API: {str(e)}")
            raise GraphAPIError(
                f"Erro na API: {str(e)}",
                status_code=getattr(e.response, 'status_code', None)
            )
    
    def get_organization_info(self) -> Dict[str, Any]:
        """Obtém informações da organização"""
        return self._make_request('GET', '/organization')
    
    def get_users(self, filter_query: str = None, select_fields: List[str] = None) -> List[Dict[str, Any]]:
        """Obtém lista de usuários"""
        params = {}
        
        if filter_query:
            params['$filter'] = filter_query
        
        if select_fields:
            params['$select'] = ','.join(select_fields)
        
        # Paginação automática
        users = []
        url = '/users'
        
        while url:
            if url.startswith('http'):
                # URL completa da próxima página
                response = requests.get(
                    url,
                    headers={'Authorization': f'Bearer {self._get_access_token()}'}
                )
                response.raise_for_status()
                data = response.json()
            else:
                # Primeira requisição
                data = self._make_request('GET', url, params=params)
                params = {}  # Limpa params para próximas páginas
            
            users.extend(data.get('value', []))
            url = data.get('@odata.nextLink')
        
        return users
    
    def get_groups(self, filter_query: str = None, select_fields: List[str] = None) -> List[Dict[str, Any]]:
        """Obtém lista de grupos"""
        params = {}
        
        if filter_query:
            params['$filter'] = filter_query
        
        if select_fields:
            params['$select'] = ','.join(select_fields)
        
        # Paginação automática
        groups = []
        url = '/groups'
        
        while url:
            if url.startswith('http'):
                response = requests.get(
                    url,
                    headers={'Authorization': f'Bearer {self._get_access_token()}'}
                )
                response.raise_for_status()
                data = response.json()
            else:
                data = self._make_request('GET', url, params=params)
                params = {}
            
            groups.extend(data.get('value', []))
            url = data.get('@odata.nextLink')
        
        return groups
    
    def get_group_members(self, group_id: str) -> List[Dict[str, Any]]:
        """Obtém membros de um grupo"""
        members = []
        url = f'/groups/{group_id}/members'
        
        while url:
            if url.startswith('http'):
                response = requests.get(
                    url,
                    headers={'Authorization': f'Bearer {self._get_access_token()}'}
                )
                response.raise_for_status()
                data = response.json()
            else:
                data = self._make_request('GET', url)
            
            members.extend(data.get('value', []))
            url = data.get('@odata.nextLink')
        
        return members
    
    def test_connection(self) -> Dict[str, Any]:
        """Testa a conexão com Microsoft Graph"""
        try:
            org_info = self.get_organization_info()
            return {
                'success': True,
                'message': 'Conexão estabelecida com sucesso',
                'organization': org_info.get('value', [{}])[0].get('displayName', 'N/A') if org_info.get('value') else 'N/A'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }