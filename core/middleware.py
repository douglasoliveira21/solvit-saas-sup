from django.utils.cache import patch_cache_control
from django.http import HttpResponse
from django.conf import settings
import time
import logging

logger = logging.getLogger(__name__)

class CacheControlMiddleware:
    """
    Middleware para adicionar headers de cache HTTP apropriados
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Aplica cache control apenas para APIs
        if request.path.startswith('/api/'):
            # Para endpoints de listagem e detalhes, aplica cache
            if request.method == 'GET':
                if 'stats' in request.path:
                    # Estatísticas podem ser cacheadas por 5 minutos
                    patch_cache_control(response, max_age=300, public=True)
                elif any(endpoint in request.path for endpoint in ['/tenants/', '/users/', '/groups/']):
                    # Dados de entidades podem ser cacheados por 2 minutos
                    patch_cache_control(response, max_age=120, public=True)
                else:
                    # Outros endpoints GET por 1 minuto
                    patch_cache_control(response, max_age=60, public=True)
            else:
                # Para métodos que modificam dados, não cacheia
                patch_cache_control(response, no_cache=True, no_store=True, must_revalidate=True)
        
        return response


class PerformanceMonitoringMiddleware:
    """
    Middleware para monitorar performance das requisições
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        start_time = time.time()
        
        response = self.get_response(request)
        
        # Calcula tempo de resposta
        response_time = time.time() - start_time
        
        # Adiciona header com tempo de resposta
        response['X-Response-Time'] = f"{response_time:.3f}s"
        
        # Log para requisições lentas (> 1 segundo)
        if response_time > 1.0:
            logger.warning(
                f"Requisição lenta detectada: {request.method} {request.path} "
                f"- {response_time:.3f}s - Status: {response.status_code}"
            )
        
        # Log para requisições muito lentas (> 3 segundos)
        if response_time > 3.0:
            logger.error(
                f"Requisição muito lenta: {request.method} {request.path} "
                f"- {response_time:.3f}s - Status: {response.status_code} "
                f"- User: {getattr(request, 'user', 'Anonymous')}"
            )
        
        return response


class CompressionMiddleware:
    """
    Middleware para adicionar headers de compressão
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Adiciona headers para habilitar compressão
        if isinstance(response, HttpResponse):
            # Para respostas JSON grandes, sugere compressão
            if (
                response.get('Content-Type', '').startswith('application/json') and
                len(response.content) > 1024  # > 1KB
            ):
                response['Vary'] = 'Accept-Encoding'
        
        return response


class SecurityHeadersMiddleware:
    """
    Middleware para adicionar headers de segurança
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Headers de segurança
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # CSP para APIs
        if request.path.startswith('/api/'):
            response['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none';"
        
        return response