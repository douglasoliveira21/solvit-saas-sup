from django.core.cache import cache
from django.conf import settings
from typing import Any, Optional, Dict, List
import json
import hashlib
from functools import wraps
import logging

logger = logging.getLogger(__name__)

class CacheService:
    """
    Serviço centralizado para gerenciamento de cache Redis
    """
    
    # Cache timeouts (em segundos)
    TIMEOUT_SHORT = 300      # 5 minutos
    TIMEOUT_MEDIUM = 1800    # 30 minutos
    TIMEOUT_LONG = 3600      # 1 hora
    TIMEOUT_VERY_LONG = 86400  # 24 horas
    
    @staticmethod
    def _generate_key(prefix: str, *args, **kwargs) -> str:
        """
        Gera uma chave única para o cache baseada nos argumentos
        """
        key_data = f"{prefix}:{args}:{sorted(kwargs.items())}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    @staticmethod
    def get(key: str, default: Any = None) -> Any:
        """
        Recupera um valor do cache
        """
        try:
            return cache.get(key, default)
        except Exception as e:
            logger.error(f"Erro ao recuperar cache {key}: {e}")
            return default
    
    @staticmethod
    def set(key: str, value: Any, timeout: int = TIMEOUT_MEDIUM) -> bool:
        """
        Define um valor no cache
        """
        try:
            cache.set(key, value, timeout)
            return True
        except Exception as e:
            logger.error(f"Erro ao definir cache {key}: {e}")
            return False
    
    @staticmethod
    def delete(key: str) -> bool:
        """
        Remove um valor do cache
        """
        try:
            cache.delete(key)
            return True
        except Exception as e:
            logger.error(f"Erro ao deletar cache {key}: {e}")
            return False
    
    @staticmethod
    def delete_pattern(pattern: str) -> bool:
        """
        Remove valores do cache que correspondem ao padrão
        """
        try:
            cache.delete_many(cache.keys(pattern))
            return True
        except Exception as e:
            logger.error(f"Erro ao deletar padrão de cache {pattern}: {e}")
            return False
    
    @staticmethod
    def clear_all() -> bool:
        """
        Limpa todo o cache
        """
        try:
            cache.clear()
            return True
        except Exception as e:
            logger.error(f"Erro ao limpar cache: {e}")
            return False
    
    # Métodos específicos para entidades do sistema
    
    @staticmethod
    def get_user_cache_key(user_id: int, suffix: str = "") -> str:
        """
        Gera chave de cache para usuário
        """
        return f"user:{user_id}:{suffix}" if suffix else f"user:{user_id}"
    
    @staticmethod
    def get_tenant_cache_key(tenant_id: int, suffix: str = "") -> str:
        """
        Gera chave de cache para tenant
        """
        return f"tenant:{tenant_id}:{suffix}" if suffix else f"tenant:{tenant_id}"
    
    @staticmethod
    def get_group_cache_key(group_id: int, suffix: str = "") -> str:
        """
        Gera chave de cache para grupo
        """
        return f"group:{group_id}:{suffix}" if suffix else f"group:{group_id}"
    
    @staticmethod
    def invalidate_user_cache(user_id: int):
        """
        Invalida todo o cache relacionado a um usuário
        """
        CacheService.delete_pattern(f"user:{user_id}:*")
        CacheService.delete(f"user:{user_id}")
    
    @staticmethod
    def invalidate_tenant_cache(tenant_id: int):
        """
        Invalida todo o cache relacionado a um tenant
        """
        CacheService.delete_pattern(f"tenant:{tenant_id}:*")
        CacheService.delete(f"tenant:{tenant_id}")
    
    @staticmethod
    def invalidate_group_cache(group_id: int):
        """
        Invalida todo o cache relacionado a um grupo
        """
        CacheService.delete_pattern(f"group:{group_id}:*")
        CacheService.delete(f"group:{group_id}")


def cache_result(timeout: int = CacheService.TIMEOUT_MEDIUM, key_prefix: str = ""):
    """
    Decorator para cachear resultados de funções
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Gera chave única para a função e argumentos
            func_name = f"{func.__module__}.{func.__name__}"
            cache_key = CacheService._generate_key(
                key_prefix or func_name, *args, **kwargs
            )
            
            # Tenta recuperar do cache
            result = CacheService.get(cache_key)
            if result is not None:
                logger.debug(f"Cache hit para {func_name}")
                return result
            
            # Executa função e cacheia resultado
            logger.debug(f"Cache miss para {func_name}")
            result = func(*args, **kwargs)
            CacheService.set(cache_key, result, timeout)
            
            return result
        return wrapper
    return decorator


def invalidate_cache_on_save(cache_keys: List[str]):
    """
    Decorator para invalidar cache quando um modelo é salvo
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            result = func(self, *args, **kwargs)
            
            # Invalida as chaves de cache especificadas
            for key_template in cache_keys:
                # Substitui placeholders na chave
                key = key_template.format(
                    id=getattr(self, 'id', None),
                    tenant_id=getattr(self, 'tenant_id', None),
                    user_id=getattr(self, 'user_id', None)
                )
                CacheService.delete(key)
            
            return result
        return wrapper
    return decorator