from django.contrib.auth.models import User
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import re
import logging

logger = logging.getLogger(__name__)

# Configurações de segurança
SECURITY_SETTINGS = getattr(settings, 'SECURITY_SETTINGS', {})
ACCOUNT_LOCKOUT_SETTINGS = SECURITY_SETTINGS.get('ACCOUNT_LOCKOUT', {})
PASSWORD_POLICY_SETTINGS = SECURITY_SETTINGS.get('PASSWORD_POLICY', {})

MAX_LOGIN_ATTEMPTS = ACCOUNT_LOCKOUT_SETTINGS.get('MAX_FAILED_ATTEMPTS', 5)
LOCKOUT_DURATION = ACCOUNT_LOCKOUT_SETTINGS.get('LOCKOUT_DURATION_MINUTES', 30)
PASSWORD_MIN_LENGTH = PASSWORD_POLICY_SETTINGS.get('MIN_LENGTH', 8)
PASSWORD_MAX_LENGTH = PASSWORD_POLICY_SETTINGS.get('MAX_LENGTH', 128)
PASSWORD_REQUIRE_UPPERCASE = PASSWORD_POLICY_SETTINGS.get('REQUIRE_UPPERCASE', True)
PASSWORD_REQUIRE_LOWERCASE = PASSWORD_POLICY_SETTINGS.get('REQUIRE_LOWERCASE', True)
PASSWORD_REQUIRE_NUMBERS = PASSWORD_POLICY_SETTINGS.get('REQUIRE_DIGITS', True)
PASSWORD_REQUIRE_SPECIAL = PASSWORD_POLICY_SETTINGS.get('REQUIRE_SPECIAL_CHARS', True)
SPECIAL_CHARS = PASSWORD_POLICY_SETTINGS.get('SPECIAL_CHARS', '!@#$%^&*()_+-=[]{}|;:,.<>?')
PASSWORD_HISTORY_COUNT = PASSWORD_POLICY_SETTINGS.get('PASSWORD_HISTORY_COUNT', 5)

class AccountLockoutManager:
    """Gerenciador de bloqueio de contas por tentativas de login falhadas"""
    
    @staticmethod
    def get_cache_key(identifier):
        """Gera chave do cache para o identificador (email ou username)"""
        return f"login_attempts:{identifier}"
    
    @staticmethod
    def get_lockout_key(identifier):
        """Gera chave do cache para bloqueio"""
        return f"account_locked:{identifier}"
    
    @classmethod
    def record_failed_attempt(cls, identifier, ip_address=None):
        """Registra uma tentativa de login falhada"""
        cache_key = cls.get_cache_key(identifier)
        lockout_key = cls.get_lockout_key(identifier)
        
        # Incrementa contador de tentativas
        attempts = cache.get(cache_key, 0) + 1
        cache.set(cache_key, attempts, timeout=LOCKOUT_DURATION * 60)
        
        logger.warning(f"Tentativa de login falhada para {identifier} (tentativa {attempts}/{MAX_LOGIN_ATTEMPTS}) - IP: {ip_address}")
        
        # Bloqueia conta se exceder limite
        if attempts >= MAX_LOGIN_ATTEMPTS:
            cache.set(lockout_key, True, timeout=LOCKOUT_DURATION * 60)
            logger.error(f"Conta bloqueada para {identifier} por {LOCKOUT_DURATION} minutos - IP: {ip_address}")
            return True
        
        return False
    
    @classmethod
    def is_locked(cls, identifier):
        """Verifica se a conta está bloqueada"""
        lockout_key = cls.get_lockout_key(identifier)
        return cache.get(lockout_key, False)
    
    @classmethod
    def clear_attempts(cls, identifier):
        """Limpa tentativas de login após sucesso"""
        cache_key = cls.get_cache_key(identifier)
        lockout_key = cls.get_lockout_key(identifier)
        cache.delete(cache_key)
        cache.delete(lockout_key)
        logger.info(f"Tentativas de login limpas para {identifier}")
    
    @classmethod
    def get_remaining_attempts(cls, identifier):
        """Retorna número de tentativas restantes"""
        cache_key = cls.get_cache_key(identifier)
        attempts = cache.get(cache_key, 0)
        return max(0, MAX_LOGIN_ATTEMPTS - attempts)
    
    @classmethod
    def get_lockout_time_remaining(cls, identifier):
        """Retorna tempo restante de bloqueio em segundos"""
        lockout_key = cls.get_lockout_key(identifier)
        return cache.ttl(lockout_key)

class PasswordValidator:
    """Validador de políticas de senha"""
    
    @staticmethod
    def validate_password_strength(password):
        """Valida força da senha baseada nas políticas configuradas"""
        errors = []
        
        # Comprimento mínimo
        if len(password) < PASSWORD_MIN_LENGTH:
            errors.append(f"A senha deve ter pelo menos {PASSWORD_MIN_LENGTH} caracteres")
        
        # Letra maiúscula
        if PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("A senha deve conter pelo menos uma letra maiúscula")
        
        # Letra minúscula
        if PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("A senha deve conter pelo menos uma letra minúscula")
        
        # Números
        if PASSWORD_REQUIRE_NUMBERS and not re.search(r'\d', password):
            errors.append("A senha deve conter pelo menos um número")
        
        # Caracteres especiais
        if PASSWORD_REQUIRE_SPECIAL and not re.search(f'[{re.escape(SPECIAL_CHARS)}]', password):
            errors.append(f"A senha deve conter pelo menos um caractere especial ({SPECIAL_CHARS})")
        
        # Padrões comuns a evitar
        common_patterns = [
            r'(.)\1{2,}',  # 3+ caracteres repetidos
            r'123456',     # sequência numérica
            r'abcdef',     # sequência alfabética
            r'qwerty',     # padrão de teclado
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                errors.append("A senha não deve conter padrões comuns ou sequências")
                break
        
        return errors
    
    @staticmethod
    def check_password_history(user, new_password):
        """Verifica se a senha já foi usada recentemente"""
        from .models import PasswordHistory
        
        recent_passwords = PasswordHistory.objects.filter(
            user=user
        ).order_by('-created_at')[:PASSWORD_HISTORY_COUNT]
        
        for password_history in recent_passwords:
            if password_history.check_password(new_password):
                return False, f"Esta senha foi usada recentemente. Escolha uma senha diferente das últimas {PASSWORD_HISTORY_COUNT}."
        
        return True, None
    
    @classmethod
    def validate_new_password(cls, user, new_password):
        """Validação completa de nova senha"""
        # Validar força da senha
        strength_errors = cls.validate_password_strength(new_password)
        if strength_errors:
            return False, strength_errors
        
        # Verificar histórico de senhas
        if user and user.pk:
            history_valid, history_error = cls.check_password_history(user, new_password)
            if not history_valid:
                return False, [history_error]
        
        return True, []

class SecurityAuditLogger:
    """Logger para eventos de segurança"""
    
    @staticmethod
    def log_security_event(event_type, user=None, ip_address=None, details=None):
        """Registra evento de segurança"""
        from core.models import AuditLog
        
        try:
            AuditLog.objects.create(
                user=user,
                action=f'SECURITY_{event_type}',
                resource_type='Security',
                resource_name=event_type,
                description=f'Evento de segurança: {event_type}',
                ip_address=ip_address,
                metadata=details or {}
            )
        except Exception as e:
            logger.error(f"Erro ao registrar evento de segurança: {e}")
    
    @classmethod
    def log_failed_login(cls, identifier, ip_address, reason='invalid_credentials'):
        """Log de tentativa de login falhada"""
        cls.log_security_event(
            'FAILED_LOGIN',
            ip_address=ip_address,
            details={
                'identifier': identifier,
                'reason': reason,
                'timestamp': timezone.now().isoformat()
            }
        )
    
    @classmethod
    def log_account_lockout(cls, identifier, ip_address):
        """Log de bloqueio de conta"""
        cls.log_security_event(
            'ACCOUNT_LOCKOUT',
            ip_address=ip_address,
            details={
                'identifier': identifier,
                'lockout_duration': LOCKOUT_DURATION,
                'timestamp': timezone.now().isoformat()
            }
        )
    
    @classmethod
    def log_password_change(cls, user, ip_address, forced=False):
        """Log de mudança de senha"""
        cls.log_security_event(
            'PASSWORD_CHANGE',
            user=user,
            ip_address=ip_address,
            details={
                'forced': forced,
                'timestamp': timezone.now().isoformat()
            }
        )

def get_client_ip(request):
    """Extrai IP do cliente da requisição"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip