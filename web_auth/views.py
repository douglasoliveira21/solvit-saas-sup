import logging
from datetime import datetime, timedelta
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.conf import settings
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.urls import reverse
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from tenants.models import TenantUser, AuditLog
from core.tasks import send_password_reset_email, send_welcome_email
from core.security import AccountLockoutManager, SecurityAuditLogger, get_client_ip
from core.models import LoginAttempt, PasswordHistory
from .serializers import (
    LoginSerializer, RegisterSerializer, UserProfileSerializer,
    ChangePasswordSerializer, PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer, RefreshTokenSerializer
)

logger = logging.getLogger('web_auth')


class LoginView(APIView):
    """
    View para login de usuários com controle de segurança.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        email = request.data.get('email', '')
        password = request.data.get('password', '')
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Verifica se a conta está bloqueada
        lockout_manager = AccountLockoutManager()
        if lockout_manager.is_locked(email):
            # Registra tentativa em conta bloqueada
            LoginAttempt.objects.create(
                username=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                failure_reason='Account locked'
            )
            
            SecurityAuditLogger.log_security_event(
                'LOGIN_BLOCKED_ACCOUNT_LOCKED',
                user=None,
                ip_address=ip_address,
                details={
                    'email': email,
                    'user_agent': user_agent,
                    'message': f'Tentativa de login em conta bloqueada: {email}'
                }
            )
            
            return Response(
                {'error': 'Conta temporariamente bloqueada devido a múltiplas tentativas de login falhadas'},
                status=status.HTTP_423_LOCKED
            )
        
        serializer = LoginSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Registra tentativa de login bem-sucedida
            LoginAttempt.objects.create(
                username=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True
            )
            
            # Limpa tentativas falhadas para este usuário
            lockout_manager.clear_attempts(email)
            
            # Gera tokens JWT
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            
            # Atualiza último login
            user.last_login = datetime.now()
            user.save(update_fields=['last_login'])
            
            # Obtém informações dos tenants do usuário
            tenant_users = TenantUser.objects.filter(
                user=user, 
                is_active=True
            ).select_related('tenant')
            
            tenants = [{
                'id': tu.tenant.id,
                'name': tu.tenant.name,
                'slug': tu.tenant.slug,
                'role': tu.role,
                'is_active': tu.tenant.is_active
            } for tu in tenant_users]
            
            # Cria log de auditoria
            if tenants:
                # Se o usuário tem tenants, cria log no primeiro tenant ativo
                active_tenant = next(
                    (t for t in tenants if t['is_active']), 
                    tenants[0] if tenants else None
                )
                
                if active_tenant:
                    AuditLog.objects.create(
                        tenant_id=active_tenant['id'],
                        user=user,
                        action='LOGIN',
                        resource_type='USER',
                        resource_name=user.username,
                        description=f'Login realizado via web panel para usuário {user.username}',
                        success=True,
                        metadata={
                            'login_method': 'web_panel',
                            'user_agent': user_agent,
                            'tenants_count': len(tenants)
                        },
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
            
            SecurityAuditLogger.log_security_event(
                'LOGIN_SUCCESS',
                user=user,
                ip_address=ip_address,
                details={
                    'tenants_count': len(tenants),
                    'user_agent': user_agent,
                    'message': f'Login bem-sucedido para usuário: {user.email}'
                }
            )
            
            logger.info(f"Login realizado com sucesso: {user.email}")
            
            return Response({
                'access': str(access_token),
                'refresh': str(refresh),
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'tenants': tenants
                },
                'message': 'Login realizado com sucesso'
            })
        
        # Registra tentativa de login falhada
        LoginAttempt.objects.create(
            username=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            failure_reason='Invalid credentials'
        )
        
        # Incrementa contador de tentativas falhadas
        lockout_manager.record_failed_attempt(email)
        
        SecurityAuditLogger.log_security_event(
            'LOGIN_FAILED',
            user=None,
            ip_address=ip_address,
            details={
                'email': email,
                'errors': serializer.errors,
                'user_agent': user_agent,
                'message': f'Tentativa de login falhada para: {email}'
            }
        )
        
        logger.warning(f"Tentativa de login falhada: {email}")
        
        return Response(
            {'error': 'Credenciais inválidas'},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    def get_client_ip(self, request):
        """Obtém IP do cliente."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class RegisterView(APIView):
    """
    View para registro de novos usuários com validação de políticas de senha.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        from core.security import PasswordValidator
        
        # Valida política de senha antes de criar o usuário
        password = request.data.get('password', '')
        email = request.data.get('email', '')
        
        # Cria um usuário temporário para validação
        temp_user = User(
            email=email,
            username=email,
            first_name=request.data.get('first_name', ''),
            last_name=request.data.get('last_name', '')
        )
        
        password_validator = PasswordValidator()
        is_valid, errors = password_validator.validate_new_password(temp_user, password)
        
        if not is_valid:
            return Response(
                {'error': 'Senha não atende aos critérios de segurança', 'details': errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = RegisterSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            
            # Gera tokens JWT
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            
            # Obtém tenant criado
            tenant_user = TenantUser.objects.get(user=user)
            
            # Cria log de auditoria
            AuditLog.objects.create(
                tenant=tenant_user.tenant,
                user=user,
                action='CREATE',
                resource_type='USER',
                resource_id=str(user.id),
                resource_name=user.username,
                description=f'Usuário {user.username} registrado com sucesso',
                success=True,
                metadata={
                    'registration_method': 'web_panel',
                    'tenant_created': tenant_user.tenant.name,
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')
                },
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            logger.info(f"Usuário registrado com sucesso: {user.email}")
            
            # Envia email de boas-vindas de forma assíncrona
            try:
                login_url = f"{settings.FRONTEND_URL}/login"
                send_welcome_email.delay(
                    user_email=user.email,
                    user_name=user.get_full_name() or user.username,
                    tenant_name=tenant_user.tenant.name,
                    login_url=login_url
                )
                logger.info(f"Task de email de boas-vindas enviada para: {user.email}")
            except Exception as e:
                logger.error(f"Erro ao enviar task de email de boas-vindas: {e}")
                # Não falha o registro se o email não puder ser enviado
            
            return Response({
                'access': str(access_token),
                'refresh': str(refresh),
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'tenants': [{
                        'id': tenant_user.tenant.id,
                        'name': tenant_user.tenant.name,
                        'slug': tenant_user.tenant.slug,
                        'role': tenant_user.role,
                        'is_active': tenant_user.tenant.is_active
                    }]
                },
                'message': 'Usuário registrado com sucesso'
            }, status=status.HTTP_201_CREATED)
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )
    
    def get_client_ip(self, request):
        """Obtém IP do cliente."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class LogoutView(APIView):
    """
    View para logout de usuários.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            # Cria log de auditoria
            tenant_user = TenantUser.objects.filter(
                user=request.user, 
                is_active=True
            ).first()
            
            if tenant_user:
                AuditLog.objects.create(
                    tenant=tenant_user.tenant,
                    user=request.user,
                    action='user_logout',
                    resource_type='user',
                    resource_id=str(request.user.id),
                    success=True,
                    details={
                        'logout_method': 'web_panel',
                        'user_agent': request.META.get('HTTP_USER_AGENT', '')
                    },
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
            
            logger.info(f"Logout realizado: {request.user.email}")
            
            return Response({
                'message': 'Logout realizado com sucesso'
            })
            
        except Exception as e:
            logger.error(f"Erro no logout: {e}")
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


class UserProfileView(APIView):
    """
    View para perfil do usuário.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Obtém perfil do usuário."""
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)
    
    def put(self, request):
        """Atualiza perfil do usuário."""
        serializer = UserProfileSerializer(
            request.user, 
            data=request.data, 
            partial=True
        )
        
        if serializer.is_valid():
            serializer.save()
            
            # Cria log de auditoria
            tenant_user = TenantUser.objects.filter(
                user=request.user, 
                is_active=True
            ).first()
            
            if tenant_user:
                AuditLog.objects.create(
                    tenant=tenant_user.tenant,
                    user=request.user,
                    action='user_profile_update',
                    resource_type='user',
                    resource_id=str(request.user.id),
                    success=True,
                    details={
                        'updated_fields': list(request.data.keys()),
                        'user_agent': request.META.get('HTTP_USER_AGENT', '')
                    },
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
            
            return Response(serializer.data)
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )
    
    def get_client_ip(self, request):
        """Obtém IP do cliente."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class ChangePasswordView(APIView):
    """
    View para alteração de senha com validação de políticas.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        from core.security import PasswordValidator
        
        current_password = request.data.get('current_password', '')
        new_password = request.data.get('new_password', '')
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Verifica senha atual
        if not request.user.check_password(current_password):
            SecurityAuditLogger.log_security_event(
                'PASSWORD_CHANGE_FAILED',
                user=request.user,
                ip_address=ip_address,
                details={
                    'user_agent': user_agent,
                    'message': f'Tentativa de alteração de senha com senha atual incorreta: {request.user.email}'
                }
            )
            
            return Response(
                {'error': 'Senha atual incorreta'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Valida nova senha
        password_validator = PasswordValidator()
        is_valid, errors = password_validator.validate_new_password(request.user, new_password)
        
        if not is_valid:
            SecurityAuditLogger.log_security_event(
                'PASSWORD_CHANGE_FAILED',
                user=request.user,
                ip_address=ip_address,
                details={
                    'validation_errors': errors,
                    'user_agent': user_agent,
                    'message': f'Tentativa de alteração de senha com política inválida: {request.user.email}'
                }
            )
            
            return Response(
                {'error': 'Nova senha não atende aos critérios de segurança', 'details': errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verifica reutilização de senha
        if PasswordHistory.check_password_reuse(request.user, new_password):
            SecurityAuditLogger.log_security_event(
                'PASSWORD_CHANGE_FAILED',
                user=request.user,
                ip_address=ip_address,
                details={
                    'user_agent': user_agent,
                    'message': f'Tentativa de reutilização de senha: {request.user.email}'
                }
            )
            
            return Response(
                {'error': 'Não é possível reutilizar uma das últimas 5 senhas'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Adiciona senha atual ao histórico antes de alterar
        PasswordHistory.add_password(request.user, current_password)
        
        # Altera a senha
        request.user.set_password(new_password)
        request.user.save()
        
        # Cria log de auditoria
        tenant_user = TenantUser.objects.filter(
            user=request.user, 
            is_active=True
        ).first()
        
        if tenant_user:
            AuditLog.objects.create(
                tenant=tenant_user.tenant,
                user=request.user,
                action='UPDATE',
                resource_type='USER',
                resource_id=str(request.user.id),
                resource_name=request.user.username,
                description=f'Senha alterada para usuário {request.user.username}',
                success=True,
                metadata={
                    'change_method': 'web_panel',
                    'user_agent': user_agent
                },
                ip_address=ip_address,
                user_agent=user_agent
            )
        
        SecurityAuditLogger.log_security_event(
            'PASSWORD_CHANGED',
            user=request.user,
            ip_address=ip_address,
            details={
                'user_agent': user_agent,
                'message': f'Senha alterada com sucesso: {request.user.email}'
            }
        )
        
        logger.info(f"Senha alterada: {request.user.email}")
        
        return Response({
            'message': 'Senha alterada com sucesso'
        })
    
    def get_client_ip(self, request):
        """Obtém IP do cliente."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class PasswordResetRequestView(APIView):
    """
    View para solicitação de reset de senha.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            
            # Gera token de reset
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            # Cria URL de reset
            reset_url = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"
            
            # Envia email usando Celery task
            try:
                # Envia email de reset de senha de forma assíncrona
                send_password_reset_email.delay(
                    user_email=email,
                    user_name=user.get_full_name() or user.username,
                    reset_url=reset_url
                )
                
                logger.info(f"Task de email de reset enviada para: {email}")
                
                response_data = {
                    'message': 'Email de reset enviado com sucesso'
                }
                
                # Inclui URL apenas em desenvolvimento
                if settings.DEBUG:
                    response_data['reset_url'] = reset_url
                    logger.info(f"URL de reset (desenvolvimento): {reset_url}")
                
                return Response(response_data)
                
            except Exception as e:
                logger.error(f"Erro ao enviar task de email de reset: {e}")
                return Response(
                    {'error': 'Erro ao processar solicitação de reset'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


class PasswordResetConfirmView(APIView):
    """
    View para confirmação de reset de senha com validação de políticas.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, uidb64, token):
        from core.security import PasswordValidator
        
        new_password = request.data.get('new_password', '')
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        try:
            # Decodifica UID
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            
            # Verifica token
            if not default_token_generator.check_token(user, token):
                SecurityAuditLogger.log_security_event(
                    'PASSWORD_RESET_FAILED',
                    user=user,
                    ip_address=ip_address,
                    details={
                        'user_agent': user_agent,
                        'message': f'Tentativa de reset com token inválido: {user.email}'
                    }
                )
                
                return Response(
                    {'error': 'Token inválido ou expirado'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Valida nova senha
            password_validator = PasswordValidator()
            is_valid, errors = password_validator.validate_new_password(user, new_password)
            
            if not is_valid:
                SecurityAuditLogger.log_security_event(
                    'PASSWORD_RESET_FAILED',
                    user=user,
                    ip_address=ip_address,
                    details={
                        'validation_errors': errors,
                        'user_agent': user_agent,
                        'message': f'Tentativa de reset com política de senha inválida: {user.email}'
                    }
                )
                
                return Response(
                    {'error': 'Nova senha não atende aos critérios de segurança', 'details': errors},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Verifica reutilização de senha
            if PasswordHistory.check_password_reuse(user, new_password):
                SecurityAuditLogger.log_security_event(
                    'PASSWORD_RESET_FAILED',
                    user=user,
                    ip_address=ip_address,
                    details={
                        'user_agent': user_agent,
                        'message': f'Tentativa de reutilização de senha no reset: {user.email}'
                    }
                )
                
                return Response(
                    {'error': 'Não é possível reutilizar uma das últimas 5 senhas'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Adiciona senha atual ao histórico antes de alterar
            if user.password:  # Se o usuário já tem uma senha
                PasswordHistory.add_password(user, user.password)
            
            # Altera senha
            user.set_password(new_password)
            user.save()
            
            # Cria log de auditoria
            tenant_user = TenantUser.objects.filter(
                user=user, 
                is_active=True
            ).first()
            
            if tenant_user:
                AuditLog.objects.create(
                    tenant=tenant_user.tenant,
                    user=user,
                    action='UPDATE',
                    resource_type='USER',
                    resource_id=str(user.id),
                    resource_name=user.username,
                    description=f'Senha resetada para usuário {user.username}',
                    success=True,
                    metadata={
                        'reset_method': 'email_token',
                        'user_agent': user_agent
                    },
                    ip_address=ip_address,
                    user_agent=user_agent
                )
            
            SecurityAuditLogger.log_security_event(
                'PASSWORD_RESET_SUCCESS',
                user=user,
                ip_address=ip_address,
                details={
                    'user_agent': user_agent,
                    'message': f'Senha resetada com sucesso: {user.email}'
                }
            )
            
            logger.info(f"Senha resetada: {user.email}")
            
            return Response({
                'message': 'Senha alterada com sucesso'
            })
                
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            SecurityAuditLogger.log_security_event(
                'PASSWORD_RESET_FAILED',
                user=None,
                ip_address=ip_address,
                details={
                    'uidb64': uidb64,
                    'user_agent': user_agent,
                    'message': f'Tentativa de reset com UID inválido'
                }
            )
            
            return Response(
                {'error': 'Token inválido'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def get_client_ip(self, request):
        """Obtém IP do cliente."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class CustomTokenRefreshView(TokenRefreshView):
    """
    View customizada para refresh de token JWT.
    """
    
    def post(self, request, *args, **kwargs):
        serializer = RefreshTokenSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                refresh = RefreshToken(serializer.validated_data['refresh'])
                access_token = refresh.access_token
                
                return Response({
                    'access': str(access_token),
                    'refresh': str(refresh)
                })
                
            except TokenError as e:
                return Response(
                    {'error': 'Token inválido'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def verify_token(request):
    """
    Endpoint para verificar se o token JWT é válido.
    """
    return Response({
        'valid': True,
        'user': {
            'id': request.user.id,
            'username': request.user.username,
            'email': request.user.email
        }
    })