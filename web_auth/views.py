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
from core.models import AuditLog
from tenants.models import TenantUser
from .serializers import (
    LoginSerializer, RegisterSerializer, UserProfileSerializer,
    ChangePasswordSerializer, PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer, RefreshTokenSerializer
)

logger = logging.getLogger('web_auth')


class LoginView(APIView):
    """
    View para login de usuários.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
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
                        action='user_login',
                        resource_type='user',
                        resource_id=str(user.id),
                        success=True,
                        details={
                            'login_method': 'web_panel',
                            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                            'tenants_count': len(tenants)
                        },
                        ip_address=self.get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')
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
        
        # Log de tentativa de login falhada
        email = request.data.get('email', 'unknown')
        logger.warning(f"Tentativa de login falhada: {email}")
        
        return Response(
            serializer.errors,
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
    View para registro de novos usuários.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
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
                action='user_register',
                resource_type='user',
                resource_id=str(user.id),
                success=True,
                details={
                    'registration_method': 'web_panel',
                    'tenant_created': tenant_user.tenant.name,
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')
                },
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            logger.info(f"Usuário registrado com sucesso: {user.email}")
            
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
    View para alteração de senha.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={'request': request}
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
                    action='user_password_change',
                    resource_type='user',
                    resource_id=str(request.user.id),
                    success=True,
                    details={
                        'change_method': 'web_panel',
                        'user_agent': request.META.get('HTTP_USER_AGENT', '')
                    },
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
            
            logger.info(f"Senha alterada: {request.user.email}")
            
            return Response({
                'message': 'Senha alterada com sucesso'
            })
        
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
            
            # Envia email (simulado)
            try:
                # Aqui você implementaria o envio real do email
                # send_mail(
                #     'Reset de Senha',
                #     f'Clique no link para resetar sua senha: {reset_url}',
                #     settings.DEFAULT_FROM_EMAIL,
                #     [email],
                #     fail_silently=False,
                # )
                
                logger.info(f"Email de reset enviado para: {email}")
                logger.info(f"URL de reset (desenvolvimento): {reset_url}")
                
                return Response({
                    'message': 'Email de reset enviado com sucesso',
                    'reset_url': reset_url  # Apenas para desenvolvimento
                })
                
            except Exception as e:
                logger.error(f"Erro ao enviar email de reset: {e}")
                return Response(
                    {'error': 'Erro ao enviar email'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


class PasswordResetConfirmView(APIView):
    """
    View para confirmação de reset de senha.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, uidb64, token):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                # Decodifica UID
                uid = force_str(urlsafe_base64_decode(uidb64))
                user = User.objects.get(pk=uid)
                
                # Verifica token
                if default_token_generator.check_token(user, token):
                    # Altera senha
                    user.set_password(serializer.validated_data['new_password'])
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
                            action='user_password_reset',
                            resource_type='user',
                            resource_id=str(user.id),
                            success=True,
                            details={
                                'reset_method': 'email_token',
                                'user_agent': request.META.get('HTTP_USER_AGENT', '')
                            },
                            ip_address=self.get_client_ip(request),
                            user_agent=request.META.get('HTTP_USER_AGENT', '')
                        )
                    
                    logger.info(f"Senha resetada: {user.email}")
                    
                    return Response({
                        'message': 'Senha alterada com sucesso'
                    })
                else:
                    return Response(
                        {'error': 'Token inválido ou expirado'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                    
            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                return Response(
                    {'error': 'Token inválido'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
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