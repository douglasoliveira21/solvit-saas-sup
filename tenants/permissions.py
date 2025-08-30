from rest_framework.permissions import BasePermission
from .models import TenantUser


class IsTenantMember(BasePermission):
    """
    Permissão que verifica se o usuário é membro de um tenant.
    """
    
    def has_permission(self, request, view):
        """
        Verifica se o usuário autenticado é membro de pelo menos um tenant.
        """
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Verifica se o usuário é membro de algum tenant ativo
        return TenantUser.objects.filter(
            user=request.user,
            is_active=True
        ).exists()
    
    def has_object_permission(self, request, view, obj):
        """
        Verifica se o usuário tem acesso ao objeto específico baseado no tenant.
        """
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Se o objeto tem um campo tenant, verifica se o usuário é membro
        if hasattr(obj, 'tenant'):
            return TenantUser.objects.filter(
                user=request.user,
                tenant=obj.tenant,
                is_active=True
            ).exists()
        
        # Se não tem campo tenant, permite acesso
        return True


class IsTenantAdmin(BasePermission):
    """
    Permissão que verifica se o usuário é administrador de um tenant.
    """
    
    def has_permission(self, request, view):
        """
        Verifica se o usuário é administrador de pelo menos um tenant.
        """
        if not request.user or not request.user.is_authenticated:
            return False
        
        return TenantUser.objects.filter(
            user=request.user,
            role='ADMIN',
            is_active=True
        ).exists()
    
    def has_object_permission(self, request, view, obj):
        """
        Verifica se o usuário é administrador do tenant do objeto.
        """
        if not request.user or not request.user.is_authenticated:
            return False
        
        if hasattr(obj, 'tenant'):
            return TenantUser.objects.filter(
                user=request.user,
                tenant=obj.tenant,
                role='ADMIN',
                is_active=True
            ).exists()
        
        return True


class IsTenantOperator(BasePermission):
    """
    Permissão que verifica se o usuário é operador ou administrador de um tenant.
    """
    
    def has_permission(self, request, view):
        """
        Verifica se o usuário é operador ou admin de pelo menos um tenant.
        """
        if not request.user or not request.user.is_authenticated:
            return False
        
        return TenantUser.objects.filter(
            user=request.user,
            role__in=['ADMIN', 'OPERATOR'],
            is_active=True
        ).exists()
    
    def has_object_permission(self, request, view, obj):
        """
        Verifica se o usuário é operador ou admin do tenant do objeto.
        """
        if not request.user or not request.user.is_authenticated:
            return False
        
        if hasattr(obj, 'tenant'):
            return TenantUser.objects.filter(
                user=request.user,
                tenant=obj.tenant,
                role__in=['ADMIN', 'OPERATOR'],
                is_active=True
            ).exists()
        
        return True