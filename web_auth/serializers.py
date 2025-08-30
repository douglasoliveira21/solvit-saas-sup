from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from tenants.models import TenantUser


class LoginSerializer(serializers.Serializer):
    """
    Serializer para login de usuários.
    """
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            # Busca usuário pelo email
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise serializers.ValidationError(
                    'Credenciais inválidas.'
                )
            
            # Autentica usuário
            user = authenticate(username=user.username, password=password)
            
            if not user:
                raise serializers.ValidationError(
                    'Credenciais inválidas.'
                )
            
            if not user.is_active:
                raise serializers.ValidationError(
                    'Conta de usuário desativada.'
                )
            
            attrs['user'] = user
        else:
            raise serializers.ValidationError(
                'Email e senha são obrigatórios.'
            )
        
        return attrs


class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer para registro de novos usuários.
    """
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)
    tenant_name = serializers.CharField(max_length=100)
    tenant_slug = serializers.SlugField(max_length=50)
    
    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 
                 'password', 'password_confirm', 'tenant_name', 'tenant_slug')
    
    def validate_email(self, value):
        """Valida se o email é único."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                'Já existe um usuário com este email.'
            )
        return value
    
    def validate_username(self, value):
        """Valida se o username é único."""
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError(
                'Já existe um usuário com este nome de usuário.'
            )
        return value
    
    def validate_tenant_slug(self, value):
        """Valida se o slug do tenant é único."""
        from tenants.models import Tenant
        if Tenant.objects.filter(slug=value).exists():
            raise serializers.ValidationError(
                'Já existe um tenant com este slug.'
            )
        return value
    
    def validate(self, attrs):
        """Valida se as senhas coincidem."""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError(
                {'password_confirm': 'As senhas não coincidem.'}
            )
        return attrs
    
    def create(self, validated_data):
        """Cria usuário e tenant associado."""
        from tenants.models import Tenant
        from tenants.models import TenantUser
        from django.db import transaction
        
        # Remove campos que não pertencem ao modelo User
        password_confirm = validated_data.pop('password_confirm')
        tenant_name = validated_data.pop('tenant_name')
        tenant_slug = validated_data.pop('tenant_slug')
        
        with transaction.atomic():
            # Cria usuário
            user = User.objects.create_user(**validated_data)
            
            # Cria tenant
            tenant = Tenant.objects.create(
                name=tenant_name,
                slug=tenant_slug,
                is_active=True
            )
            
            # Associa usuário ao tenant como admin
            TenantUser.objects.create(
                tenant=tenant,
                user=user,
                role='admin',
                is_active=True
            )
        
        return user


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer para perfil do usuário.
    """
    tenants = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 
                 'date_joined', 'last_login', 'tenants')
        read_only_fields = ('id', 'username', 'date_joined', 'last_login')
    
    def get_tenants(self, obj):
        """Retorna lista de tenants do usuário."""
        tenant_users = TenantUser.objects.filter(
            user=obj, 
            is_active=True
        ).select_related('tenant')
        
        return [{
            'id': tu.tenant.id,
            'name': tu.tenant.name,
            'slug': tu.tenant.slug,
            'role': tu.role,
            'is_active': tu.tenant.is_active
        } for tu in tenant_users]


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer para alteração de senha.
    """
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate_current_password(self, value):
        """Valida senha atual."""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                'Senha atual incorreta.'
            )
        return value
    
    def validate(self, attrs):
        """Valida se as novas senhas coincidem."""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError(
                {'new_password_confirm': 'As senhas não coincidem.'}
            )
        return attrs
    
    def save(self):
        """Altera a senha do usuário."""
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer para solicitação de reset de senha.
    """
    email = serializers.EmailField()
    
    def validate_email(self, value):
        """Valida se o email existe."""
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                'Não existe usuário com este email.'
            )
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer para confirmação de reset de senha.
    """
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """Valida se as senhas coincidem."""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError(
                {'new_password_confirm': 'As senhas não coincidem.'}
            )
        return attrs


class RefreshTokenSerializer(serializers.Serializer):
    """
    Serializer para refresh de token JWT.
    """
    refresh = serializers.CharField()