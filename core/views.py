from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.db import connection
from django.utils import timezone
from .models import AuditLog, SystemConfiguration
from .serializers import AuditLogSerializer, SystemConfigurationSerializer
import logging

logger = logging.getLogger(__name__)


class HealthCheckView(APIView):
    """Endpoint para verificação de saúde do sistema"""
    permission_classes = []
    
    def get(self, request):
        try:
            # Verifica conexão com banco de dados
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            
            health_data = {
                'status': 'healthy',
                'timestamp': timezone.now(),
                'database': 'connected',
                'version': '1.0.0'
            }
            
            return Response(health_data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return Response({
                'status': 'unhealthy',
                'timestamp': timezone.now(),
                'error': str(e)
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet para logs de auditoria (apenas leitura)"""
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ['action', 'resource_type', 'success', 'tenant']
    search_fields = ['description', 'resource_name']
    ordering_fields = ['created_at', 'action']
    ordering = ['-created_at']
    
    def get_queryset(self):
        queryset = AuditLog.objects.all()
        
        # Se o usuário não é admin, filtra apenas logs do seu tenant
        if not self.request.user.is_staff:
            user_tenant = getattr(self.request.user, 'tenant', None)
            if user_tenant:
                queryset = queryset.filter(tenant=user_tenant)
        
        return queryset
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Estatísticas dos logs de auditoria"""
        queryset = self.get_queryset()
        
        stats = {
            'total_logs': queryset.count(),
            'success_rate': queryset.filter(success=True).count() / max(queryset.count(), 1) * 100,
            'actions_summary': {},
            'resource_summary': {},
            'recent_errors': queryset.filter(success=False)[:5].values(
                'action', 'resource_type', 'error_message', 'created_at'
            )
        }
        
        # Resumo por ação
        for action in AuditLog.ACTION_CHOICES:
            count = queryset.filter(action=action[0]).count()
            if count > 0:
                stats['actions_summary'][action[1]] = count
        
        # Resumo por tipo de recurso
        for resource in AuditLog.RESOURCE_CHOICES:
            count = queryset.filter(resource_type=resource[0]).count()
            if count > 0:
                stats['resource_summary'][resource[1]] = count
        
        return Response(stats)


class SystemConfigurationViewSet(viewsets.ModelViewSet):
    """ViewSet para configurações do sistema"""
    queryset = SystemConfiguration.objects.all()
    serializer_class = SystemConfigurationSerializer
    permission_classes = [IsAdminUser]
    lookup_field = 'key'
    
    def list(self, request, *args, **kwargs):
        """Lista configurações, ocultando valores sensíveis"""
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        # Oculta valores sensíveis na listagem
        data = serializer.data
        for item in data:
            if item.get('is_sensitive'):
                item['value'] = '***HIDDEN***'
        
        return Response(data)
    
    @action(detail=True, methods=['post'])
    def toggle_sensitive(self, request, key=None):
        """Alterna o status de sensibilidade de uma configuração"""
        config = self.get_object()
        config.is_sensitive = not config.is_sensitive
        config.save()
        
        return Response({
            'key': config.key,
            'is_sensitive': config.is_sensitive
        })