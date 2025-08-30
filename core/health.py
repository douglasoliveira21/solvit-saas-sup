from django.http import JsonResponse
from django.db import connection
from django.core.cache import cache
from django.conf import settings
import redis
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def health_check(request):
    """
    Health check endpoint for monitoring application status.
    Returns detailed health information about various components.
    """
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': getattr(settings, 'VERSION', '1.0.0'),
        'checks': {}
    }
    
    overall_healthy = True
    
    # Database Health Check
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        health_status['checks']['database'] = {
            'status': 'healthy',
            'message': 'Database connection successful'
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        health_status['checks']['database'] = {
            'status': 'unhealthy',
            'message': f'Database connection failed: {str(e)}'
        }
        overall_healthy = False
    
    # Redis/Cache Health Check
    try:
        cache.set('health_check', 'test', 30)
        cache_value = cache.get('health_check')
        if cache_value == 'test':
            health_status['checks']['cache'] = {
                'status': 'healthy',
                'message': 'Cache connection successful'
            }
        else:
            raise Exception("Cache value mismatch")
    except Exception as e:
        logger.error(f"Cache health check failed: {e}")
        health_status['checks']['cache'] = {
            'status': 'unhealthy',
            'message': f'Cache connection failed: {str(e)}'
        }
        overall_healthy = False
    
    # Redis Direct Connection Check (for Celery)
    try:
        redis_url = getattr(settings, 'CELERY_BROKER_URL', None)
        if redis_url:
            r = redis.from_url(redis_url)
            r.ping()
            health_status['checks']['redis'] = {
                'status': 'healthy',
                'message': 'Redis connection successful'
            }
        else:
            health_status['checks']['redis'] = {
                'status': 'skipped',
                'message': 'Redis URL not configured'
            }
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        health_status['checks']['redis'] = {
            'status': 'unhealthy',
            'message': f'Redis connection failed: {str(e)}'
        }
        overall_healthy = False
    
    # Microsoft Graph API Health Check (basic)
    try:
        msgraph_client_id = getattr(settings, 'MSGRAPH_CLIENT_ID', None)
        msgraph_client_secret = getattr(settings, 'MSGRAPH_CLIENT_SECRET', None)
        
        if msgraph_client_id and msgraph_client_secret:
            health_status['checks']['msgraph'] = {
                'status': 'configured',
                'message': 'Microsoft Graph credentials configured'
            }
        else:
            health_status['checks']['msgraph'] = {
                'status': 'not_configured',
                'message': 'Microsoft Graph credentials not configured'
            }
    except Exception as e:
        logger.error(f"Microsoft Graph health check failed: {e}")
        health_status['checks']['msgraph'] = {
            'status': 'error',
            'message': f'Microsoft Graph check failed: {str(e)}'
        }
    
    # Agent API Health Check
    try:
        agent_secret = getattr(settings, 'AGENT_API_SECRET_KEY', None)
        if agent_secret:
            health_status['checks']['agent_api'] = {
                'status': 'configured',
                'message': 'Agent API secret configured'
            }
        else:
            health_status['checks']['agent_api'] = {
                'status': 'not_configured',
                'message': 'Agent API secret not configured'
            }
    except Exception as e:
        logger.error(f"Agent API health check failed: {e}")
        health_status['checks']['agent_api'] = {
            'status': 'error',
            'message': f'Agent API check failed: {str(e)}'
        }
    
    # Overall Status
    if not overall_healthy:
        health_status['status'] = 'unhealthy'
    
    # Return appropriate HTTP status code
    status_code = 200 if overall_healthy else 503
    
    return JsonResponse(health_status, status=status_code)


def readiness_check(request):
    """
    Readiness check endpoint for Kubernetes/container orchestration.
    Returns 200 if the application is ready to serve traffic.
    """
    try:
        # Check database connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        
        # Check cache connection
        cache.set('readiness_check', 'ready', 10)
        cache_value = cache.get('readiness_check')
        
        if cache_value == 'ready':
            return JsonResponse({
                'status': 'ready',
                'timestamp': datetime.now().isoformat()
            })
        else:
            raise Exception("Cache not ready")
            
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return JsonResponse({
            'status': 'not_ready',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }, status=503)


def liveness_check(request):
    """
    Liveness check endpoint for Kubernetes/container orchestration.
    Returns 200 if the application is alive (basic functionality).
    """
    return JsonResponse({
        'status': 'alive',
        'timestamp': datetime.now().isoformat()
    })