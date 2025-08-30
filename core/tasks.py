from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def send_welcome_email(self, user_email, user_name, tenant_name, login_url):
    """
    Envia email de boas-vindas para novos usuários.
    """
    try:
        subject = f'Bem-vindo ao {tenant_name} - SaaS Identity'
        
        # Contexto para o template
        context = {
            'user_name': user_name,
            'tenant_name': tenant_name,
            'login_url': login_url,
            'support_email': settings.DEFAULT_FROM_EMAIL
        }
        
        # Renderiza o template HTML (se existir)
        try:
            html_message = render_to_string('emails/welcome_email.html', context)
            plain_message = strip_tags(html_message)
        except:
            # Fallback para mensagem simples se não houver template
            plain_message = f"""
Olá {user_name},

Sua conta foi criada com sucesso no {tenant_name}!

Você pode fazer login em: {login_url}

Se precisar de ajuda, entre em contato conosco em {settings.DEFAULT_FROM_EMAIL}

Atenciosamente,
Equipe {tenant_name}
"""
            html_message = None
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Email de boas-vindas enviado para {user_email}")
        return f"Email enviado com sucesso para {user_email}"
        
    except Exception as exc:
        logger.error(f"Erro ao enviar email de boas-vindas para {user_email}: {exc}")
        # Retry com backoff exponencial
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def send_password_reset_email(self, user_email, user_name, reset_url):
    """
    Envia email de reset de senha.
    """
    try:
        subject = 'Reset de Senha - SaaS Identity'
        
        context = {
            'user_name': user_name,
            'reset_url': reset_url,
            'support_email': settings.DEFAULT_FROM_EMAIL
        }
        
        try:
            html_message = render_to_string('emails/password_reset_email.html', context)
            plain_message = strip_tags(html_message)
        except:
            plain_message = f"""
Olá {user_name},

Você solicitou um reset de senha.

Clique no link abaixo para redefinir sua senha:
{reset_url}

Este link expira em 24 horas.

Se você não solicitou este reset, ignore este email.

Atenciosamente,
Equipe SaaS Identity
"""
            html_message = None
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Email de reset de senha enviado para {user_email}")
        return f"Email de reset enviado com sucesso para {user_email}"
        
    except Exception as exc:
        logger.error(f"Erro ao enviar email de reset para {user_email}: {exc}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def send_user_deactivation_email(self, user_email, user_name, tenant_name, admin_email):
    """
    Envia email de notificação quando um usuário é desativado.
    """
    try:
        subject = f'Conta Desativada - {tenant_name}'
        
        context = {
            'user_name': user_name,
            'tenant_name': tenant_name,
            'admin_email': admin_email,
            'support_email': settings.DEFAULT_FROM_EMAIL
        }
        
        try:
            html_message = render_to_string('emails/user_deactivation_email.html', context)
            plain_message = strip_tags(html_message)
        except:
            plain_message = f"""
Olá {user_name},

Sua conta no {tenant_name} foi desativada.

Se você acredita que isso foi um erro, entre em contato com o administrador em {admin_email}

Atenciosamente,
Equipe {tenant_name}
"""
            html_message = None
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Email de desativação enviado para {user_email}")
        return f"Email de desativação enviado com sucesso para {user_email}"
        
    except Exception as exc:
        logger.error(f"Erro ao enviar email de desativação para {user_email}: {exc}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def send_sync_notification_email(self, admin_email, tenant_name, sync_type, sync_status, sync_details):
    """
    Envia email de notificação sobre status de sincronização.
    """
    try:
        subject = f'Relatório de Sincronização - {tenant_name}'
        
        context = {
            'tenant_name': tenant_name,
            'sync_type': sync_type,
            'sync_status': sync_status,
            'sync_details': sync_details,
            'support_email': settings.DEFAULT_FROM_EMAIL
        }
        
        try:
            html_message = render_to_string('emails/sync_notification_email.html', context)
            plain_message = strip_tags(html_message)
        except:
            status_text = "concluída com sucesso" if sync_status == "success" else "falhou"
            plain_message = f"""
Olá,

A sincronização {sync_type} para {tenant_name} foi {status_text}.

Detalhes:
{sync_details}

Atenciosamente,
Sistema SaaS Identity
"""
            html_message = None
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[admin_email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Email de sincronização enviado para {admin_email}")
        return f"Email de sincronização enviado com sucesso para {admin_email}"
        
    except Exception as exc:
        logger.error(f"Erro ao enviar email de sincronização para {admin_email}: {exc}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))