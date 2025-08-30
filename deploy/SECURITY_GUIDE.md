# Guia de Segurança e SSL

## 🔒 Visão Geral

Este guia aborda as melhores práticas de segurança para a aplicação SaaS Identity, incluindo:
- Configuração SSL/TLS
- Hardening do servidor
- Segurança da aplicação Django
- Proteção contra ataques comuns
- Monitoramento de segurança
- Backup e recuperação

## 🛡️ Fase 1: Hardening do Servidor (VPS Ubuntu)

### 1.1 Configuração SSH Segura

```bash
# Backup da configuração original
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Editar configuração SSH
sudo vim /etc/ssh/sshd_config
```

Configurações recomendadas para `/etc/ssh/sshd_config`:

```bash
# Porta não padrão (opcional, mas recomendado)
Port 2222

# Protocolo SSH versão 2 apenas
Protocol 2

# Desabilitar login root
PermitRootLogin no

# Autenticação por chave apenas
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey

# Desabilitar autenticação vazia
PermitEmptyPasswords no

# Limitar usuários
AllowUsers saasapp

# Configurações de timeout
ClientAliveInterval 300
ClientAliveCountMax 2

# Desabilitar X11 forwarding
X11Forwarding no

# Desabilitar forwarding de agente
AllowAgentForwarding no

# Limitar tentativas de login
MaxAuthTries 3
MaxSessions 2

# Banner de aviso
Banner /etc/ssh/banner
```

Criar banner de aviso:

```bash
sudo vim /etc/ssh/banner
```

Conteúdo do banner:

```
***************************************************************************
                    SISTEMA AUTORIZADO APENAS
                    
Este sistema é para uso autorizado apenas. Todas as atividades são
monitoradas e registradas. Uso não autorizado é estritamente proibido
e pode resultar em ação legal.
***************************************************************************
```

```bash
# Reiniciar SSH
sudo systemctl restart sshd

# Verificar configuração
sudo sshd -t
```

### 1.2 Configuração do Firewall (UFW)

```bash
# Reset UFW para configuração limpa
sudo ufw --force reset

# Política padrão
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Permitir SSH (porta customizada)
sudo ufw allow 2222/tcp

# Permitir HTTP e HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Permitir PostgreSQL apenas localmente
sudo ufw allow from 127.0.0.1 to any port 5432

# Rate limiting para SSH
sudo ufw limit 2222/tcp

# Habilitar firewall
sudo ufw --force enable

# Verificar status
sudo ufw status verbose
```

### 1.3 Fail2Ban para Proteção contra Brute Force

```bash
# Instalar Fail2Ban
sudo apt install -y fail2ban

# Criar configuração local
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Editar configuração
sudo vim /etc/fail2ban/jail.local
```

Configurações recomendadas:

```ini
[DEFAULT]
# Banir por 1 hora
bantime = 3600

# Janela de tempo para contar tentativas (10 minutos)
findtime = 600

# Máximo de tentativas antes do ban
maxretry = 3

# Email para notificações
destemail = admin@seudominio.com
sender = fail2ban@seudominio.com

# Ação padrão
action = %(action_mwl)s

[sshd]
enabled = true
port = 2222
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 10
bantime = 600

[django-auth]
enabled = true
filter = django-auth
logpath = /home/saasapp/saas-identity/logs/django.log
maxretry = 5
bantime = 3600
```

Criar filtro personalizado para Django:

```bash
sudo vim /etc/fail2ban/filter.d/django-auth.conf
```

```ini
[Definition]
failregex = .*Invalid login attempt.*<HOST>
            .*Authentication failed.*<HOST>
            .*Failed login.*<HOST>
ignoreregex =
```

```bash
# Iniciar e habilitar Fail2Ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Verificar status
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

### 1.4 Configuração de Logs e Auditoria

```bash
# Instalar auditd
sudo apt install -y auditd audispd-plugins

# Configurar regras de auditoria
sudo vim /etc/audit/rules.d/audit.rules
```

Regras de auditoria:

```bash
# Deletar todas as regras existentes
-D

# Buffer size
-b 8192

# Falha de auditoria
-f 1

# Monitorar alterações em arquivos críticos
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity

# Monitorar configurações SSH
-w /etc/ssh/sshd_config -p wa -k sshd

# Monitorar logs
-w /var/log/auth.log -p wa -k auth
-w /var/log/syslog -p wa -k syslog

# Monitorar aplicação
-w /home/saasapp/saas-identity -p wa -k saas-app

# Monitorar comandos privilegiados
-a always,exit -F arch=b64 -S execve -F euid=0 -k root-commands
-a always,exit -F arch=b32 -S execve -F euid=0 -k root-commands

# Monitorar alterações de rede
-a always,exit -F arch=b64 -S socket -F a0=10 -k network
-a always,exit -F arch=b64 -S socket -F a0=2 -k network

# Tornar regras imutáveis
-e 2
```

```bash
# Reiniciar auditd
sudo systemctl restart auditd

# Verificar regras
sudo auditctl -l
```

## 🔐 Fase 2: SSL/TLS com Let's Encrypt

### 2.1 Instalação e Configuração do Certbot

```bash
# Instalar Certbot
sudo apt install -y certbot python3-certbot-nginx

# Obter certificado SSL
sudo certbot --nginx -d seudominio.com -d www.seudominio.com -d api.seudominio.com

# Verificar certificados
sudo certbot certificates
```

### 2.2 Configuração Avançada do Nginx para SSL

Editar `/etc/nginx/sites-available/saas-identity`:

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name seudominio.com www.seudominio.com api.seudominio.com;
    return 301 https://$server_name$request_uri;
}

# Main HTTPS server
server {
    listen 443 ssl http2;
    server_name seudominio.com www.seudominio.com;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/seudominio.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/seudominio.com/privkey.pem;
    
    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/seudominio.com/chain.pem;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https://api.seudominio.com; frame-ancestors 'none';" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    
    # Hide Nginx version
    server_tokens off;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
    
    # Logs
    access_log /var/log/nginx/saas_access.log;
    error_log /var/log/nginx/saas_error.log;
    
    # Frontend (React)
    location / {
        root /home/saasapp/saas-identity/frontend/dist;
        index index.html;
        try_files $uri $uri/ /index.html;
        
        # Cache para assets estáticos
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            add_header Vary "Accept-Encoding";
        }
    }
    
    # API Backend com rate limiting
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }
    
    # Login endpoint com rate limiting mais restritivo
    location /api/auth/login/ {
        limit_req zone=login burst=3 nodelay;
        
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Admin Django
    location /admin/ {
        # Restringir acesso por IP (opcional)
        # allow 192.168.1.0/24;
        # deny all;
        
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Static files Django
    location /static/ {
        alias /home/saasapp/saas-identity/staticfiles/;
        expires 1y;
        add_header Cache-Control "public";
        add_header Vary "Accept-Encoding";
    }
    
    # Media files Django
    location /media/ {
        alias /home/saasapp/saas-identity/media/;
        expires 1y;
        add_header Cache-Control "public";
    }
    
    # Bloquear acesso a arquivos sensíveis
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    location ~ ~$ {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Bloquear bots maliciosos
    if ($http_user_agent ~* (bot|crawler|spider|scraper)) {
        return 403;
    }
}

# API subdomain
server {
    listen 443 ssl http2;
    server_name api.seudominio.com;
    
    # SSL Configuration (mesmo do servidor principal)
    ssl_certificate /etc/letsencrypt/live/seudominio.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/seudominio.com/privkey.pem;
    
    # Incluir todas as configurações SSL do servidor principal
    include /etc/nginx/snippets/ssl-params.conf;
    
    # Rate limiting para API
    limit_req_zone $binary_remote_addr zone=api_subdomain:10m rate=200r/m;
    
    location / {
        limit_req zone=api_subdomain burst=50 nodelay;
        
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Criar snippet SSL reutilizável:

```bash
sudo vim /etc/nginx/snippets/ssl-params.conf
```

```nginx
# SSL Security Settings
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

# Security Headers
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Hide Nginx version
server_tokens off;
```

### 2.3 Configuração de Renovação Automática

```bash
# Testar renovação
sudo certbot renew --dry-run

# Configurar cron para renovação automática
sudo crontab -e

# Adicionar linha:
# 0 12 * * * /usr/bin/certbot renew --quiet && systemctl reload nginx

# Ou usar systemd timer
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

## 🛡️ Fase 3: Segurança da Aplicação Django

### 3.1 Configurações de Segurança no Django

Editar `settings.py`:

```python
# Security Settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Session Security
SESSION_COOKIE_AGE = 3600  # 1 hour
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'

# CSRF Protection
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_TRUSTED_ORIGINS = [
    'https://seudominio.com',
    'https://www.seudominio.com',
    'https://api.seudominio.com',
]

# CORS Settings
CORS_ALLOWED_ORIGINS = [
    'https://seudominio.com',
    'https://www.seudominio.com',
]
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = False

# Content Security Policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'", "'unsafe-eval'")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_FONT_SRC = ("'self'", "data:")
CSP_CONNECT_SRC = ("'self'", "https://api.seudominio.com")
CSP_FRAME_ANCESTORS = ("'none'",)

# Logging Security Events
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'security': {
            'format': 'SECURITY {levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'security_file': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': '/home/saasapp/saas-identity/logs/security.log',
            'formatter': 'security',
        },
        'django_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': '/home/saasapp/saas-identity/logs/django.log',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django.security': {
            'handlers': ['security_file'],
            'level': 'WARNING',
            'propagate': False,
        },
        'django': {
            'handlers': ['django_file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

# Rate Limiting (usando django-ratelimit)
RATELIMIT_ENABLE = True

# Password Validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Admin Security
ADMIN_URL = 'secure-admin-' + get_random_string(20) + '/'
```

### 3.2 Middleware de Segurança Personalizado

Criar `middleware/security.py`:

```python
import logging
import time
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.signals import user_login_failed
from django.dispatch import receiver

security_logger = logging.getLogger('django.security')

class SecurityMiddleware(MiddlewareMixin):
    """Middleware de segurança personalizado"""
    
    def process_request(self, request):
        # Rate limiting por IP
        ip = self.get_client_ip(request)
        
        # Verificar tentativas de login falhadas
        failed_attempts = cache.get(f'failed_login_{ip}', 0)
        if failed_attempts >= 5:
            security_logger.warning(f'IP blocked due to failed login attempts: {ip}')
            return HttpResponseForbidden('Too many failed login attempts')
        
        # Verificar User-Agent suspeito
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        suspicious_agents = ['bot', 'crawler', 'spider', 'scraper']
        if any(agent in user_agent.lower() for agent in suspicious_agents):
            security_logger.warning(f'Suspicious user agent blocked: {user_agent} from {ip}')
            return HttpResponseForbidden('Access denied')
        
        # Log de tentativas de acesso a paths sensíveis
        sensitive_paths = ['/admin/', '/.env', '/config/', '/backup/']
        if any(path in request.path for path in sensitive_paths):
            security_logger.info(f'Access to sensitive path: {request.path} from {ip}')
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

@receiver(user_login_failed)
def handle_failed_login(sender, credentials, request, **kwargs):
    """Registrar tentativas de login falhadas"""
    ip = request.META.get('REMOTE_ADDR')
    username = credentials.get('username', 'unknown')
    
    # Incrementar contador de tentativas falhadas
    cache_key = f'failed_login_{ip}'
    failed_attempts = cache.get(cache_key, 0) + 1
    cache.set(cache_key, failed_attempts, 300)  # 5 minutos
    
    security_logger.warning(f'Failed login attempt for user {username} from {ip}. Attempt #{failed_attempts}')
```

### 3.3 Validação de Input e Sanitização

Criar `utils/security.py`:

```python
import re
import html
from django.core.exceptions import ValidationError
from django.utils.html import strip_tags

def sanitize_input(value):
    """Sanitizar input do usuário"""
    if isinstance(value, str):
        # Remover tags HTML
        value = strip_tags(value)
        # Escapar caracteres HTML
        value = html.escape(value)
        # Remover caracteres de controle
        value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
    return value

def validate_no_sql_injection(value):
    """Validar contra SQL injection"""
    sql_patterns = [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)',
        r'(--|#|/\*|\*/)',
        r'(\b(OR|AND)\s+\d+\s*=\s*\d+)',
        r'(\b(OR|AND)\s+[\'"]\w+[\'"]\s*=\s*[\'"]\w+[\'"])',
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, str(value), re.IGNORECASE):
            raise ValidationError('Potentially malicious input detected')

def validate_no_xss(value):
    """Validar contra XSS"""
    xss_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>.*?</iframe>',
        r'<object[^>]*>.*?</object>',
        r'<embed[^>]*>.*?</embed>',
    ]
    
    for pattern in xss_patterns:
        if re.search(pattern, str(value), re.IGNORECASE):
            raise ValidationError('Potentially malicious script detected')

class SecureModelMixin:
    """Mixin para adicionar validação de segurança aos models"""
    
    def clean(self):
        super().clean()
        
        # Validar todos os campos de texto
        for field in self._meta.fields:
            if hasattr(self, field.name):
                value = getattr(self, field.name)
                if isinstance(value, str):
                    validate_no_sql_injection(value)
                    validate_no_xss(value)
                    setattr(self, field.name, sanitize_input(value))
```

## 🔍 Fase 4: Monitoramento de Segurança

### 4.1 Script de Monitoramento de Segurança

Criar `/home/saasapp/security_monitor.py`:

```python
#!/usr/bin/env python3

import os
import re
import smtplib
import subprocess
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class SecurityMonitor:
    def __init__(self):
        self.alerts = []
        self.log_files = {
            'auth': '/var/log/auth.log',
            'nginx': '/var/log/nginx/saas_error.log',
            'django': '/home/saasapp/saas-identity/logs/security.log',
            'fail2ban': '/var/log/fail2ban.log'
        }
    
    def check_failed_logins(self):
        """Verificar tentativas de login falhadas"""
        try:
            with open(self.log_files['auth'], 'r') as f:
                lines = f.readlines()[-1000:]  # Últimas 1000 linhas
            
            failed_attempts = 0
            for line in lines:
                if 'Failed password' in line or 'Invalid user' in line:
                    failed_attempts += 1
            
            if failed_attempts > 10:
                self.alerts.append(f"High number of failed login attempts: {failed_attempts}")
        except Exception as e:
            self.alerts.append(f"Error checking auth logs: {e}")
    
    def check_disk_space(self):
        """Verificar espaço em disco"""
        try:
            result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                usage = lines[1].split()[4].replace('%', '')
                if int(usage) > 85:
                    self.alerts.append(f"High disk usage: {usage}%")
        except Exception as e:
            self.alerts.append(f"Error checking disk space: {e}")
    
    def check_memory_usage(self):
        """Verificar uso de memória"""
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
            
            total_match = re.search(r'MemTotal:\s+(\d+)', meminfo)
            available_match = re.search(r'MemAvailable:\s+(\d+)', meminfo)
            
            if total_match and available_match:
                total = int(total_match.group(1))
                available = int(available_match.group(1))
                used_percent = ((total - available) / total) * 100
                
                if used_percent > 85:
                    self.alerts.append(f"High memory usage: {used_percent:.1f}%")
        except Exception as e:
            self.alerts.append(f"Error checking memory usage: {e}")
    
    def check_service_status(self):
        """Verificar status dos serviços críticos"""
        services = ['nginx', 'postgresql', 'saas-identity', 'fail2ban']
        
        for service in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True, text=True
                )
                if result.stdout.strip() != 'active':
                    self.alerts.append(f"Service {service} is not active")
            except Exception as e:
                self.alerts.append(f"Error checking service {service}: {e}")
    
    def check_ssl_expiry(self):
        """Verificar expiração do certificado SSL"""
        try:
            result = subprocess.run([
                'openssl', 's_client', '-connect', 'seudominio.com:443',
                '-servername', 'seudominio.com'
            ], input='', capture_output=True, text=True, timeout=10)
            
            cert_info = subprocess.run([
                'openssl', 'x509', '-noout', '-dates'
            ], input=result.stdout, capture_output=True, text=True)
            
            for line in cert_info.stdout.split('\n'):
                if 'notAfter=' in line:
                    expiry_str = line.split('notAfter=')[1]
                    expiry_date = datetime.strptime(expiry_str.strip(), '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        self.alerts.append(f"SSL certificate expires in {days_until_expiry} days")
        except Exception as e:
            self.alerts.append(f"Error checking SSL certificate: {e}")
    
    def send_alerts(self):
        """Enviar alertas por email"""
        if not self.alerts:
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = 'security@seudominio.com'
            msg['To'] = 'admin@seudominio.com'
            msg['Subject'] = f'Security Alert - {datetime.now().strftime("%Y-%m-%d %H:%M")}'
            
            body = "Security alerts detected:\n\n"
            for alert in self.alerts:
                body += f"• {alert}\n"
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Configurar SMTP (ajustar conforme seu provedor)
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login('security@seudominio.com', 'sua_senha_app')
            server.send_message(msg)
            server.quit()
            
            print(f"Alerts sent: {len(self.alerts)} issues detected")
        except Exception as e:
            print(f"Error sending alerts: {e}")
    
    def run_checks(self):
        """Executar todas as verificações"""
        self.check_failed_logins()
        self.check_disk_space()
        self.check_memory_usage()
        self.check_service_status()
        self.check_ssl_expiry()
        
        if self.alerts:
            self.send_alerts()
        else:
            print("All security checks passed")

if __name__ == '__main__':
    monitor = SecurityMonitor()
    monitor.run_checks()
```

```bash
# Tornar executável
chmod +x /home/saasapp/security_monitor.py

# Adicionar ao crontab para execução a cada hora
crontab -e

# Adicionar linha:
# 0 * * * * /usr/bin/python3 /home/saasapp/security_monitor.py
```

## 💾 Fase 5: Backup e Recuperação

### 5.1 Script de Backup Automatizado

Criar `/home/saasapp/backup.sh`:

```bash
#!/bin/bash

set -e

# Configurações
BACKUP_DIR="/home/saasapp/backups"
APP_DIR="/home/saasapp/saas-identity"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Criar diretório de backup
mkdir -p $BACKUP_DIR

echo "Starting backup at $(date)"

# Backup do banco de dados
echo "Backing up database..."
pg_dump -h localhost -U saasapp_user -d saas_identity_db > $BACKUP_DIR/db_backup_$DATE.sql

# Backup dos arquivos da aplicação
echo "Backing up application files..."
tar -czf $BACKUP_DIR/app_backup_$DATE.tar.gz -C /home/saasapp saas-identity --exclude='saas-identity/venv' --exclude='saas-identity/logs' --exclude='saas-identity/__pycache__'

# Backup dos logs
echo "Backing up logs..."
tar -czf $BACKUP_DIR/logs_backup_$DATE.tar.gz -C $APP_DIR logs/

# Backup das configurações do sistema
echo "Backing up system configs..."
sudo tar -czf $BACKUP_DIR/system_backup_$DATE.tar.gz /etc/nginx/sites-available/saas-identity /etc/systemd/system/saas-identity.service /etc/fail2ban/jail.local

# Criptografar backups
echo "Encrypting backups..."
for file in $BACKUP_DIR/*_$DATE.*; do
    gpg --symmetric --cipher-algo AES256 --compress-algo 1 --s2k-mode 3 --s2k-digest-algo SHA512 --s2k-count 65536 --quiet --batch --passphrase "sua_senha_de_backup" "$file"
    rm "$file"
done

# Remover backups antigos
echo "Cleaning old backups..."
find $BACKUP_DIR -name "*.gpg" -mtime +$RETENTION_DAYS -delete

# Verificar espaço em disco
echo "Disk usage after backup:"
df -h $BACKUP_DIR

echo "Backup completed at $(date)"

# Enviar notificação (opcional)
echo "Backup completed successfully at $(date)" | mail -s "Backup Report - $(date +%Y-%m-%d)" admin@seudominio.com
```

```bash
# Tornar executável
chmod +x /home/saasapp/backup.sh

# Configurar cron para backup diário às 2:00 AM
crontab -e

# Adicionar linha:
# 0 2 * * * /home/saasapp/backup.sh >> /home/saasapp/backup.log 2>&1
```

### 5.2 Script de Restauração

Criar `/home/saasapp/restore.sh`:

```bash
#!/bin/bash

set -e

BACKUP_DIR="/home/saasapp/backups"
APP_DIR="/home/saasapp/saas-identity"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_date>"
    echo "Available backups:"
    ls -la $BACKUP_DIR/*.gpg | grep -o '[0-9]\{8\}_[0-9]\{6\}' | sort -u
    exit 1
fi

BACKUP_DATE=$1

echo "Starting restore from backup $BACKUP_DATE"

# Parar serviços
echo "Stopping services..."
sudo systemctl stop saas-identity.service
sudo systemctl stop nginx

# Descriptografar backups
echo "Decrypting backups..."
for file in $BACKUP_DIR/*_$BACKUP_DATE.*.gpg; do
    gpg --quiet --batch --yes --decrypt --passphrase "sua_senha_de_backup" "$file" > "${file%.gpg}"
done

# Restaurar banco de dados
echo "Restoring database..."
psql -h localhost -U saasapp_user -d saas_identity_db < $BACKUP_DIR/db_backup_$BACKUP_DATE.sql

# Backup atual antes da restauração
echo "Creating current backup before restore..."
mv $APP_DIR $APP_DIR.backup.$(date +%Y%m%d_%H%M%S)

# Restaurar aplicação
echo "Restoring application..."
tar -xzf $BACKUP_DIR/app_backup_$BACKUP_DATE.tar.gz -C /home/saasapp/

# Restaurar logs
echo "Restoring logs..."
tar -xzf $BACKUP_DIR/logs_backup_$BACKUP_DATE.tar.gz -C $APP_DIR/

# Restaurar configurações do sistema
echo "Restoring system configs..."
sudo tar -xzf $BACKUP_DIR/system_backup_$BACKUP_DATE.tar.gz -C /

# Ajustar permissões
echo "Fixing permissions..."
sudo chown -R saasapp:saasapp $APP_DIR
chmod +x $APP_DIR/startup.sh

# Reiniciar serviços
echo "Starting services..."
sudo systemctl start saas-identity.service
sudo systemctl start nginx

# Verificar saúde
echo "Checking application health..."
sleep 10
curl -f http://localhost:8000/api/health/ || echo "Warning: Health check failed"

echo "Restore completed at $(date)"

# Limpar arquivos descriptografados
rm -f $BACKUP_DIR/*_$BACKUP_DATE.*
echo "Temporary files cleaned"
```

```bash
# Tornar executável
chmod +x /home/saasapp/restore.sh
```

## ✅ Checklist de Segurança

### Servidor
- [ ] SSH configurado com chaves apenas
- [ ] Firewall UFW configurado
- [ ] Fail2Ban instalado e configurado
- [ ] Auditd configurado
- [ ] Usuário não-root para aplicação
- [ ] Porta SSH não padrão
- [ ] Rate limiting configurado

### SSL/TLS
- [ ] Certificado Let's Encrypt instalado
- [ ] Renovação automática configurada
- [ ] Configurações SSL seguras
- [ ] HSTS habilitado
- [ ] OCSP Stapling configurado

### Aplicação
- [ ] Configurações de segurança Django
- [ ] Middleware de segurança
- [ ] Validação de input
- [ ] Logs de segurança
- [ ] Rate limiting na aplicação
- [ ] CORS configurado corretamente

### Monitoramento
- [ ] Script de monitoramento configurado
- [ ] Alertas por email configurados
- [ ] Logs centralizados
- [ ] Verificação de saúde automática

### Backup
- [ ] Backup automático configurado
- [ ] Backups criptografados
- [ ] Script de restauração testado
- [ ] Retenção de backups configurada

## 🚨 Plano de Resposta a Incidentes

### 1. Detecção de Intrusão
```bash
# Verificar conexões ativas
ss -tuln
netstat -an | grep ESTABLISHED

# Verificar processos suspeitos
ps aux | grep -v "\[.*\]"
top -c

# Verificar logs de autenticação
tail -f /var/log/auth.log
grep "Failed password" /var/log/auth.log | tail -20

# Verificar tentativas de acesso
tail -f /var/log/nginx/saas_access.log
grep "404\|403\|500" /var/log/nginx/saas_error.log
```

### 2. Bloqueio de IP Suspeito
```bash
# Bloquear IP imediatamente
sudo ufw insert 1 deny from IP_SUSPEITO

# Adicionar ao Fail2Ban permanentemente
sudo fail2ban-client set sshd banip IP_SUSPEITO

# Verificar IPs banidos
sudo fail2ban-client status sshd
```

### 3. Isolamento da Aplicação
```bash
# Parar aplicação
sudo systemctl stop saas-identity.service

# Bloquear tráfego web
sudo ufw deny 80
sudo ufw deny 443

# Criar backup de emergência
/home/saasapp/backup.sh

# Analisar logs
grep -i "error\|warning\|failed" /home/saasapp/saas-identity/logs/*.log
```

Este guia fornece uma base sólida para a segurança da aplicação. Lembre-se de sempre manter os sistemas atualizados e revisar regularmente as configurações de segurança!