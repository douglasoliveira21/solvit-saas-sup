# Guia de Implantação - VPS Ubuntu

## 📋 Pré-requisitos

- VPS Ubuntu 20.04 LTS ou superior
- Acesso root ou usuário com privilégios sudo
- Domínio configurado (opcional, mas recomendado)
- Chaves SSH configuradas

## 🚀 Fase 1: Preparação do Servidor

### 1.1 Atualização do Sistema

```bash
# Conectar ao VPS
ssh root@seu-servidor-ip

# Atualizar pacotes
sudo apt update && sudo apt upgrade -y

# Instalar pacotes essenciais
sudo apt install -y curl wget git vim htop unzip software-properties-common
```

### 1.2 Criar Usuário para Aplicação

```bash
# Criar usuário dedicado
sudo adduser saasapp
sudo usermod -aG sudo saasapp

# Configurar SSH para o novo usuário
sudo mkdir -p /home/saasapp/.ssh
sudo cp ~/.ssh/authorized_keys /home/saasapp/.ssh/
sudo chown -R saasapp:saasapp /home/saasapp/.ssh
sudo chmod 700 /home/saasapp/.ssh
sudo chmod 600 /home/saasapp/.ssh/authorized_keys

# Trocar para o usuário da aplicação
su - saasapp
```

### 1.3 Configurar Firewall

```bash
# Configurar UFW
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
sudo ufw status
```

## 🐍 Fase 2: Instalação do Python e Dependências

### 2.1 Instalar Python 3.11

```bash
# Adicionar repositório Python
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update

# Instalar Python 3.11 e pip
sudo apt install -y python3.11 python3.11-venv python3.11-dev python3-pip

# Verificar instalação
python3.11 --version
```

### 2.2 Instalar Node.js (para frontend)

```bash
# Instalar Node.js 18.x
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verificar instalação
node --version
npm --version
```

## 🗄️ Fase 3: Configuração do PostgreSQL

### 3.1 Instalação do PostgreSQL

```bash
# Instalar PostgreSQL
sudo apt install -y postgresql postgresql-contrib postgresql-server-dev-all

# Iniciar e habilitar serviço
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### 3.2 Configuração do Banco de Dados

```bash
# Acessar PostgreSQL como usuário postgres
sudo -u postgres psql

-- Criar banco de dados e usuário
CREATE DATABASE saas_identity_db;
CREATE USER saasapp_user WITH PASSWORD 'sua_senha_super_segura';
ALTER ROLE saasapp_user SET client_encoding TO 'utf8';
ALTER ROLE saasapp_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE saasapp_user SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE saas_identity_db TO saasapp_user;
\q
```

### 3.3 Configurar Acesso ao PostgreSQL

```bash
# Editar configuração do PostgreSQL
sudo vim /etc/postgresql/*/main/postgresql.conf

# Adicionar/modificar:
# listen_addresses = 'localhost'

# Editar autenticação
sudo vim /etc/postgresql/*/main/pg_hba.conf

# Adicionar linha:
# local   saas_identity_db    saasapp_user                    md5

# Reiniciar PostgreSQL
sudo systemctl restart postgresql
```

## 🌐 Fase 4: Configuração do Nginx

### 4.1 Instalação do Nginx

```bash
# Instalar Nginx
sudo apt install -y nginx

# Iniciar e habilitar
sudo systemctl start nginx
sudo systemctl enable nginx
```

### 4.2 Configuração do Nginx

```bash
# Criar configuração do site
sudo vim /etc/nginx/sites-available/saas-identity
```

Conteúdo do arquivo de configuração:

```nginx
server {
    listen 80;
    server_name seu-dominio.com www.seu-dominio.com;
    
    # Logs
    access_log /var/log/nginx/saas_access.log;
    error_log /var/log/nginx/saas_error.log;
    
    # Frontend (React)
    location / {
        root /home/saasapp/saas-identity/frontend/dist;
        index index.html;
        try_files $uri $uri/ /index.html;
        
        # Cache para assets estáticos
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
    
    # Backend API
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Admin Django
    location /admin/ {
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
    }
    
    # Media files Django
    location /media/ {
        alias /home/saasapp/saas-identity/media/;
        expires 1y;
        add_header Cache-Control "public";
    }
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
}
```

```bash
# Habilitar site
sudo ln -s /etc/nginx/sites-available/saas-identity /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default

# Testar configuração
sudo nginx -t

# Reiniciar Nginx
sudo systemctl restart nginx
```

## 📁 Fase 5: Deploy da Aplicação

### 5.1 Clonar Repositório

```bash
# Ir para diretório home
cd /home/saasapp

# Clonar repositório (substitua pela URL do seu repo)
git clone https://github.com/seu-usuario/saas-identity.git
cd saas-identity
```

### 5.2 Configurar Backend Django

```bash
# Criar ambiente virtual
python3.11 -m venv venv
source venv/bin/activate

# Instalar dependências
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn psycopg2-binary
```

### 5.3 Configurar Variáveis de Ambiente

```bash
# Criar arquivo de ambiente
vim .env
```

Conteúdo do arquivo `.env`:

```env
# Django Settings
DEBUG=False
SECRET_KEY=sua_chave_secreta_super_longa_e_segura_aqui
ALLOWED_HOSTS=seu-dominio.com,www.seu-dominio.com,127.0.0.1,localhost

# Database
DATABASE_URL=postgresql://saasapp_user:sua_senha_super_segura@localhost:5432/saas_identity_db

# Security
CSRF_TRUSTED_ORIGINS=https://seu-dominio.com,https://www.seu-dominio.com
CORS_ALLOWED_ORIGINS=https://seu-dominio.com,https://www.seu-dominio.com

# Microsoft Graph (se aplicável)
MICROSOFT_CLIENT_ID=seu_client_id
MICROSOFT_CLIENT_SECRET=seu_client_secret
MICROSOFT_TENANT_ID=seu_tenant_id

# Email (opcional)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=seu-email@gmail.com
EMAIL_HOST_PASSWORD=sua_senha_app
EMAIL_USE_TLS=True

# Redis (se usar cache)
REDIS_URL=redis://localhost:6379/0
```

### 5.4 Executar Migrações e Coletar Arquivos Estáticos

```bash
# Ativar ambiente virtual
source venv/bin/activate

# Executar migrações
python manage.py migrate

# Criar superusuário
python manage.py createsuperuser

# Coletar arquivos estáticos
python manage.py collectstatic --noinput

# Testar aplicação
python manage.py runserver 127.0.0.1:8000
```

### 5.5 Configurar Gunicorn

```bash
# Criar arquivo de configuração do Gunicorn
vim gunicorn.conf.py
```

Conteúdo do `gunicorn.conf.py`:

```python
# Gunicorn configuration file
import multiprocessing

# Server socket
bind = "127.0.0.1:8000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Restart workers after this many requests
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = "/home/saasapp/saas-identity/logs/gunicorn_access.log"
errorlog = "/home/saasapp/saas-identity/logs/gunicorn_error.log"
loglevel = "info"

# Process naming
proc_name = "saas_identity_gunicorn"

# Server mechanics
preload_app = True
daemon = False
pidfile = "/home/saasapp/saas-identity/gunicorn.pid"
user = "saasapp"
group = "saasapp"
tmp_upload_dir = None

# SSL (se necessário)
# keyfile = "/path/to/keyfile"
# certfile = "/path/to/certfile"
```

```bash
# Criar diretório de logs
mkdir -p /home/saasapp/saas-identity/logs

# Testar Gunicorn
gunicorn saas_identity.wsgi:application -c gunicorn.conf.py
```

### 5.6 Configurar Systemd Service

```bash
# Criar service do systemd
sudo vim /etc/systemd/system/saas-identity.service
```

Conteúdo do service:

```ini
[Unit]
Description=SaaS Identity Gunicorn daemon
Requires=saas-identity.socket
After=network.target

[Service]
Type=notify
User=saasapp
Group=saasapp
RuntimeDirectory=gunicorn
WorkingDirectory=/home/saasapp/saas-identity
EnvironmentFile=/home/saasapp/saas-identity/.env
ExecStart=/home/saasapp/saas-identity/venv/bin/gunicorn \
          --config /home/saasapp/saas-identity/gunicorn.conf.py \
          saas_identity.wsgi:application
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
# Criar socket do systemd
sudo vim /etc/systemd/system/saas-identity.socket
```

Conteúdo do socket:

```ini
[Unit]
Description=SaaS Identity socket

[Socket]
ListenStream=/run/gunicorn.sock
SocketUser=www-data

[Install]
WantedBy=sockets.target
```

```bash
# Habilitar e iniciar serviços
sudo systemctl daemon-reload
sudo systemctl enable saas-identity.socket
sudo systemctl start saas-identity.socket
sudo systemctl enable saas-identity.service
sudo systemctl start saas-identity.service

# Verificar status
sudo systemctl status saas-identity.service
```

## 🎨 Fase 6: Deploy do Frontend

### 6.1 Build do Frontend

```bash
# Ir para diretório do frontend
cd /home/saasapp/saas-identity/frontend

# Instalar dependências
npm install

# Configurar variáveis de ambiente para produção
vim .env.production
```

Conteúdo do `.env.production`:

```env
VITE_API_URL=https://seu-dominio.com/api
VITE_APP_NAME=SaaS Identity Manager
VITE_APP_VERSION=1.0.0
```

```bash
# Build para produção
npm run build

# Verificar se o build foi criado
ls -la dist/
```

## 🔒 Fase 7: Configuração SSL com Let's Encrypt

### 7.1 Instalar Certbot

```bash
# Instalar Certbot
sudo apt install -y certbot python3-certbot-nginx

# Obter certificado SSL
sudo certbot --nginx -d seu-dominio.com -d www.seu-dominio.com

# Configurar renovação automática
sudo crontab -e

# Adicionar linha:
# 0 12 * * * /usr/bin/certbot renew --quiet
```

## 📊 Fase 8: Monitoramento e Logs

### 8.1 Configurar Logrotate

```bash
# Criar configuração de logrotate
sudo vim /etc/logrotate.d/saas-identity
```

Conteúdo:

```
/home/saasapp/saas-identity/logs/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 saasapp saasapp
    postrotate
        systemctl reload saas-identity.service
    endscript
}
```

### 8.2 Script de Monitoramento

```bash
# Criar script de monitoramento
vim /home/saasapp/monitor.sh
```

Conteúdo do script:

```bash
#!/bin/bash

# Verificar se os serviços estão rodando
services=("nginx" "postgresql" "saas-identity")

for service in "${services[@]}"; do
    if ! systemctl is-active --quiet $service; then
        echo "$(date): $service is not running!" >> /home/saasapp/monitor.log
        systemctl restart $service
    fi
done

# Verificar espaço em disco
disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $disk_usage -gt 80 ]; then
    echo "$(date): Disk usage is ${disk_usage}%" >> /home/saasapp/monitor.log
fi

# Verificar uso de memória
mem_usage=$(free | awk 'NR==2{printf "%.2f", $3*100/$2 }')
if (( $(echo "$mem_usage > 80" | bc -l) )); then
    echo "$(date): Memory usage is ${mem_usage}%" >> /home/saasapp/monitor.log
fi
```

```bash
# Tornar executável
chmod +x /home/saasapp/monitor.sh

# Adicionar ao crontab
crontab -e

# Adicionar linha:
# */5 * * * * /home/saasapp/monitor.sh
```

## 🔧 Comandos Úteis para Manutenção

### Logs
```bash
# Ver logs do Django
tail -f /home/saasapp/saas-identity/logs/gunicorn_error.log

# Ver logs do Nginx
sudo tail -f /var/log/nginx/saas_error.log

# Ver logs do systemd
sudo journalctl -u saas-identity.service -f
```

### Restart de Serviços
```bash
# Restart da aplicação
sudo systemctl restart saas-identity.service

# Restart do Nginx
sudo systemctl restart nginx

# Restart do PostgreSQL
sudo systemctl restart postgresql
```

### Backup do Banco de Dados
```bash
# Criar backup
pg_dump -h localhost -U saasapp_user -d saas_identity_db > backup_$(date +%Y%m%d_%H%M%S).sql

# Restaurar backup
psql -h localhost -U saasapp_user -d saas_identity_db < backup_file.sql
```

## ✅ Checklist Final

- [ ] Servidor atualizado e configurado
- [ ] Python 3.11 e Node.js instalados
- [ ] PostgreSQL configurado e funcionando
- [ ] Nginx configurado e funcionando
- [ ] Aplicação Django deployada
- [ ] Frontend React buildado e servido
- [ ] SSL configurado com Let's Encrypt
- [ ] Serviços systemd configurados
- [ ] Monitoramento e logs configurados
- [ ] Backup automatizado configurado
- [ ] Firewall configurado
- [ ] Domínio apontando para o servidor

## 🚨 Troubleshooting

### Problemas Comuns

1. **Erro 502 Bad Gateway**
   - Verificar se Gunicorn está rodando: `sudo systemctl status saas-identity.service`
   - Verificar logs: `sudo journalctl -u saas-identity.service`

2. **Erro de Conexão com Banco**
   - Verificar se PostgreSQL está rodando: `sudo systemctl status postgresql`
   - Testar conexão: `psql -h localhost -U saasapp_user -d saas_identity_db`

3. **Problemas de Permissão**
   - Verificar ownership: `sudo chown -R saasapp:saasapp /home/saasapp/saas-identity`
   - Verificar permissões: `chmod 755 /home/saasapp/saas-identity`

4. **Frontend não carrega**
   - Verificar se build existe: `ls -la /home/saasapp/saas-identity/frontend/dist/`
   - Verificar configuração do Nginx

Este guia fornece uma base sólida para deployment em VPS Ubuntu. Lembre-se de sempre testar em ambiente de staging antes de aplicar em produção!