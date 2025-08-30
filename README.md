# SaaS Identity Management Platform

Uma plataforma SaaS para gerenciamento de identidades com integração ao Active Directory e Microsoft 365.

## 📋 Visão Geral

Esta plataforma permite que organizações gerenciem usuários e grupos de forma centralizada, com sincronização automática entre Active Directory on-premises e Microsoft 365 na nuvem.

### Principais Funcionalidades

- **Multi-tenant**: Suporte a múltiplos tenants isolados
- **Integração AD**: Sincronização com Active Directory on-premises via agente
- **Integração M365**: Sincronização com Microsoft 365 via Microsoft Graph API
- **API REST**: APIs completas para gerenciamento de usuários, grupos e configurações
- **Autenticação JWT**: Sistema de autenticação seguro para painel web
- **Logs de Auditoria**: Rastreamento completo de todas as operações

## 🏗️ Arquitetura

### Componentes Principais

1. **Backend Django**: API REST com Django REST Framework
2. **Agente On-premises**: Aplicação que roda na rede local para integração com AD
3. **Frontend Web**: Painel de administração (não incluído neste repositório)
4. **Banco de Dados**: PostgreSQL para persistência de dados
5. **Cache/Queue**: Redis para cache e filas de tarefas

### Estrutura de Apps

```
saas_identity/
├── core/                    # Modelos base e utilitários
├── tenants/                 # Gerenciamento de tenants e usuários
├── msgraph_integration/     # Integração com Microsoft Graph API
├── agent_api/              # APIs para comunicação com agente
├── web_auth/               # Autenticação JWT para painel web
└── saas_identity/          # Configurações do projeto
```

## 🚀 Configuração e Instalação

### Pré-requisitos

- Python 3.9+
- PostgreSQL 12+
- Redis 6+
- Conta Microsoft Azure (para integração M365)

### Instalação

1. **Clone o repositório**
```bash
git clone <repository-url>
cd teste-saas
```

2. **Crie e ative um ambiente virtual**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows
```

3. **Instale as dependências**
```bash
pip install -r requirements.txt
```

4. **Configure as variáveis de ambiente**

Crie um arquivo `.env` na raiz do projeto:

```env
# Django
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DB_NAME=saas_identity
DB_USER=postgres
DB_PASSWORD=your-db-password
DB_HOST=localhost
DB_PORT=5432

# Redis
REDIS_URL=redis://localhost:6379/0

# Microsoft Graph
MSGRAPH_CLIENT_ID=your-azure-app-client-id
MSGRAPH_CLIENT_SECRET=your-azure-app-client-secret
MSGRAPH_TENANT_ID=your-azure-tenant-id

# Agent API
AGENT_API_SECRET_KEY=your-agent-secret-key

# Frontend
FRONTEND_URL=http://localhost:3000

# Email (opcional)
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-email-password
DEFAULT_FROM_EMAIL=noreply@yourdomain.com
```

5. **Execute as migrações**
```bash
python manage.py makemigrations
python manage.py migrate
```

6. **Crie um superusuário**
```bash
python manage.py createsuperuser
```

7. **Inicie o servidor de desenvolvimento**
```bash
python manage.py runserver
```

## 📚 Documentação da API

### Autenticação Web (JWT)

#### Registro de Usuário
```http
POST /api/auth/register/
Content-Type: application/json

{
    "username": "admin",
    "email": "admin@example.com",
    "password": "securepassword",
    "password_confirm": "securepassword",
    "first_name": "Admin",
    "last_name": "User",
    "tenant_name": "Minha Empresa",
    "tenant_slug": "minha-empresa"
}
```

#### Login
```http
POST /api/auth/login/
Content-Type: application/json

{
    "email": "admin@example.com",
    "password": "securepassword"
}
```

#### Refresh Token
```http
POST /api/auth/token/refresh/
Content-Type: application/json

{
    "refresh": "your-refresh-token"
}
```

### Gerenciamento de Tenants

#### Listar Tenants
```http
GET /api/tenants/tenants/
Authorization: Bearer your-access-token
```

#### Criar Tenant
```http
POST /api/tenants/tenants/
Authorization: Bearer your-access-token
Content-Type: application/json

{
    "name": "Nova Empresa",
    "slug": "nova-empresa",
    "domain": "novaempresa.com"
}
```

### Gerenciamento de Usuários

#### Listar Usuários Gerenciados
```http
GET /api/tenants/managed-users/
Authorization: Bearer your-access-token
```

#### Criar Usuário
```http
POST /api/tenants/managed-users/
Authorization: Bearer your-access-token
Content-Type: application/json

{
    "username": "joao.silva",
    "email": "joao.silva@empresa.com",
    "first_name": "João",
    "last_name": "Silva",
    "display_name": "João Silva"
}
```

### APIs do Agente

#### Heartbeat
```http
POST /api/agent/heartbeat/
Agent-Key: your-agent-api-key
Content-Type: application/json

{
    "agent_version": "1.0.0",
    "status": "running",
    "system_info": {
        "os": "Windows Server 2019",
        "hostname": "DC01"
    }
}
```

#### Sincronizar Usuários
```http
POST /api/agent/sync/sync_users/
Agent-Key: your-agent-api-key
Content-Type: application/json

{
    "users": [
        {
            "username": "joao.silva",
            "email": "joao.silva@empresa.com",
            "first_name": "João",
            "last_name": "Silva",
            "ad_object_guid": "12345678-1234-1234-1234-123456789012",
            "is_active": true
        }
    ]
}
```

## 🔧 Configuração do Microsoft Graph

1. **Registre uma aplicação no Azure AD**
   - Acesse o [Portal Azure](https://portal.azure.com)
   - Vá para "Azure Active Directory" > "App registrations"
   - Clique em "New registration"

2. **Configure as permissões**
   - API permissions > Add a permission > Microsoft Graph
   - Application permissions:
     - `User.ReadWrite.All`
     - `Group.ReadWrite.All`
     - `Directory.Read.All`

3. **Gere um client secret**
   - Certificates & secrets > New client secret
   - Copie o valor e adicione ao `.env`

4. **Configure as URLs de redirecionamento** (se necessário)
   - Authentication > Add a platform > Web
   - Adicione as URLs do seu frontend

## 🔐 Segurança

### Autenticação

- **JWT Tokens**: Tokens de acesso com expiração de 1 hora
- **Refresh Tokens**: Tokens de renovação com expiração de 7 dias
- **Token Blacklist**: Tokens invalidados no logout

### Autorização

- **Multi-tenant**: Isolamento completo entre tenants
- **Roles**: Sistema de papéis (admin, user)
- **Permissions**: Controle granular de permissões

### API do Agente

- **API Keys**: Autenticação via chaves de API
- **IP Whitelist**: Restrição por endereços IP (configurável)
- **Rate Limiting**: Limitação de requisições

## 📊 Monitoramento e Logs

### Logs de Auditoria

Todas as operações são registradas com:
- Usuário responsável
- Ação executada
- Recurso afetado
- Timestamp
- IP de origem
- Detalhes da operação

### Logs de Sistema

Logs são salvos em:
- Console (desenvolvimento)
- Arquivo `logs/django.log` (produção)

### Métricas

- Heartbeats dos agentes
- Status de sincronização
- Estatísticas de usuários e grupos

## 🚀 Deploy em Produção

### Usando Docker (Recomendado)

```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["gunicorn", "saas_identity.wsgi:application", "--bind", "0.0.0.0:8000"]
```

### Configurações de Produção

1. **Defina `DEBUG=False`**
2. **Configure HTTPS**
3. **Use um banco PostgreSQL dedicado**
4. **Configure Redis para cache e filas**
5. **Configure um servidor de email**
6. **Use um proxy reverso (Nginx)**

## 🤝 Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📝 Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

## 📞 Suporte

Para suporte, entre em contato através de:
- Email: suporte@saasidentity.com
- Issues: [GitHub Issues](https://github.com/seu-usuario/teste-saas/issues)

## 🔄 Roadmap

- [ ] Interface web completa
- [ ] Integração com outros provedores de identidade
- [ ] API GraphQL
- [ ] Webhooks para eventos
- [ ] Dashboard de analytics
- [ ] Integração com LDAP
- [ ] SSO (Single Sign-On)
- [ ] MFA (Multi-Factor Authentication)