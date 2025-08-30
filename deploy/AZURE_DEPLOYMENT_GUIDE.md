# Guia de Implantação - Azure App Service

## 📋 Visão Geral

Este guia fornece instruções detalhadas para implantar a aplicação SaaS Identity no Azure App Service, incluindo:
- Configuração do Azure App Service para backend Django
- Configuração do Azure Static Web Apps para frontend React
- Configuração do Azure Database for PostgreSQL
- Configuração de variáveis de ambiente e segurança
- Integração com CI/CD via GitHub Actions

## 🏗️ Arquitetura no Azure

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   Azure Front Door  │───▶│  Static Web Apps    │───▶│   App Service       │
│   (CDN + WAF)       │    │   (Frontend React)  │    │  (Backend Django)   │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
                                       │                         │
                                       ▼                         ▼
                           ┌─────────────────────┐    ┌─────────────────────┐
                           │   Azure Storage     │    │  Azure Database     │
                           │   (Static Assets)   │    │  for PostgreSQL    │
                           └─────────────────────┘    └─────────────────────┘
```

## 🚀 Fase 1: Configuração Inicial do Azure

### 1.1 Pré-requisitos

```bash
# Instalar Azure CLI
winget install Microsoft.AzureCLI

# Fazer login
az login

# Definir subscription (se necessário)
az account set --subscription "sua-subscription-id"

# Verificar subscription ativa
az account show
```

### 1.2 Criar Resource Group

```bash
# Criar resource group
az group create \
  --name "rg-saas-identity" \
  --location "East US"

# Verificar criação
az group show --name "rg-saas-identity"
```

## 🗄️ Fase 2: Configuração do Banco de Dados

### 2.1 Criar Azure Database for PostgreSQL

```bash
# Criar servidor PostgreSQL
az postgres flexible-server create \
  --resource-group "rg-saas-identity" \
  --name "psql-saas-identity" \
  --location "East US" \
  --admin-user "saasadmin" \
  --admin-password "SuaSenhaSegura123!" \
  --sku-name "Standard_B1ms" \
  --tier "Burstable" \
  --storage-size 32 \
  --version 15

# Configurar firewall para permitir Azure services
az postgres flexible-server firewall-rule create \
  --resource-group "rg-saas-identity" \
  --name "psql-saas-identity" \
  --rule-name "AllowAzureServices" \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 0.0.0.0

# Criar banco de dados
az postgres flexible-server db create \
  --resource-group "rg-saas-identity" \
  --server-name "psql-saas-identity" \
  --database-name "saas_identity_db"
```

### 2.2 Configurar SSL e Segurança

```bash
# Configurar SSL como obrigatório
az postgres flexible-server parameter set \
  --resource-group "rg-saas-identity" \
  --server-name "psql-saas-identity" \
  --name require_secure_transport \
  --value on

# Obter string de conexão
az postgres flexible-server show-connection-string \
  --server-name "psql-saas-identity" \
  --database-name "saas_identity_db" \
  --admin-user "saasadmin" \
  --admin-password "SuaSenhaSegura123!"
```

## 🌐 Fase 3: Configuração do App Service (Backend)

### 3.1 Criar App Service Plan

```bash
# Criar App Service Plan
az appservice plan create \
  --resource-group "rg-saas-identity" \
  --name "asp-saas-identity" \
  --location "East US" \
  --sku "B1" \
  --is-linux

# Verificar criação
az appservice plan show \
  --resource-group "rg-saas-identity" \
  --name "asp-saas-identity"
```

### 3.2 Criar Web App

```bash
# Criar Web App
az webapp create \
  --resource-group "rg-saas-identity" \
  --plan "asp-saas-identity" \
  --name "app-saas-identity-backend" \
  --runtime "PYTHON:3.11" \
  --startup-file "startup.sh"

# Habilitar logs
az webapp log config \
  --resource-group "rg-saas-identity" \
  --name "app-saas-identity-backend" \
  --application-logging filesystem \
  --level information
```

### 3.3 Configurar Variáveis de Ambiente

```bash
# Configurar app settings
az webapp config appsettings set \
  --resource-group "rg-saas-identity" \
  --name "app-saas-identity-backend" \
  --settings \
    DEBUG="False" \
    SECRET_KEY="sua-chave-secreta-super-longa-e-segura" \
    ALLOWED_HOSTS="app-saas-identity-backend.azurewebsites.net,seudominio.com" \
    DATABASE_URL="postgresql://saasadmin:SuaSenhaSegura123!@psql-saas-identity.postgres.database.azure.com:5432/saas_identity_db?sslmode=require" \
    CSRF_TRUSTED_ORIGINS="https://app-saas-identity-backend.azurewebsites.net,https://seudominio.com" \
    CORS_ALLOWED_ORIGINS="https://app-saas-identity-frontend.azurewebsites.net,https://seudominio.com" \
    MICROSOFT_CLIENT_ID="seu-client-id" \
    MICROSOFT_CLIENT_SECRET="seu-client-secret" \
    MICROSOFT_TENANT_ID="seu-tenant-id" \
    WEBSITES_PORT="8000" \
    SCM_DO_BUILD_DURING_DEPLOYMENT="true"
```

### 3.4 Configurar Deployment

Crie o arquivo `startup.sh` na raiz do projeto:

```bash
#!/bin/bash

# Instalar dependências
pip install -r requirements.txt

# Executar migrações
python manage.py migrate

# Coletar arquivos estáticos
python manage.py collectstatic --noinput

# Iniciar Gunicorn
gunicorn --bind 0.0.0.0:8000 --workers 3 --timeout 600 saas_identity.wsgi:application
```

Crie o arquivo `requirements.txt` (se não existir):

```txt
Django==4.2.7
django-cors-headers==4.3.1
django-environ==0.11.2
psycopg2-binary==2.9.9
gunicorn==21.2.0
requests==2.31.0
msal==1.25.0
django-extensions==3.2.3
Pillow==10.1.0
whitenoise==6.6.0
```

### 3.5 Configurar Deployment via GitHub

```bash
# Configurar deployment do GitHub
az webapp deployment source config \
  --resource-group "rg-saas-identity" \
  --name "app-saas-identity-backend" \
  --repo-url "https://github.com/seu-usuario/saas-identity" \
  --branch "main" \
  --manual-integration

# Obter publish profile para GitHub Actions
az webapp deployment list-publishing-profiles \
  --resource-group "rg-saas-identity" \
  --name "app-saas-identity-backend" \
  --xml
```

## ⚛️ Fase 4: Configuração do Static Web Apps (Frontend)

### 4.1 Criar Static Web App

```bash
# Criar Static Web App
az staticwebapp create \
  --resource-group "rg-saas-identity" \
  --name "swa-saas-identity-frontend" \
  --location "East US2" \
  --source "https://github.com/seu-usuario/saas-identity" \
  --branch "main" \
  --app-location "/frontend" \
  --output-location "dist" \
  --login-with-github
```

### 4.2 Configurar Build do Frontend

Crie o arquivo `.github/workflows/azure-static-web-apps.yml`:

```yaml
name: Azure Static Web Apps CI/CD

on:
  push:
    branches:
      - main
  pull_request:
    types: [opened, synchronize, reopened, closed]
    branches:
      - main

jobs:
  build_and_deploy_job:
    if: github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'closed')
    runs-on: ubuntu-latest
    name: Build and Deploy Job
    steps:
      - uses: actions/checkout@v3
        with:
          submodules: true
      
      - name: Build And Deploy
        id: builddeploy
        uses: Azure/static-web-apps-deploy@v1
        with:
          azure_static_web_apps_api_token: ${{ secrets.AZURE_STATIC_WEB_APPS_API_TOKEN }}
          repo_token: ${{ secrets.GITHUB_TOKEN }}
          action: "upload"
          app_location: "/frontend"
          output_location: "dist"
        env:
          VITE_API_URL: https://app-saas-identity-backend.azurewebsites.net/api

  close_pull_request_job:
    if: github.event_name == 'pull_request' && github.event.action == 'closed'
    runs-on: ubuntu-latest
    name: Close Pull Request Job
    steps:
      - name: Close Pull Request
        id: closepullrequest
        uses: Azure/static-web-apps-deploy@v1
        with:
          azure_static_web_apps_api_token: ${{ secrets.AZURE_STATIC_WEB_APPS_API_TOKEN }}
          action: "close"
```

### 4.3 Configurar Roteamento do Frontend

Crie o arquivo `frontend/public/staticwebapp.config.json`:

```json
{
  "routes": [
    {
      "route": "/api/*",
      "allowedRoles": ["anonymous"]
    },
    {
      "route": "/*",
      "serve": "/index.html",
      "statusCode": 200
    }
  ],
  "navigationFallback": {
    "rewrite": "/index.html",
    "exclude": ["/api/*", "*.{css,scss,js,png,gif,ico,jpg,svg}"]
  },
  "mimeTypes": {
    ".json": "text/json"
  },
  "globalHeaders": {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block"
  },
  "responseOverrides": {
    "401": {
      "redirect": "/login",
      "statusCode": 302
    }
  }
}
```

## 🔒 Fase 5: Configuração de Segurança

### 5.1 Configurar HTTPS e Domínio Customizado

```bash
# Adicionar domínio customizado ao App Service
az webapp config hostname add \
  --resource-group "rg-saas-identity" \
  --webapp-name "app-saas-identity-backend" \
  --hostname "api.seudominio.com"

# Configurar SSL certificate
az webapp config ssl bind \
  --resource-group "rg-saas-identity" \
  --name "app-saas-identity-backend" \
  --certificate-thumbprint "thumbprint-do-certificado" \
  --ssl-type SNI

# Adicionar domínio customizado ao Static Web App
az staticwebapp hostname set \
  --resource-group "rg-saas-identity" \
  --name "swa-saas-identity-frontend" \
  --hostname "seudominio.com"
```

### 5.2 Configurar Azure Key Vault

```bash
# Criar Key Vault
az keyvault create \
  --resource-group "rg-saas-identity" \
  --name "kv-saas-identity" \
  --location "East US" \
  --sku standard

# Adicionar secrets
az keyvault secret set \
  --vault-name "kv-saas-identity" \
  --name "django-secret-key" \
  --value "sua-chave-secreta-super-longa"

az keyvault secret set \
  --vault-name "kv-saas-identity" \
  --name "database-url" \
  --value "postgresql://saasadmin:SuaSenhaSegura123!@psql-saas-identity.postgres.database.azure.com:5432/saas_identity_db?sslmode=require"

az keyvault secret set \
  --vault-name "kv-saas-identity" \
  --name "microsoft-client-secret" \
  --value "seu-client-secret"
```

### 5.3 Configurar Managed Identity

```bash
# Habilitar system-assigned managed identity
az webapp identity assign \
  --resource-group "rg-saas-identity" \
  --name "app-saas-identity-backend"

# Obter principal ID
PRINCIPAL_ID=$(az webapp identity show \
  --resource-group "rg-saas-identity" \
  --name "app-saas-identity-backend" \
  --query principalId --output tsv)

# Dar acesso ao Key Vault
az keyvault set-policy \
  --name "kv-saas-identity" \
  --object-id $PRINCIPAL_ID \
  --secret-permissions get list
```

## 📊 Fase 6: Monitoramento e Logs

### 6.1 Configurar Application Insights

```bash
# Criar Application Insights
az monitor app-insights component create \
  --resource-group "rg-saas-identity" \
  --app "ai-saas-identity" \
  --location "East US" \
  --kind web

# Obter instrumentation key
INSTRUMENTATION_KEY=$(az monitor app-insights component show \
  --resource-group "rg-saas-identity" \
  --app "ai-saas-identity" \
  --query instrumentationKey --output tsv)

# Configurar no App Service
az webapp config appsettings set \
  --resource-group "rg-saas-identity" \
  --name "app-saas-identity-backend" \
  --settings APPINSIGHTS_INSTRUMENTATIONKEY=$INSTRUMENTATION_KEY
```

### 6.2 Configurar Alertas

```bash
# Criar action group para notificações
az monitor action-group create \
  --resource-group "rg-saas-identity" \
  --name "ag-saas-alerts" \
  --short-name "saasalerts" \
  --email-receivers name="admin" email="admin@seudominio.com"

# Criar alerta para falhas HTTP
az monitor metrics alert create \
  --resource-group "rg-saas-identity" \
  --name "High HTTP 5xx Errors" \
  --scopes "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/rg-saas-identity/providers/Microsoft.Web/sites/app-saas-identity-backend" \
  --condition "avg Http5xx > 10" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --action "ag-saas-alerts"

# Criar alerta para uso de CPU
az monitor metrics alert create \
  --resource-group "rg-saas-identity" \
  --name "High CPU Usage" \
  --scopes "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/rg-saas-identity/providers/Microsoft.Web/sites/app-saas-identity-backend" \
  --condition "avg CpuPercentage > 80" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --action "ag-saas-alerts"
```

## 🚀 Fase 7: CI/CD com GitHub Actions

### 7.1 Workflow para Backend

Crie `.github/workflows/azure-backend-deploy.yml`:

```yaml
name: Deploy Backend to Azure App Service

on:
  push:
    branches:
      - main
    paths:
      - '**'
      - '!frontend/**'
  workflow_dispatch:

env:
  AZURE_WEBAPP_NAME: app-saas-identity-backend
  PYTHON_VERSION: '3.11'

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ env.PYTHON_VERSION }}
    
    - name: Create and start virtual environment
      run: |
        python -m venv venv
        source venv/bin/activate
    
    - name: Install dependencies
      run: |
        source venv/bin/activate
        pip install -r requirements.txt
    
    - name: Run tests
      env:
        DATABASE_URL: sqlite:///test.db
        SECRET_KEY: test-secret-key
        DEBUG: True
      run: |
        source venv/bin/activate
        python manage.py test
    
    - name: Upload artifact for deployment
      uses: actions/upload-artifact@v3
      with:
        name: python-app
        path: |
          .
          !venv/

  deploy:
    runs-on: ubuntu-latest
    needs: build
    environment:
      name: 'Production'
      url: ${{ steps.deploy-to-webapp.outputs.webapp-url }}
    
    steps:
    - name: Download artifact from build job
      uses: actions/download-artifact@v3
      with:
        name: python-app
        path: .
    
    - name: Deploy to Azure Web App
      uses: azure/webapps-deploy@v2
      id: deploy-to-webapp
      with:
        app-name: ${{ env.AZURE_WEBAPP_NAME }}
        publish-profile: ${{ secrets.AZURE_WEBAPP_PUBLISH_PROFILE }}
    
    - name: Health check
      run: |
        sleep 30
        curl -f https://${{ env.AZURE_WEBAPP_NAME }}.azurewebsites.net/api/health/ || exit 1
```

### 7.2 Configurar Secrets no GitHub

Adicione os seguintes secrets no GitHub:

```bash
# Obter publish profile
az webapp deployment list-publishing-profiles \
  --resource-group "rg-saas-identity" \
  --name "app-saas-identity-backend" \
  --xml > publish-profile.xml

# Adicionar como secret AZURE_WEBAPP_PUBLISH_PROFILE no GitHub
```

## 🔧 Fase 8: Configurações Avançadas

### 8.1 Configurar Auto-scaling

```bash
# Configurar auto-scaling
az monitor autoscale create \
  --resource-group "rg-saas-identity" \
  --resource "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/rg-saas-identity/providers/Microsoft.Web/serverfarms/asp-saas-identity" \
  --name "autoscale-saas-identity" \
  --min-count 1 \
  --max-count 3 \
  --count 1

# Adicionar regra de scale-out
az monitor autoscale rule create \
  --resource-group "rg-saas-identity" \
  --autoscale-name "autoscale-saas-identity" \
  --condition "CpuPercentage > 70 avg 5m" \
  --scale out 1

# Adicionar regra de scale-in
az monitor autoscale rule create \
  --resource-group "rg-saas-identity" \
  --autoscale-name "autoscale-saas-identity" \
  --condition "CpuPercentage < 30 avg 5m" \
  --scale in 1
```

### 8.2 Configurar Backup

```bash
# Configurar backup do banco de dados
az postgres flexible-server backup create \
  --resource-group "rg-saas-identity" \
  --name "psql-saas-identity" \
  --backup-name "backup-$(date +%Y%m%d)"

# Configurar backup automático do App Service
az webapp config backup create \
  --resource-group "rg-saas-identity" \
  --webapp-name "app-saas-identity-backend" \
  --container-url "https://storageaccount.blob.core.windows.net/backups" \
  --frequency 1 \
  --frequency-unit Day \
  --retain-one true \
  --retention 30
```

## 📋 Configuração de Ambiente Local para Azure

### Arquivo `.env.azure`

```env
# Azure Configuration
DEBUG=False
SECRET_KEY=@Microsoft.KeyVault(VaultName=kv-saas-identity;SecretName=django-secret-key)
ALLOWED_HOSTS=app-saas-identity-backend.azurewebsites.net,api.seudominio.com
DATABASE_URL=@Microsoft.KeyVault(VaultName=kv-saas-identity;SecretName=database-url)

# CORS and CSRF
CSRF_TRUSTED_ORIGINS=https://app-saas-identity-backend.azurewebsites.net,https://api.seudominio.com,https://seudominio.com
CORS_ALLOWED_ORIGINS=https://swa-saas-identity-frontend.azurestaticapps.net,https://seudominio.com

# Microsoft Graph
MICROSOFT_CLIENT_ID=seu-client-id
MICROSOFT_CLIENT_SECRET=@Microsoft.KeyVault(VaultName=kv-saas-identity;SecretName=microsoft-client-secret)
MICROSOFT_TENANT_ID=seu-tenant-id

# Application Insights
APPINSIGHTS_INSTRUMENTATIONKEY=sua-instrumentation-key

# Azure specific
WEBSITES_PORT=8000
SCM_DO_BUILD_DURING_DEPLOYMENT=true
WEBSITE_HTTPLOGGING_RETENTION_DAYS=3
```

## ✅ Checklist de Deployment

### Recursos Azure
- [ ] Resource Group criado
- [ ] PostgreSQL Flexible Server configurado
- [ ] App Service Plan criado
- [ ] Web App configurada
- [ ] Static Web App configurada
- [ ] Key Vault configurado
- [ ] Application Insights configurado

### Configurações
- [ ] Variáveis de ambiente configuradas
- [ ] Managed Identity configurada
- [ ] SSL/TLS configurado
- [ ] Domínio customizado configurado
- [ ] Auto-scaling configurado
- [ ] Backup configurado

### CI/CD
- [ ] GitHub Actions configurado
- [ ] Secrets configurados
- [ ] Deploy automático funcionando
- [ ] Health checks funcionando

### Monitoramento
- [ ] Application Insights configurado
- [ ] Alertas configurados
- [ ] Logs configurados
- [ ] Métricas configuradas

## 💰 Estimativa de Custos (USD/mês)

| Recurso | SKU | Custo Estimado |
|---------|-----|----------------|
| App Service Plan | B1 | $13.14 |
| PostgreSQL Flexible Server | Standard_B1ms | $12.41 |
| Static Web Apps | Standard | $9.00 |
| Application Insights | Pay-as-you-go | $2-5 |
| Key Vault | Standard | $0.03 |
| **Total** | | **~$36-40** |

*Custos podem variar baseado no uso e região*

## 🚨 Troubleshooting

### Problemas Comuns

1. **App Service não inicia**
   ```bash
   # Verificar logs
   az webapp log tail --resource-group "rg-saas-identity" --name "app-saas-identity-backend"
   
   # Verificar configurações
   az webapp config show --resource-group "rg-saas-identity" --name "app-saas-identity-backend"
   ```

2. **Erro de conexão com banco**
   ```bash
   # Testar conectividade
   az postgres flexible-server connect --name "psql-saas-identity" --admin-user "saasadmin" --database-name "saas_identity_db"
   ```

3. **Static Web App não carrega**
   ```bash
   # Verificar build
   az staticwebapp show --resource-group "rg-saas-identity" --name "swa-saas-identity-frontend"
   ```

4. **Problemas de CORS**
   - Verificar CORS_ALLOWED_ORIGINS nas configurações do App Service
   - Verificar se o domínio do frontend está correto

Este guia fornece uma base completa para deployment no Azure App Service. Adapte conforme suas necessidades específicas!