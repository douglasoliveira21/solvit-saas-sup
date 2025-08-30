# Guia de CI/CD - GitHub Actions

## 📋 Visão Geral

Este guia configura um pipeline completo de CI/CD usando GitHub Actions para automatizar:
- Testes do backend (Python/Django)
- Testes do frontend (React/TypeScript)
- Build e deploy automático para staging/produção
- Deploy para VPS Ubuntu ou Azure App Service

## 🏗️ Estrutura do Pipeline

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Pull Request  │───▶│   CI Pipeline   │───▶│  Deploy Stage   │
│                 │    │                 │    │                 │
│ • Lint          │    │ • Tests         │    │ • Staging       │
│ • Type Check    │    │ • Build         │    │ • Production    │
│ • Security      │    │ • Security Scan │    │ • Rollback      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📁 Estrutura de Arquivos

```
.github/
├── workflows/
│   ├── ci.yml                 # Pipeline principal
│   ├── deploy-staging.yml     # Deploy para staging
│   ├── deploy-production.yml  # Deploy para produção
│   └── security.yml          # Verificações de segurança
├── scripts/
│   ├── deploy.sh             # Script de deploy
│   ├── health-check.sh       # Verificação de saúde
│   └── rollback.sh           # Script de rollback
└── environments/
    ├── staging.env           # Variáveis de staging
    └── production.env        # Variáveis de produção
```

## 🔧 Configuração Inicial

### 1. Secrets do GitHub

Configure os seguintes secrets no GitHub (Settings → Secrets and variables → Actions):

#### Para VPS Ubuntu:
```
VPS_HOST=seu-servidor-ip
VPS_USER=saasapp
VPS_SSH_KEY=sua-chave-ssh-privada
VPS_PORT=22
```

#### Para Azure App Service:
```
AZURE_WEBAPP_NAME=seu-app-name
AZURE_WEBAPP_PUBLISH_PROFILE=seu-publish-profile
AZURE_SUBSCRIPTION_ID=sua-subscription-id
```

#### Banco de Dados e Aplicação:
```
DATABASE_URL=postgresql://user:pass@host:port/db
SECRET_KEY=sua-chave-secreta-django
MICROSOFT_CLIENT_ID=seu-client-id
MICROSOFT_CLIENT_SECRET=seu-client-secret
MICROSOFT_TENANT_ID=seu-tenant-id
```

#### Notificações (opcional):
```
SLACK_WEBHOOK_URL=sua-webhook-url
DISCORD_WEBHOOK_URL=sua-webhook-url
```

## 🚀 Pipeline Principal (CI)

Crie o arquivo `.github/workflows/ci.yml`:

```yaml
name: CI Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

env:
  PYTHON_VERSION: '3.11'
  NODE_VERSION: '18'

jobs:
  # ===== BACKEND TESTS =====
  backend-tests:
    name: Backend Tests
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ env.PYTHON_VERSION }}
        cache: 'pip'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install pytest pytest-django pytest-cov flake8 black isort safety bandit
    
    - name: Lint with flake8
      run: |
        flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
        flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
    
    - name: Check code formatting
      run: |
        black --check .
        isort --check-only .
    
    - name: Security check with bandit
      run: bandit -r . -x tests/
    
    - name: Check for vulnerabilities
      run: safety check
    
    - name: Run tests
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/test_db
        SECRET_KEY: test-secret-key
        DEBUG: True
      run: |
        python manage.py migrate
        pytest --cov=. --cov-report=xml --cov-report=html
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        flags: backend
        name: backend-coverage

  # ===== FRONTEND TESTS =====
  frontend-tests:
    name: Frontend Tests
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Set up Node.js
      uses: actions/setup-node@v4
      with:
        node-version: ${{ env.NODE_VERSION }}
        cache: 'npm'
        cache-dependency-path: frontend/package-lock.json
    
    - name: Install dependencies
      working-directory: ./frontend
      run: npm ci
    
    - name: Lint code
      working-directory: ./frontend
      run: npm run lint
    
    - name: Type check
      working-directory: ./frontend
      run: npm run type-check
    
    - name: Run tests
      working-directory: ./frontend
      run: npm run test:coverage
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./frontend/coverage/lcov.info
        flags: frontend
        name: frontend-coverage
    
    - name: Build application
      working-directory: ./frontend
      env:
        VITE_API_URL: ${{ github.ref == 'refs/heads/main' && 'https://api.seudominio.com' || 'https://staging-api.seudominio.com' }}
      run: npm run build
    
    - name: Upload build artifacts
      uses: actions/upload-artifact@v4
      with:
        name: frontend-build
        path: frontend/dist/
        retention-days: 7

  # ===== SECURITY SCAN =====
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    needs: [backend-tests, frontend-tests]
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

  # ===== BUILD DOCKER IMAGES =====
  build-images:
    name: Build Docker Images
    runs-on: ubuntu-latest
    needs: [backend-tests, frontend-tests]
    if: github.ref == 'refs/heads/main' || github.ref == 'refs/heads/develop'
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3
    
    - name: Login to Docker Hub
      uses: docker/login-action@v3
      with:
        username: ${{ secrets.DOCKER_USERNAME }}
        password: ${{ secrets.DOCKER_PASSWORD }}
    
    - name: Build and push backend image
      uses: docker/build-push-action@v5
      with:
        context: .
        file: ./Dockerfile.backend
        push: true
        tags: |
          ${{ secrets.DOCKER_USERNAME }}/saas-identity-backend:${{ github.sha }}
          ${{ secrets.DOCKER_USERNAME }}/saas-identity-backend:${{ github.ref == 'refs/heads/main' && 'latest' || 'develop' }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
    
    - name: Build and push frontend image
      uses: docker/build-push-action@v5
      with:
        context: ./frontend
        file: ./frontend/Dockerfile
        push: true
        tags: |
          ${{ secrets.DOCKER_USERNAME }}/saas-identity-frontend:${{ github.sha }}
          ${{ secrets.DOCKER_USERNAME }}/saas-identity-frontend:${{ github.ref == 'refs/heads/main' && 'latest' || 'develop' }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
```

## 🎯 Deploy para Staging

Crie o arquivo `.github/workflows/deploy-staging.yml`:

```yaml
name: Deploy to Staging

on:
  push:
    branches: [ develop ]
  workflow_dispatch:

env:
  ENVIRONMENT: staging

jobs:
  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    environment: staging
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Setup SSH
      uses: webfactory/ssh-agent@v0.8.0
      with:
        ssh-private-key: ${{ secrets.STAGING_SSH_KEY }}
    
    - name: Deploy to staging server
      run: |
        ssh -o StrictHostKeyChecking=no ${{ secrets.STAGING_USER }}@${{ secrets.STAGING_HOST }} << 'EOF'
          set -e
          
          # Navegar para diretório da aplicação
          cd /home/saasapp/saas-identity
          
          # Backup atual
          sudo systemctl stop saas-identity.service
          cp -r . ../backup-$(date +%Y%m%d_%H%M%S)
          
          # Atualizar código
          git fetch origin
          git checkout develop
          git pull origin develop
          
          # Atualizar backend
          source venv/bin/activate
          pip install -r requirements.txt
          python manage.py migrate
          python manage.py collectstatic --noinput
          
          # Atualizar frontend
          cd frontend
          npm ci
          npm run build
          cd ..
          
          # Reiniciar serviços
          sudo systemctl start saas-identity.service
          sudo systemctl reload nginx
          
          # Verificar saúde
          sleep 10
          curl -f http://localhost:8000/api/health/ || exit 1
        EOF
    
    - name: Health check
      run: |
        sleep 30
        curl -f https://staging.seudominio.com/api/health/ || exit 1
    
    - name: Notify Slack
      if: always()
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        channel: '#deployments'
        webhook_url: ${{ secrets.SLACK_WEBHOOK_URL }}
        fields: repo,message,commit,author,action,eventName,ref,workflow
```

## 🚀 Deploy para Produção

Crie o arquivo `.github/workflows/deploy-production.yml`:

```yaml
name: Deploy to Production

on:
  push:
    branches: [ main ]
  workflow_dispatch:
    inputs:
      confirm_deploy:
        description: 'Type "deploy" to confirm production deployment'
        required: true
        default: ''

env:
  ENVIRONMENT: production

jobs:
  confirm-deployment:
    name: Confirm Deployment
    runs-on: ubuntu-latest
    if: github.event_name == 'workflow_dispatch'
    
    steps:
    - name: Validate confirmation
      run: |
        if [ "${{ github.event.inputs.confirm_deploy }}" != "deploy" ]; then
          echo "Deployment not confirmed. Exiting."
          exit 1
        fi

  deploy-production:
    name: Deploy to Production
    runs-on: ubuntu-latest
    environment: production
    needs: [confirm-deployment]
    if: always() && (needs.confirm-deployment.result == 'success' || github.event_name == 'push')
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Setup SSH
      uses: webfactory/ssh-agent@v0.8.0
      with:
        ssh-private-key: ${{ secrets.VPS_SSH_KEY }}
    
    - name: Create deployment backup
      run: |
        ssh -o StrictHostKeyChecking=no ${{ secrets.VPS_USER }}@${{ secrets.VPS_HOST }} << 'EOF'
          cd /home/saasapp
          sudo systemctl stop saas-identity.service
          tar -czf backup-$(date +%Y%m%d_%H%M%S).tar.gz saas-identity/
          ls -la backup-*.tar.gz | tail -5
        EOF
    
    - name: Deploy to production
      run: |
        ssh -o StrictHostKeyChecking=no ${{ secrets.VPS_USER }}@${{ secrets.VPS_HOST }} << 'EOF'
          set -e
          
          cd /home/saasapp/saas-identity
          
          # Atualizar código
          git fetch origin
          git checkout main
          git pull origin main
          
          # Atualizar backend
          source venv/bin/activate
          pip install -r requirements.txt
          
          # Executar migrações com backup
          python manage.py migrate --check
          python manage.py migrate
          
          # Coletar arquivos estáticos
          python manage.py collectstatic --noinput
          
          # Atualizar frontend
          cd frontend
          npm ci
          VITE_API_URL=https://api.seudominio.com npm run build
          cd ..
          
          # Reiniciar serviços
          sudo systemctl start saas-identity.service
          sudo systemctl reload nginx
          
          # Aguardar inicialização
          sleep 15
        EOF
    
    - name: Health check
      run: |
        for i in {1..5}; do
          if curl -f https://seudominio.com/api/health/; then
            echo "Health check passed"
            exit 0
          fi
          echo "Health check failed, attempt $i/5"
          sleep 10
        done
        exit 1
    
    - name: Rollback on failure
      if: failure()
      run: |
        ssh -o StrictHostKeyChecking=no ${{ secrets.VPS_USER }}@${{ secrets.VPS_HOST }} << 'EOF'
          cd /home/saasapp
          sudo systemctl stop saas-identity.service
          
          # Restaurar backup mais recente
          LATEST_BACKUP=$(ls -t backup-*.tar.gz | head -1)
          if [ -n "$LATEST_BACKUP" ]; then
            rm -rf saas-identity
            tar -xzf $LATEST_BACKUP
            sudo systemctl start saas-identity.service
            echo "Rollback completed using $LATEST_BACKUP"
          else
            echo "No backup found for rollback"
            exit 1
          fi
        EOF
    
    - name: Notify team
      if: always()
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        channel: '#production'
        webhook_url: ${{ secrets.SLACK_WEBHOOK_URL }}
        fields: repo,message,commit,author,action,eventName,ref,workflow
        text: |
          Production deployment ${{ job.status }}!
          Commit: ${{ github.sha }}
          Author: ${{ github.actor }}
```

## 🐳 Dockerfiles

### Backend Dockerfile

Crie `Dockerfile.backend`:

```dockerfile
FROM python:3.11-slim

# Instalar dependências do sistema
RUN apt-get update && apt-get install -y \
    postgresql-client \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Criar usuário não-root
RUN useradd --create-home --shell /bin/bash app

# Definir diretório de trabalho
WORKDIR /app

# Copiar requirements e instalar dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código da aplicação
COPY . .

# Mudar ownership para usuário app
RUN chown -R app:app /app
USER app

# Coletar arquivos estáticos
RUN python manage.py collectstatic --noinput

# Expor porta
EXPOSE 8000

# Comando padrão
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "saas_identity.wsgi:application"]
```

### Frontend Dockerfile

Crie `frontend/Dockerfile`:

```dockerfile
FROM node:18-alpine as builder

WORKDIR /app

# Copiar package files
COPY package*.json ./
RUN npm ci

# Copiar código e build
COPY . .
RUN npm run build

# Estágio de produção
FROM nginx:alpine

# Copiar build
COPY --from=builder /app/dist /usr/share/nginx/html

# Copiar configuração do nginx
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

## 📊 Monitoramento e Alertas

### Health Check Endpoint

Adicione ao Django (`views.py`):

```python
from django.http import JsonResponse
from django.db import connection
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
import time

@csrf_exempt
@require_http_methods(["GET"])
def health_check(request):
    """Endpoint de verificação de saúde da aplicação"""
    start_time = time.time()
    
    try:
        # Verificar conexão com banco
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
    
    response_time = time.time() - start_time
    
    status = {
        "status": "healthy" if db_status == "healthy" else "unhealthy",
        "timestamp": time.time(),
        "response_time": response_time,
        "database": db_status,
        "version": "1.0.0"
    }
    
    status_code = 200 if status["status"] == "healthy" else 503
    return JsonResponse(status, status=status_code)
```

### Script de Monitoramento

Crie `.github/scripts/health-check.sh`:

```bash
#!/bin/bash

URL="$1"
MAX_ATTEMPTS=5
SLEEP_TIME=10

echo "Checking health of $URL"

for i in $(seq 1 $MAX_ATTEMPTS); do
    echo "Attempt $i/$MAX_ATTEMPTS"
    
    if curl -f -s "$URL/api/health/" > /dev/null; then
        echo "✅ Health check passed"
        exit 0
    fi
    
    echo "❌ Health check failed"
    
    if [ $i -lt $MAX_ATTEMPTS ]; then
        echo "Waiting ${SLEEP_TIME}s before retry..."
        sleep $SLEEP_TIME
    fi
done

echo "🚨 Health check failed after $MAX_ATTEMPTS attempts"
exit 1
```

## 🔧 Scripts Auxiliares

### Deploy Script

Crie `.github/scripts/deploy.sh`:

```bash
#!/bin/bash

set -e

ENVIRONMENT="$1"
BRANCH="$2"

if [ -z "$ENVIRONMENT" ] || [ -z "$BRANCH" ]; then
    echo "Usage: $0 <environment> <branch>"
    exit 1
fi

echo "🚀 Starting deployment to $ENVIRONMENT from branch $BRANCH"

# Backup atual
echo "📦 Creating backup..."
sudo systemctl stop saas-identity.service
cp -r . ../backup-$(date +%Y%m%d_%H%M%S)

# Atualizar código
echo "📥 Updating code..."
git fetch origin
git checkout $BRANCH
git pull origin $BRANCH

# Atualizar backend
echo "🐍 Updating backend..."
source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py collectstatic --noinput

# Atualizar frontend
echo "⚛️ Updating frontend..."
cd frontend
npm ci

if [ "$ENVIRONMENT" = "production" ]; then
    VITE_API_URL=https://api.seudominio.com npm run build
else
    VITE_API_URL=https://staging-api.seudominio.com npm run build
fi

cd ..

# Reiniciar serviços
echo "🔄 Restarting services..."
sudo systemctl start saas-identity.service
sudo systemctl reload nginx

echo "✅ Deployment completed successfully!"
```

### Rollback Script

Crie `.github/scripts/rollback.sh`:

```bash
#!/bin/bash

set -e

BACKUP_DIR="$1"

if [ -z "$BACKUP_DIR" ]; then
    echo "Available backups:"
    ls -la ../backup-* 2>/dev/null || echo "No backups found"
    echo "Usage: $0 <backup_directory>"
    exit 1
fi

if [ ! -d "../$BACKUP_DIR" ]; then
    echo "Backup directory ../$BACKUP_DIR not found"
    exit 1
fi

echo "🔄 Rolling back to $BACKUP_DIR"

# Parar serviços
sudo systemctl stop saas-identity.service

# Backup atual antes do rollback
cp -r . ../pre-rollback-$(date +%Y%m%d_%H%M%S)

# Restaurar backup
rm -rf ./*
cp -r ../$BACKUP_DIR/* .

# Reiniciar serviços
sudo systemctl start saas-identity.service
sudo systemctl reload nginx

echo "✅ Rollback completed successfully!"
```

## 📈 Métricas e Alertas

### Configuração de Alertas

Crie `.github/workflows/alerts.yml`:

```yaml
name: Health Monitoring

on:
  schedule:
    - cron: '*/5 * * * *'  # A cada 5 minutos
  workflow_dispatch:

jobs:
  health-check:
    name: Health Check
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        environment:
          - name: production
            url: https://seudominio.com
          - name: staging
            url: https://staging.seudominio.com
    
    steps:
    - name: Check ${{ matrix.environment.name }}
      run: |
        if ! curl -f -s "${{ matrix.environment.url }}/api/health/"; then
          echo "🚨 ${{ matrix.environment.name }} is down!"
          exit 1
        fi
        echo "✅ ${{ matrix.environment.name }} is healthy"
    
    - name: Alert on failure
      if: failure()
      uses: 8398a7/action-slack@v3
      with:
        status: failure
        channel: '#alerts'
        webhook_url: ${{ secrets.SLACK_WEBHOOK_URL }}
        text: |
          🚨 ALERT: ${{ matrix.environment.name }} health check failed!
          URL: ${{ matrix.environment.url }}
          Time: $(date)
```

## ✅ Checklist de Configuração

### GitHub Secrets
- [ ] `VPS_HOST` - IP do servidor
- [ ] `VPS_USER` - Usuário SSH
- [ ] `VPS_SSH_KEY` - Chave SSH privada
- [ ] `DATABASE_URL` - URL do banco de dados
- [ ] `SECRET_KEY` - Chave secreta do Django
- [ ] `DOCKER_USERNAME` - Usuário Docker Hub
- [ ] `DOCKER_PASSWORD` - Senha Docker Hub
- [ ] `SLACK_WEBHOOK_URL` - Webhook do Slack

### Environments
- [ ] `staging` - Ambiente de staging
- [ ] `production` - Ambiente de produção

### Branch Protection
- [ ] Require pull request reviews
- [ ] Require status checks to pass
- [ ] Require branches to be up to date
- [ ] Include administrators

### Workflows
- [ ] CI pipeline funcionando
- [ ] Deploy staging funcionando
- [ ] Deploy production funcionando
- [ ] Health checks funcionando
- [ ] Alertas configurados

## 🚨 Troubleshooting

### Problemas Comuns

1. **SSH Connection Failed**
   ```bash
   # Verificar chave SSH
   ssh-keygen -l -f ~/.ssh/id_rsa.pub
   
   # Testar conexão
   ssh -v user@host
   ```

2. **Deploy Failed**
   ```bash
   # Verificar logs
   sudo journalctl -u saas-identity.service -f
   
   # Verificar status
   sudo systemctl status saas-identity.service
   ```

3. **Health Check Failed**
   ```bash
   # Testar localmente
   curl -v http://localhost:8000/api/health/
   
   # Verificar logs do Django
   tail -f logs/gunicorn_error.log
   ```

4. **Frontend Build Failed**
   ```bash
   # Limpar cache
   npm cache clean --force
   rm -rf node_modules package-lock.json
   npm install
   ```

Este guia fornece uma base sólida para CI/CD com GitHub Actions. Adapte conforme suas necessidades específicas!