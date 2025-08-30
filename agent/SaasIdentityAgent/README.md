# SaaS Identity Management Agent

A robust, cross-platform agent for synchronizing Active Directory users and groups with the SaaS Identity Management platform.

## Overview

The SaaS Identity Management Agent is a background service that provides seamless integration between on-premises Active Directory and cloud-based identity management systems. It enables organizations to maintain centralized user and group management while leveraging modern SaaS identity solutions.

## Key Features

### 🔄 **Multi-Platform Support**
- **Windows Service**: Native Windows service installation
- **Linux Systemd**: Systemd service for Linux distributions  
- **Docker Container**: Containerized deployment for any platform
- **Cloud Ready**: Supports deployment in cloud environments

### 🛡️ **Enterprise Security**
- Secure LDAPS connections to Active Directory
- API key-based authentication with the SaaS platform
- Service account with least-privilege access
- Encrypted configuration storage options

### 🔄 **Bidirectional Synchronization**
- Real-time user and group synchronization from Active Directory
- Configurable sync intervals and retry mechanisms
- Delta synchronization for optimal performance
- Conflict resolution and data validation

### 📊 **Comprehensive Monitoring**
- Structured logging with Serilog
- Health checks and heartbeat monitoring
- Performance metrics and sync statistics
- Integration with Windows Event Log and systemd journal

### ⚙️ **Flexible Configuration**
- JSON-based configuration with environment variable support
- Organizational Unit (OU) filtering and exclusion
- Customizable sync policies and user mapping
- Environment-specific configuration profiles

## Prerequisites

### Common Requirements

- **.NET 6 Runtime**: Required for all deployment methods
- **Network Access**: 
  - Outbound HTTPS access to the SaaS backend API
  - LDAP/LDAPS access to Active Directory domain controllers
- **Service Account**: Dedicated AD service account with read permissions
- **API Key**: Generated from the SaaS platform admin panel

### Platform-Specific Requirements

#### Windows
- Windows Server 2016+ or Windows 10+
- PowerShell 5.0+
- Administrator privileges for installation

#### Linux
- Modern Linux distribution with systemd
- curl and ldap-utils packages
- Root privileges for installation

#### Docker
- Docker Engine 20.10+
- Docker Compose 2.0+ (optional but recommended)

### Active Directory Requirements
- Service account with permissions for:
  - Read access to user and group objects
  - Read access to specified Organizational Units
  - No write permissions required (read-only synchronization)
- Network connectivity to domain controllers
- LDAP/LDAPS protocol access (ports 389/636)

## Quick Start

### Windows Installation

```powershell
# Clone the repository
git clone https://github.com/yourcompany/saas-identity-agent.git
cd saas-identity-agent

# Quick deployment with configuration
.\Scripts\deploy-agent.ps1 `
    -TenantId "your-tenant-id" `
    -BackendUrl "https://api.yourcompany.com" `
    -ApiKey "your-api-key" `
    -DomainName "company.local" `
    -ServiceAccountUsername "COMPANY\svc-saas" `
    -ServiceAccountPassword "SecurePassword123!"
```

### Linux Installation

```bash
# Clone the repository
git clone https://github.com/yourcompany/saas-identity-agent.git
cd saas-identity-agent

# Quick deployment with configuration
sudo ./Scripts/deploy-agent-linux.sh \
    --tenant-id "your-tenant-id" \
    --backend-url "https://api.yourcompany.com" \
    --api-key "your-api-key" \
    --domain-name "company.local" \
    --service-account "svc-saas" \
    --service-password "SecurePassword123!"
```

### Docker Installation

```bash
# Clone the repository
git clone https://github.com/yourcompany/saas-identity-agent.git
cd saas-identity-agent

# Configure environment
cp .env.example .env
vim .env  # Edit configuration

# Deploy with Docker Compose
docker-compose up -d
```

## Configuration

### Basic Configuration

The agent uses a JSON configuration file (`appsettings.json`) with the following structure:

```json
{
  "Agent": {
    "AgentId": "seu-agent-id-unico",
    "TenantId": "seu-tenant-id",
    "Version": "1.0.0"
  },
  "Backend": {
    "BaseUrl": "https://seu-backend.com",
    "ApiKey": "sua-api-key-secreta"
  },
  "ActiveDirectory": {
    "Domain": "seu-dominio.local",
    "ServiceAccountUsername": "DOMINIO\\conta-servico",
    "ServiceAccountPassword": "senha-da-conta",
    "DomainController": "dc01.seu-dominio.local"
  }
}
```

### 3. Instalação do Serviço

```powershell
# Executar como Administrador
.\Scripts\install-agent.ps1
```

Ou com parâmetros personalizados:

```powershell
.\Scripts\install-agent.ps1 -InstallPath "C:\CustomPath\Agent" -ServiceAccount "DOMINIO\ContaServico"
```

### 4. Verificação

```powershell
# Verificar status do serviço
Get-Service -Name "SaasIdentityAgent"

# Verificar logs
Get-EventLog -LogName Application -Source "SaasIdentityAgent" -Newest 10
```

## Configuração Detalhada

### Configurações do Agente

```json
{
  "Agent": {
    "AgentId": "agent-001",
    "TenantId": "tenant-123",
    "Version": "1.0.0",
    "HeartbeatIntervalMinutes": 5,
    "SyncIntervalMinutes": 60,
    "CommandCheckIntervalMinutes": 2,
    "MaxRetryAttempts": 3,
    "RetryDelaySeconds": 30,
    "LogLevel": "Information"
  }
}
```

### Configurações do Backend

```json
{
  "Backend": {
    "BaseUrl": "https://api.exemplo.com",
    "ApiKey": "sua-api-key",
    "TimeoutSeconds": 30,
    "ValidateSslCertificate": true,
    "ProxyUrl": "",
    "ProxyUsername": "",
    "ProxyPassword": ""
  }
}
```

### Configurações do Active Directory

```json
{
  "ActiveDirectory": {
    "Domain": "exemplo.local",
    "ServiceAccountUsername": "EXEMPLO\\svc-agent",
    "ServiceAccountPassword": "senha123",
    "DomainController": "dc01.exemplo.local",
    "DefaultUserContainer": "CN=Users,DC=exemplo,DC=local",
    "DefaultGroupContainer": "CN=Users,DC=exemplo,DC=local",
    "UseSecureConnection": true,
    "LdapPort": 636,
    "ConnectionTimeoutSeconds": 30,
    "SyncOUs": [
      "OU=Usuarios,DC=exemplo,DC=local",
      "OU=Grupos,DC=exemplo,DC=local"
    ],
    "ExcludeOUs": [
      "OU=ServiceAccounts,DC=exemplo,DC=local"
    ]
  }
}
```

## Operação

### Comandos Suportados

O agente processa os seguintes comandos do backend:

1. **CreateUser**: Criar usuário no AD
2. **UpdateUser**: Atualizar usuário existente
3. **DisableUser**: Desabilitar usuário
4. **EnableUser**: Habilitar usuário
5. **DeleteUser**: Excluir usuário
6. **AddUserToGroup**: Adicionar usuário a grupo
7. **CreateGroup**: Criar grupo
8. **SyncNow**: Forçar sincronização imediata
9. **TestConnection**: Testar conexão com AD
10. **ExecutePowerShell**: Executar script PowerShell

### Sincronização

O agente sincroniza automaticamente:
- **Usuários**: Informações básicas, grupos, status
- **Grupos**: Membros, descrição, tipo
- **Frequência**: Configurável (padrão: 60 minutos)

### Logs

Logs são gravados em:
- **Arquivo**: `C:\ProgramData\SaasIdentityAgent\logs\agent-.log`
- **Event Log**: Application Log (Source: SaasIdentityAgent)
- **Console**: Durante desenvolvimento

Níveis de log:
- **Verbose**: Informações detalhadas
- **Debug**: Informações de depuração
- **Information**: Operações normais
- **Warning**: Avisos
- **Error**: Erros
- **Fatal**: Erros críticos

## Monitoramento

### Health Checks

O agente envia heartbeats regulares incluindo:
- Status do sistema
- Conectividade com AD
- Estatísticas de sincronização
- Comandos pendentes

### Métricas

- Tempo de resposta do AD
- Número de usuários/grupos sincronizados
- Taxa de sucesso de comandos
- Uso de memória e CPU

## Solução de Problemas

### Problemas Comuns

#### Serviço não inicia
```powershell
# Verificar logs do Event Viewer
Get-EventLog -LogName Application -Source "SaasIdentityAgent" -EntryType Error

# Verificar configuração
Test-Json -Path "C:\Program Files\SaasIdentityAgent\appsettings.json"
```

#### Erro de conectividade com AD
```powershell
# Testar conectividade
Test-NetConnection -ComputerName "dc01.exemplo.local" -Port 389
Test-NetConnection -ComputerName "dc01.exemplo.local" -Port 636

# Verificar credenciais
$cred = Get-Credential
Get-ADUser -Filter * -Credential $cred -Server "dc01.exemplo.local"
```

#### Erro de comunicação com backend
```powershell
# Testar conectividade HTTPS
Test-NetConnection -ComputerName "api.exemplo.com" -Port 443

# Testar API
$headers = @{ "X-API-Key" = "sua-api-key" }
Invoke-RestMethod -Uri "https://api.exemplo.com/health" -Headers $headers
```

### Logs de Diagnóstico

Para habilitar logs detalhados, altere em `appsettings.json`:

```json
{
  "Serilog": {
    "MinimumLevel": {
      "Default": "Debug",
      "Override": {
        "Microsoft": "Warning",
        "System": "Warning"
      }
    }
  }
}
```

## Desinstalação

```powershell
# Desinstalar serviço (manter arquivos)
.\Scripts\uninstall-agent.ps1

# Desinstalar completamente
.\Scripts\uninstall-agent.ps1 -RemoveFiles -RemoveLogs
```

## Segurança

### Boas Práticas

1. **Conta de Serviço**:
   - Use conta dedicada com permissões mínimas
   - Não use conta de administrador de domínio
   - Configure expiração de senha apropriada

2. **API Key**:
   - Mantenha a API Key segura
   - Rotacione regularmente
   - Use HTTPS sempre

3. **Configuração**:
   - Proteja o arquivo `appsettings.json`
   - Use criptografia para senhas sensíveis
   - Monitore logs de acesso

4. **Rede**:
   - Use firewall para restringir acesso
   - Configure proxy se necessário
   - Monitore tráfego de rede

### Permissões Necessárias

#### Active Directory
- Read all user information
- Read all group information
- Create user objects
- Reset user passwords
- Enable/disable user accounts
- Modify group membership

#### Sistema
- Log on as a service
- Access to installation directory
- Write to log directory
- Network access

## Desenvolvimento

### Estrutura do Projeto

```
SaasIdentityAgent/
├── Models/
│   ├── Configuration.cs
│   └── ApiModels.cs
├── Services/
│   ├── BackendApiService.cs
│   ├── ActiveDirectoryService.cs
│   ├── HeartbeatService.cs
│   ├── SynchronizationService.cs
│   └── CommandProcessorService.cs
├── Scripts/
│   ├── install-agent.ps1
│   └── uninstall-agent.ps1
├── Program.cs
├── appsettings.json
└── SaasIdentityAgent.csproj
```

### Build

```bash
# Restaurar dependências
dotnet restore

# Build
dotnet build --configuration Release

# Publicar
dotnet publish --configuration Release --output ./publish
```

### Testes

```bash
# Executar testes
dotnet test

# Executar com cobertura
dotnet test --collect:"XPlat Code Coverage"
```

## Suporte

Para suporte técnico:
- Consulte os logs do agente
- Verifique a documentação da API
- Entre em contato com o suporte técnico

## Changelog

### v1.0.0
- Versão inicial
- Sincronização básica de usuários e grupos
- Processamento de comandos
- Logging com Serilog
- Configuração via JSON