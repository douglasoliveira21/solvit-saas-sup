# SaaS Identity Management Agent

O SaaS Identity Management Agent é um serviço Windows desenvolvido em C# que atua como ponte entre o Active Directory local e o backend SaaS, permitindo sincronização de usuários e grupos, além de execução de comandos remotos.

## Características

- **Serviço Windows**: Executa em segundo plano como serviço do Windows
- **Comunicação Segura**: HTTPS com autenticação via API Key
- **Integração AD**: Sincronização bidirecional com Active Directory
- **Processamento de Comandos**: Executa comandos remotos do backend
- **Logging Avançado**: Logs estruturados com Serilog
- **Configuração Flexível**: Configuração via JSON com suporte a ambientes
- **Retry Logic**: Lógica de retry com backoff exponencial
- **Monitoramento**: Heartbeat e health checks

## Pré-requisitos

### Sistema
- Windows Server 2016+ ou Windows 10+
- .NET 6.0 Runtime
- PowerShell 5.1+
- Privilégios de Administrador para instalação

### Active Directory
- Conta de serviço com permissões para:
  - Leitura de usuários e grupos
  - Criação/modificação de usuários
  - Adição de usuários a grupos
  - Acesso às OUs configuradas

### Rede
- Conectividade HTTPS com o backend SaaS
- Portas de saída: 443 (HTTPS)
- Resolução DNS para o domínio do backend

## Instalação

### 1. Preparação

```powershell
# Baixar e extrair o agente
# Navegar para o diretório do agente
cd C:\path\to\SaasIdentityAgent
```

### 2. Configuração

Edite o arquivo `appsettings.json`:

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