# Guia de Instalação do Agente AD e Teste de Funcionalidades

## 📁 Onde Encontrar o Agente para Instalação no Active Directory

### Localização dos Arquivos
O agente está localizado na pasta:
```
/home/solvit/solvit-saas-sup/agent/SaasIdentityAgent/
```

### Arquivos Principais
- **`SaasIdentityAgent.csproj`** - Projeto C# do agente
- **`Program.cs`** - Código principal do agente
- **`DEPLOYMENT_GUIDE.md`** - Guia completo de deployment
- **`Scripts/`** - Scripts de instalação automatizada
- **`Dockerfile`** - Para deployment em container
- **`docker-compose.yml`** - Orquestração Docker

## 🚀 Instalação do Agente no Active Directory

### Opção 1: Instalação Automatizada (Recomendada)

#### No Windows Server (Active Directory)
```powershell
# 1. Baixar os arquivos do agente para o servidor AD
# 2. Executar o script de deployment
.\Scripts\deploy-agent.ps1 `
    -TenantId "seu-tenant-id" `
    -BackendUrl "http://localhost:8000" `
    -ApiKey "sua-api-key" `
    -DomainName "empresa.local" `
    -ServiceAccountUsername "EMPRESA\svc-saas" `
    -ServiceAccountPassword "SenhaSegura123!" `
    -Environment "Production"
```

#### No Linux (com Samba AD)
```bash
# 1. Tornar o script executável
chmod +x Scripts/deploy-agent-linux.sh

# 2. Executar a instalação
sudo ./Scripts/deploy-agent-linux.sh \
    --tenant-id "seu-tenant-id" \
    --backend-url "http://localhost:8000" \
    --api-key "sua-api-key" \
    --domain-name "empresa.local" \
    --service-account "svc-saas" \
    --service-password "SenhaSegura123!" \
    --environment "Production"
```

### Opção 2: Docker (Mais Simples)
```bash
# 1. Navegar para a pasta do agente
cd /home/solvit/solvit-saas-sup/agent/SaasIdentityAgent/

# 2. Configurar variáveis de ambiente
cp .env.example .env
# Editar o arquivo .env com suas configurações

# 3. Executar com Docker Compose
docker-compose up -d

# 4. Verificar logs
docker-compose logs -f saas-identity-agent
```

## 🔧 Configuração Inicial

### 1. Obter API Key
1. Acesse o painel admin: `http://localhost:3000`
2. Faça login como administrador
3. Vá em **Configurações** → **API Keys**
4. Gere uma nova API key para o agente

### 2. Criar Conta de Serviço no AD
```powershell
# No Active Directory
New-ADUser -Name "svc-saas" `
    -UserPrincipalName "svc-saas@empresa.local" `
    -SamAccountName "svc-saas" `
    -AccountPassword (ConvertTo-SecureString "SenhaSegura123!" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true

# Adicionar permissões de leitura no AD
Add-ADGroupMember -Identity "Domain Users" -Members "svc-saas"
```

## 🧪 Como Testar a Funcionalidade - Passo a Passo

### Teste 1: Verificar Conexão do Agente

#### 1. Verificar Status do Agente
```bash
# Se instalado como serviço Linux
sudo systemctl status saas-identity-agent

# Se usando Docker
docker-compose ps
docker-compose logs saas-identity-agent
```

#### 2. Verificar Logs de Conexão
```bash
# Verificar se o agente está se conectando ao backend
tail -f /var/log/saas-identity-agent/agent-*.log

# Ou no Docker
docker-compose logs -f saas-identity-agent
```

### Teste 2: Sincronização de Usuários Existentes

#### 1. Acessar o Painel Web
1. Abra o navegador: `http://localhost:3000`
2. Faça login com suas credenciais de admin
3. Vá para **Usuários** → **Usuários Gerenciados**

#### 2. Verificar Sincronização
1. Clique em **"Sincronizar com AD"**
2. Aguarde o processo de sincronização
3. Verifique se os usuários do AD aparecem na lista

### Teste 3: Criação de Usuário via Painel

#### Passo 1: Acessar Criação de Usuário
1. No painel, vá para **Usuários** → **Adicionar Usuário**
2. Preencha os campos obrigatórios:
   - **Nome**: João Silva
   - **Email**: joao.silva@empresa.com
   - **Username**: joao.silva
   - **Senha temporária**: TempPass123!

#### Passo 2: Configurar Sincronização com AD
1. Marque a opção **"Sincronizar com Active Directory"**
2. Selecione a **Unidade Organizacional (OU)** de destino
3. Configure os **grupos** que o usuário deve pertencer

#### Passo 3: Criar o Usuário
1. Clique em **"Criar Usuário"**
2. Aguarde a confirmação de criação
3. Verifique se aparece a mensagem: "Usuário criado e sincronizado com AD"

#### Passo 4: Verificar no Active Directory
```powershell
# No servidor AD, verificar se o usuário foi criado
Get-ADUser -Filter "SamAccountName -eq 'joao.silva'" -Properties *

# Verificar grupos do usuário
Get-ADPrincipalGroupMembership -Identity "joao.silva"
```

### Teste 4: Verificar Logs de Auditoria

#### 1. Acessar Logs no Painel
1. Vá para **Auditoria** → **Logs de Sistema**
2. Filtre por:
   - **Ação**: "user_created"
   - **Data**: Hoje
   - **Usuário**: Seu usuário admin

#### 2. Verificar Detalhes
1. Clique no log da criação do usuário
2. Verifique os detalhes:
   - Usuário criado
   - Sincronização com AD
   - Grupos atribuídos
   - Timestamp da operação

### Teste 5: Testar Autenticação do Novo Usuário

#### 1. Logout do Admin
1. Clique em **"Sair"** no painel

#### 2. Login com Novo Usuário
1. Tente fazer login com:
   - **Username**: joao.silva
   - **Senha**: TempPass123!
2. Verifique se o login é bem-sucedido
3. Confirme se o usuário tem as permissões corretas

## 🔍 Troubleshooting

### Problemas Comuns

#### 1. Agente Não Conecta
```bash
# Verificar conectividade
curl -I http://localhost:8000/api/health/

# Verificar configuração
cat /opt/saas-identity-agent/appsettings.json
```

#### 2. Erro de Autenticação AD
```bash
# Testar credenciais do serviço
ldapsearch -x -H ldap://seu-dc.empresa.local -D "svc-saas@empresa.local" -W
```

#### 3. Usuário Não Criado no AD
1. Verificar logs do agente
2. Confirmar permissões da conta de serviço
3. Verificar conectividade LDAP

### Comandos Úteis de Diagnóstico

```bash
# Status dos serviços
sudo systemctl status saas-identity-agent
sudo systemctl status nginx
sudo systemctl status postgresql

# Logs em tempo real
tail -f /var/log/saas-identity-agent/agent-*.log
tail -f /var/log/nginx/access.log

# Verificar portas
netstat -tlnp | grep -E ':(3000|8000|5432)'

# Testar API
curl -H "Authorization: Bearer sua-api-key" http://localhost:8000/api/tenants/
```

## 📊 Monitoramento Contínuo

### 1. Verificações Diárias
- Status do agente
- Logs de sincronização
- Usuários pendentes
- Erros de autenticação

### 2. Métricas Importantes
- Taxa de sincronização bem-sucedida
- Tempo de resposta da API
- Uso de memória do agente
- Conectividade com AD

### 3. Alertas Recomendados
- Agente offline por mais de 5 minutos
- Falhas de sincronização consecutivas
- Erros de autenticação AD
- Uso excessivo de recursos

## 🎯 Próximos Passos

1. **Configurar sincronização automática** (a cada hora)
2. **Implementar backup** das configurações
3. **Configurar monitoramento** com alertas
4. **Documentar procedimentos** específicos da empresa
5. **Treinar equipe** de TI nos procedimentos

---

**📞 Suporte**: Em caso de problemas, verifique os logs e consulte a documentação técnica completa em `DEPLOYMENT_GUIDE.md`.