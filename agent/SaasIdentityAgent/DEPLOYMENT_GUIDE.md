# SaaS Identity Management Agent - Deployment Guide

This guide provides comprehensive instructions for deploying the SaaS Identity Management Agent across different environments and platforms.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Windows Deployment](#windows-deployment)
4. [Linux Deployment](#linux-deployment)
5. [Docker Deployment](#docker-deployment)
6. [Configuration](#configuration)
7. [Security Considerations](#security-considerations)
8. [Monitoring and Troubleshooting](#monitoring-and-troubleshooting)
9. [Maintenance](#maintenance)

## Overview

The SaaS Identity Management Agent is a background service that synchronizes Active Directory users and groups with the SaaS Identity Management platform. It supports multiple deployment methods:

- **Windows Service**: Native Windows service installation
- **Linux Systemd**: Systemd service on Linux distributions
- **Docker Container**: Containerized deployment for any Docker-compatible platform

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

## Windows Deployment

### Method 1: Advanced Deployment Script (Recommended)

The advanced deployment script provides automated configuration and validation.

```powershell
# Download and run the deployment script
.\Scripts\deploy-agent.ps1 `
    -TenantId "your-tenant-id" `
    -BackendUrl "https://api.yourcompany.com" `
    -ApiKey "your-api-key" `
    -DomainName "company.local" `
    -ServiceAccountUsername "COMPANY\svc-saas" `
    -ServiceAccountPassword "SecurePassword123!" `
    -Environment "Production"
```

#### Parameters

- **TenantId**: Your tenant identifier from the SaaS platform
- **BackendUrl**: URL of the SaaS backend API
- **ApiKey**: API key for authentication
- **DomainName**: Active Directory domain name
- **ServiceAccountUsername**: AD service account (format: DOMAIN\username)
- **ServiceAccountPassword**: Service account password
- **Environment**: Deployment environment (Development, Staging, Production)
- **InstallPath**: Installation directory (default: C:\Program Files\SaasIdentityAgent)
- **ValidateOnly**: Only validate configuration without installing
- **Force**: Force reinstallation

#### Validation Only

```powershell
# Validate configuration before deployment
.\Scripts\deploy-agent.ps1 `
    -TenantId "your-tenant-id" `
    -BackendUrl "https://api.yourcompany.com" `
    -ApiKey "your-api-key" `
    -DomainName "company.local" `
    -ServiceAccountUsername "COMPANY\svc-saas" `
    -ServiceAccountPassword "SecurePassword123!" `
    -ValidateOnly
```

### Method 2: Manual Installation

```powershell
# Build the application
dotnet publish -c Release -o "C:\Program Files\SaasIdentityAgent"

# Install as Windows Service
.\Scripts\install-agent.ps1

# Configure appsettings.json manually
# Start the service
Start-Service -Name "SaasIdentityAgent"
```

### Service Management

```powershell
# Check service status
Get-Service -Name "SaasIdentityAgent"

# Start/Stop/Restart service
Start-Service -Name "SaasIdentityAgent"
Stop-Service -Name "SaasIdentityAgent"
Restart-Service -Name "SaasIdentityAgent"

# View service logs
Get-EventLog -LogName Application -Source "SaasIdentityAgent" -Newest 50
```

## Linux Deployment

### Method 1: Automated Script (Recommended)

```bash
# Make script executable
chmod +x Scripts/deploy-agent-linux.sh

# Deploy with configuration
sudo ./Scripts/deploy-agent-linux.sh \
    --tenant-id "your-tenant-id" \
    --backend-url "https://api.yourcompany.com" \
    --api-key "your-api-key" \
    --domain-name "company.local" \
    --service-account "svc-saas" \
    --service-password "SecurePassword123!" \
    --environment "Production"
```

#### Parameters

- **--tenant-id**: Your tenant identifier
- **--backend-url**: SaaS backend API URL
- **--api-key**: API key for authentication
- **--domain-name**: Active Directory domain
- **--service-account**: AD service account username
- **--service-password**: Service account password
- **--install-path**: Installation directory (default: /opt/saas-identity-agent)
- **--environment**: Deployment environment
- **--validate-only**: Validation mode
- **--force**: Force reinstallation

### Method 2: Manual Installation

```bash
# Install .NET 6 Runtime (Ubuntu/Debian)
wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y aspnetcore-runtime-6.0

# Create service user
sudo useradd --system --home-dir /var/lib/saas-identity-agent --shell /bin/false saas-agent

# Create directories
sudo mkdir -p /opt/saas-identity-agent /var/lib/saas-identity-agent /var/log/saas-identity-agent

# Build and publish
dotnet publish -c Release -o /opt/saas-identity-agent

# Set permissions
sudo chown -R saas-agent:saas-agent /opt/saas-identity-agent /var/lib/saas-identity-agent /var/log/saas-identity-agent

# Create systemd service (see script for service file content)
sudo systemctl daemon-reload
sudo systemctl enable saas-identity-agent
sudo systemctl start saas-identity-agent
```

### Service Management

```bash
# Check service status
sudo systemctl status saas-identity-agent

# Start/Stop/Restart service
sudo systemctl start saas-identity-agent
sudo systemctl stop saas-identity-agent
sudo systemctl restart saas-identity-agent

# View logs
sudo journalctl -u saas-identity-agent -f
sudo tail -f /var/log/saas-identity-agent/agent-*.log
```

## Docker Deployment

### Method 1: Docker Compose (Recommended)

1. **Prepare Environment Configuration**

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
vim .env
```

2. **Configure .env File**

```bash
# Required Configuration
AGENT_TENANT_ID=your-tenant-id
AGENT_BACKEND_URL=https://api.yourcompany.com
AGENT_API_KEY=your-api-key
AD_DOMAIN_NAME=company.local
AD_SERVICE_ACCOUNT=svc-saas
AD_SERVICE_PASSWORD=SecurePassword123!

# Optional Configuration
AGENT_ENVIRONMENT=Production
AGENT_SYNC_INTERVAL=3600
BACKEND_VALIDATE_SSL=true
```

3. **Deploy with Docker Compose**

```bash
# Build and start the container
docker-compose up -d

# View logs
docker-compose logs -f saas-identity-agent

# Check container status
docker-compose ps
```

### Method 2: Docker Run

```bash
# Build the image
docker build -t saas-identity-agent .

# Run the container
docker run -d \
    --name saas-identity-agent \
    --restart unless-stopped \
    -e AGENT_TENANT_ID="your-tenant-id" \
    -e AGENT_BACKEND_URL="https://api.yourcompany.com" \
    -e AGENT_API_KEY="your-api-key" \
    -e AD_DOMAIN_NAME="company.local" \
    -e AD_SERVICE_ACCOUNT="svc-saas" \
    -e AD_SERVICE_PASSWORD="SecurePassword123!" \
    -v agent_data:/app/data \
    -v agent_logs:/app/logs \
    saas-identity-agent
```

### Container Management

```bash
# View container logs
docker logs -f saas-identity-agent

# Check container status
docker ps

# Access container shell
docker exec -it saas-identity-agent /bin/bash

# Stop/Start container
docker stop saas-identity-agent
docker start saas-identity-agent

# Update container
docker-compose pull
docker-compose up -d
```

## Configuration

### Core Settings

#### Agent Configuration

```json
{
  "Agent": {
    "AgentId": "AGENT-SERVER01-20240101-120000",
    "TenantId": "your-tenant-id",
    "Version": "1.0.0",
    "HeartbeatIntervalSeconds": 60,
    "SyncIntervalSeconds": 3600,
    "CommandCheckIntervalSeconds": 30,
    "MaxRetryAttempts": 3,
    "RetryDelaySeconds": 5,
    "SyncOnlyEnabledUsers": true,
    "LogLevel": "Information"
  }
}
```

#### Backend Configuration

```json
{
  "Backend": {
    "BaseUrl": "https://api.yourcompany.com",
    "ApiKey": "your-api-key",
    "TimeoutSeconds": 30,
    "ValidateSslCertificate": true,
    "ProxyUrl": "",
    "ProxyUsername": "",
    "ProxyPassword": ""
  }
}
```

#### Active Directory Configuration

```json
{
  "ActiveDirectory": {
    "DomainName": "company.local",
    "ServiceAccountUsername": "COMPANY\\svc-saas",
    "ServiceAccountPassword": "SecurePassword123!",
    "DomainController": "",
    "DefaultUserContainer": "CN=Users",
    "DefaultGroupContainer": "CN=Users",
    "UseSecureConnection": true,
    "LdapPort": 636,
    "ConnectionTimeoutSeconds": 30,
    "OrganizationalUnitsToSync": [
      "OU=Users,DC=company,DC=local",
      "OU=Groups,DC=company,DC=local"
    ],
    "OrganizationalUnitsToExclude": [
      "OU=Service Accounts,DC=company,DC=local",
      "OU=Disabled Users,DC=company,DC=local"
    ]
  }
}
```

### Environment-Specific Settings

#### Development

```json
{
  "Agent": {
    "SyncIntervalSeconds": 300,
    "LogLevel": "Debug"
  },
  "Backend": {
    "ValidateSslCertificate": false
  }
}
```

#### Production

```json
{
  "Agent": {
    "SyncIntervalSeconds": 3600,
    "LogLevel": "Information"
  },
  "Backend": {
    "ValidateSslCertificate": true
  }
}
```

## Security Considerations

### Service Account Security

1. **Principle of Least Privilege**
   - Grant only read permissions to AD
   - Limit access to specific OUs if possible
   - Use a dedicated service account

2. **Password Management**
   - Use strong, complex passwords
   - Rotate passwords regularly
   - Store passwords securely (avoid plain text)

3. **Account Monitoring**
   - Monitor service account usage
   - Set up alerts for failed authentications
   - Regular security audits

### Network Security

1. **Firewall Configuration**
   ```bash
   # Allow outbound HTTPS to SaaS backend
   # Allow outbound LDAPS (636) to domain controllers
   # Block unnecessary inbound connections
   ```

2. **SSL/TLS Configuration**
   - Always use HTTPS for backend communication
   - Use LDAPS for Active Directory connections
   - Validate SSL certificates in production

3. **Network Segmentation**
   - Deploy agent in secure network segment
   - Limit network access to required services only
   - Use VPN or private networks when possible

### Configuration Security

1. **Secrets Management**
   ```bash
   # Use environment variables for sensitive data
   # Consider using secret management systems
   # Encrypt configuration files at rest
   ```

2. **File Permissions**
   ```bash
   # Windows
   icacls config.json /grant "SYSTEM:(R)" /inheritance:r
   
   # Linux
   chmod 600 appsettings.json
   chown saas-agent:saas-agent appsettings.json
   ```

## Monitoring and Troubleshooting

### Health Checks

1. **Service Status**
   ```bash
   # Windows
   Get-Service -Name "SaasIdentityAgent"
   
   # Linux
   systemctl status saas-identity-agent
   
   # Docker
   docker ps
   docker-compose ps
   ```

2. **Log Analysis**
   ```bash
   # Windows Event Log
   Get-EventLog -LogName Application -Source "SaasIdentityAgent"
   
   # Linux Journal
   journalctl -u saas-identity-agent --since "1 hour ago"
   
   # Application Logs
   tail -f /var/log/saas-identity-agent/agent-*.log
   ```

3. **Network Connectivity**
   ```bash
   # Test backend API
   curl -I https://api.yourcompany.com/api/health/
   
   # Test LDAP connectivity
   ldapsearch -x -H ldap://company.local -b "" -s base
   ```

### Common Issues

#### Authentication Failures

**Symptoms**: Agent cannot authenticate with backend or AD

**Solutions**:
- Verify API key is correct and not expired
- Check service account credentials
- Ensure service account has proper permissions
- Verify network connectivity

#### Synchronization Issues

**Symptoms**: Users/groups not syncing properly

**Solutions**:
- Check OU configuration
- Verify LDAP filters
- Review sync logs for errors
- Ensure proper AD permissions

#### Performance Issues

**Symptoms**: Slow synchronization or high resource usage

**Solutions**:
- Adjust sync intervals
- Optimize OU selection
- Increase timeout values
- Monitor system resources

### Logging Configuration

```json
{
  "Serilog": {
    "MinimumLevel": {
      "Default": "Information",
      "Override": {
        "SaasIdentityAgent": "Debug"
      }
    },
    "WriteTo": [
      {
        "Name": "File",
        "Args": {
          "path": "logs/agent-.log",
          "rollingInterval": "Day",
          "retainedFileCountLimit": 30
        }
      }
    ]
  }
}
```

## Maintenance

### Regular Tasks

1. **Log Rotation**
   - Monitor log file sizes
   - Configure automatic log rotation
   - Archive old logs if needed

2. **Updates**
   ```bash
   # Windows
   Stop-Service -Name "SaasIdentityAgent"
   # Replace binaries
   Start-Service -Name "SaasIdentityAgent"
   
   # Linux
   sudo systemctl stop saas-identity-agent
   # Replace binaries
   sudo systemctl start saas-identity-agent
   
   # Docker
   docker-compose pull
   docker-compose up -d
   ```

3. **Security Updates**
   - Rotate service account passwords
   - Update API keys
   - Apply OS security patches
   - Update .NET runtime

### Backup and Recovery

1. **Configuration Backup**
   ```bash
   # Backup configuration files
   cp appsettings.json appsettings.json.backup
   
   # Backup environment files
   cp .env .env.backup
   ```

2. **Data Backup**
   ```bash
   # Backup agent data (if applicable)
   tar -czf agent-data-backup.tar.gz /var/lib/saas-identity-agent/
   ```

3. **Recovery Procedures**
   - Document recovery steps
   - Test recovery procedures regularly
   - Maintain emergency contact information

### Performance Tuning

1. **Sync Optimization**
   ```json
   {
     "Agent": {
       "SyncIntervalSeconds": 7200,  // Increase for large domains
       "MaxRetryAttempts": 5,        // Increase for unreliable networks
       "RetryDelaySeconds": 10       // Increase delay for stability
     }
   }
   ```

2. **Resource Limits**
   ```yaml
   # Docker Compose
   deploy:
     resources:
       limits:
         memory: 1G
         cpus: '1.0'
   ```

3. **Network Optimization**
   - Use local domain controllers
   - Optimize network routes
   - Consider bandwidth limitations

## Support and Documentation

### Getting Help

1. **Log Analysis**: Always include relevant logs when requesting support
2. **Configuration Review**: Verify configuration against this guide
3. **Network Testing**: Test connectivity to all required services
4. **Version Information**: Include agent version and platform details

### Additional Resources

- [API Documentation](../README.md)
- [Security Guide](../../deploy/SECURITY_GUIDE.md)
- [Troubleshooting Guide](./TROUBLESHOOTING.md)
- [Performance Tuning Guide](./PERFORMANCE_GUIDE.md)

---

**Note**: This deployment guide is regularly updated. Please check for the latest version before deployment.