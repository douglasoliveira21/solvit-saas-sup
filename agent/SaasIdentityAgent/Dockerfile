# SaaS Identity Management Agent - Docker Image
# Multi-stage build for optimized production image

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src

# Copy project file and restore dependencies
COPY SaasIdentityAgent.csproj .
RUN dotnet restore

# Copy source code and build
COPY . .
RUN dotnet publish -c Release -o /app/publish --no-restore --self-contained false

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS runtime

# Install additional packages for LDAP connectivity
RUN apt-get update && apt-get install -y \
    ldap-utils \
    dnsutils \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r saasagent && useradd -r -g saasagent -d /app -s /bin/bash saasagent

# Set working directory
WORKDIR /app

# Create directories for data and logs
RUN mkdir -p /app/data /app/logs && \
    chown -R saasagent:saasagent /app

# Copy published application
COPY --from=build /app/publish .

# Copy configuration template
COPY appsettings.json appsettings.template.json

# Create entrypoint script
RUN cat > /app/entrypoint.sh << 'EOF'
#!/bin/bash
set -e

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting SaaS Identity Management Agent..."

# Validate required environment variables
required_vars=(
    "AGENT_TENANT_ID"
    "AGENT_BACKEND_URL"
    "AGENT_API_KEY"
    "AD_DOMAIN_NAME"
    "AD_SERVICE_ACCOUNT"
    "AD_SERVICE_PASSWORD"
)

for var in "${required_vars[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        log "ERROR: Required environment variable $var is not set"
        exit 1
    fi
done

# Generate unique Agent ID if not provided
if [[ -z "${AGENT_ID:-}" ]]; then
    AGENT_ID="AGENT-$(hostname)-$(date +%Y%m%d-%H%M%S)"
    log "Generated Agent ID: $AGENT_ID"
fi

# Set default values
AGENT_ENVIRONMENT="${AGENT_ENVIRONMENT:-Production}"
AGENT_HEARTBEAT_INTERVAL="${AGENT_HEARTBEAT_INTERVAL:-60}"
AGENT_SYNC_INTERVAL="${AGENT_SYNC_INTERVAL:-3600}"
AGENT_COMMAND_CHECK_INTERVAL="${AGENT_COMMAND_CHECK_INTERVAL:-30}"
AGENT_MAX_RETRY_ATTEMPTS="${AGENT_MAX_RETRY_ATTEMPTS:-3}"
AGENT_RETRY_DELAY="${AGENT_RETRY_DELAY:-5}"
AGENT_SYNC_ONLY_ENABLED="${AGENT_SYNC_ONLY_ENABLED:-true}"
BACKEND_TIMEOUT="${BACKEND_TIMEOUT:-30}"
BACKEND_VALIDATE_SSL="${BACKEND_VALIDATE_SSL:-true}"
AD_USE_SECURE_CONNECTION="${AD_USE_SECURE_CONNECTION:-true}"
AD_LDAP_PORT="${AD_LDAP_PORT:-636}"
AD_CONNECTION_TIMEOUT="${AD_CONNECTION_TIMEOUT:-30}"

# Set log level based on environment
if [[ "$AGENT_ENVIRONMENT" == "Development" ]]; then
    LOG_LEVEL="Debug"
    AGENT_SYNC_INTERVAL="${AGENT_SYNC_INTERVAL:-300}"
    BACKEND_VALIDATE_SSL="false"
else
    LOG_LEVEL="Information"
fi

# Generate configuration file from template
log "Generating configuration file..."
cat > /app/appsettings.json << EOL
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information",
      "System.Net.Http.HttpClient": "Warning",
      "SaasIdentityAgent": "$LOG_LEVEL"
    }
  },
  "Serilog": {
    "Using": ["Serilog.Sinks.Console", "Serilog.Sinks.File"],
    "MinimumLevel": {
      "Default": "Information",
      "Override": {
        "Microsoft": "Warning",
        "System": "Warning",
        "SaasIdentityAgent": "$LOG_LEVEL"
      }
    },
    "WriteTo": [
      {
        "Name": "Console",
        "Args": {
          "outputTemplate": "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}"
        }
      },
      {
        "Name": "File",
        "Args": {
          "path": "/app/logs/agent-.log",
          "rollingInterval": "Day",
          "retainedFileCountLimit": 30,
          "outputTemplate": "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}",
          "fileSizeLimitBytes": 104857600,
          "rollOnFileSizeLimit": true
        }
      }
    ],
    "Enrich": ["FromLogContext", "WithMachineName", "WithThreadId"]
  },
  "Agent": {
    "AgentId": "$AGENT_ID",
    "TenantId": "$AGENT_TENANT_ID",
    "Version": "1.0.0",
    "HeartbeatIntervalSeconds": $AGENT_HEARTBEAT_INTERVAL,
    "SyncIntervalSeconds": $AGENT_SYNC_INTERVAL,
    "CommandCheckIntervalSeconds": $AGENT_COMMAND_CHECK_INTERVAL,
    "MaxRetryAttempts": $AGENT_MAX_RETRY_ATTEMPTS,
    "RetryDelaySeconds": $AGENT_RETRY_DELAY,
    "SyncOnlyEnabledUsers": $AGENT_SYNC_ONLY_ENABLED,
    "LogLevel": "$LOG_LEVEL"
  },
  "Backend": {
    "BaseUrl": "$AGENT_BACKEND_URL",
    "ApiKey": "$AGENT_API_KEY",
    "TimeoutSeconds": $BACKEND_TIMEOUT,
    "ValidateSslCertificate": $BACKEND_VALIDATE_SSL,
    "ProxyUrl": "${BACKEND_PROXY_URL:-}",
    "ProxyUsername": "${BACKEND_PROXY_USERNAME:-}",
    "ProxyPassword": "${BACKEND_PROXY_PASSWORD:-}"
  },
  "ActiveDirectory": {
    "DomainName": "$AD_DOMAIN_NAME",
    "ServiceAccountUsername": "$AD_SERVICE_ACCOUNT",
    "ServiceAccountPassword": "$AD_SERVICE_PASSWORD",
    "DomainController": "${AD_DOMAIN_CONTROLLER:-}",
    "DefaultUserContainer": "${AD_DEFAULT_USER_CONTAINER:-CN=Users}",
    "DefaultGroupContainer": "${AD_DEFAULT_GROUP_CONTAINER:-CN=Users}",
    "UseSecureConnection": $AD_USE_SECURE_CONNECTION,
    "LdapPort": $AD_LDAP_PORT,
    "ConnectionTimeoutSeconds": $AD_CONNECTION_TIMEOUT,
    "OrganizationalUnitsToSync": [
      "${AD_SYNC_OUS:-OU=Users,DC=$(echo $AD_DOMAIN_NAME | sed 's/\./,DC=/g')}"
    ],
    "OrganizationalUnitsToExclude": [
      "${AD_EXCLUDE_OUS:-OU=Service Accounts,DC=$(echo $AD_DOMAIN_NAME | sed 's/\./,DC=/g')}"
    ]
  }
}
EOL

# Validate backend connectivity
log "Testing backend connectivity..."
if ! curl -s --connect-timeout 10 "$AGENT_BACKEND_URL/api/health/" > /dev/null; then
    log "WARNING: Cannot connect to backend API: $AGENT_BACKEND_URL"
    log "The agent will continue to retry connections..."
else
    log "Backend API is accessible: $AGENT_BACKEND_URL"
fi

# Test LDAP connectivity (optional)
if command -v ldapsearch &> /dev/null; then
    log "Testing LDAP connectivity..."
    if ldapsearch -x -H "ldap://$AD_DOMAIN_NAME" -b "" -s base "(objectclass=*)" namingContexts &> /dev/null; then
        log "LDAP connectivity test successful"
    else
        log "WARNING: LDAP connectivity test failed. Check network and credentials."
    fi
fi

# Start the application
log "Starting SaaS Identity Agent with configuration:"
log "  Agent ID: $AGENT_ID"
log "  Tenant ID: $AGENT_TENANT_ID"
log "  Environment: $AGENT_ENVIRONMENT"
log "  Backend URL: $AGENT_BACKEND_URL"
log "  AD Domain: $AD_DOMAIN_NAME"
log "  Log Level: $LOG_LEVEL"

exec dotnet SaasIdentityAgent.dll
EOF

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Switch to non-root user
USER saasagent

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose health check port (if implemented)
EXPOSE 8080

# Set environment variables with defaults
ENV AGENT_ENVIRONMENT=Production \
    AGENT_HEARTBEAT_INTERVAL=60 \
    AGENT_SYNC_INTERVAL=3600 \
    AGENT_COMMAND_CHECK_INTERVAL=30 \
    AGENT_MAX_RETRY_ATTEMPTS=3 \
    AGENT_RETRY_DELAY=5 \
    AGENT_SYNC_ONLY_ENABLED=true \
    BACKEND_TIMEOUT=30 \
    BACKEND_VALIDATE_SSL=true \
    AD_USE_SECURE_CONNECTION=true \
    AD_LDAP_PORT=636 \
    AD_CONNECTION_TIMEOUT=30

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]