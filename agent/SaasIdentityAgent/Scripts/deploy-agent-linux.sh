#!/bin/bash

# SaaS Identity Management Agent - Linux Deployment Script
# This script deploys the agent as a systemd service on Linux systems

set -euo pipefail

# Default values
INSTALL_PATH="/opt/saas-identity-agent"
DATA_PATH="/var/lib/saas-identity-agent"
LOG_PATH="/var/log/saas-identity-agent"
SERVICE_NAME="saas-identity-agent"
SERVICE_USER="saas-agent"
ENVIRONMENT="Production"
VALIDATE_ONLY=false
FORCE=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploys the SaaS Identity Management Agent as a systemd service.

Required Options:
  --tenant-id TENANT_ID           Tenant ID for the SaaS platform
  --backend-url BACKEND_URL       URL of the SaaS backend API
  --api-key API_KEY               API key for authentication
  --domain-name DOMAIN_NAME       Active Directory domain name
  --service-account SERVICE_ACCOUNT Service account username
  --service-password PASSWORD     Service account password

Optional Options:
  --install-path PATH             Installation directory (default: $INSTALL_PATH)
  --environment ENV               Environment (Development|Staging|Production, default: $ENVIRONMENT)
  --validate-only                 Only validate configuration without installing
  --force                         Force reinstallation
  --help                          Show this help message

Example:
  $0 --tenant-id "tenant123" --backend-url "https://api.example.com" \\
     --api-key "key123" --domain-name "company.local" \\
     --service-account "svc-saas" --service-password "Password123"

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --tenant-id)
            TENANT_ID="$2"
            shift 2
            ;;
        --backend-url)
            BACKEND_URL="$2"
            shift 2
            ;;
        --api-key)
            API_KEY="$2"
            shift 2
            ;;
        --domain-name)
            DOMAIN_NAME="$2"
            shift 2
            ;;
        --service-account)
            SERVICE_ACCOUNT="$2"
            shift 2
            ;;
        --service-password)
            SERVICE_PASSWORD="$2"
            shift 2
            ;;
        --install-path)
            INSTALL_PATH="$2"
            shift 2
            ;;
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --validate-only)
            VALIDATE_ONLY=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "${TENANT_ID:-}" || -z "${BACKEND_URL:-}" || -z "${API_KEY:-}" || 
      -z "${DOMAIN_NAME:-}" || -z "${SERVICE_ACCOUNT:-}" || -z "${SERVICE_PASSWORD:-}" ]]; then
    print_error "Missing required parameters"
    show_usage
    exit 1
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

# Generate unique Agent ID
AGENT_ID="AGENT-$(hostname)-$(date +%Y%m%d-%H%M%S)"

print_status "=== SaaS Identity Management Agent Deployment ==="
print_status "Environment: $ENVIRONMENT"
print_status "Agent ID: $AGENT_ID"
print_status "Tenant ID: $TENANT_ID"
print_status "Backend URL: $BACKEND_URL"

# Function to validate prerequisites
validate_prerequisites() {
    print_status "Validating prerequisites..."
    
    local errors=()
    
    # Check .NET 6 Runtime
    if command -v dotnet &> /dev/null; then
        local dotnet_version=$(dotnet --version 2>/dev/null || echo "")
        if [[ $dotnet_version == 6.* ]]; then
            print_success "✓ .NET 6 Runtime found: $dotnet_version"
        else
            errors+=("✗ .NET 6 Runtime not found or incorrect version")
        fi
    else
        errors+=("✗ .NET 6 Runtime not installed")
    fi
    
    # Check systemd
    if command -v systemctl &> /dev/null; then
        print_success "✓ systemd found"
    else
        errors+=("✗ systemd not found")
    fi
    
    # Check curl for API testing
    if command -v curl &> /dev/null; then
        print_success "✓ curl found"
    else
        errors+=("✗ curl not found")
    fi
    
    # Test backend connectivity
    if curl -s --connect-timeout 10 "$BACKEND_URL/api/health/" > /dev/null; then
        print_success "✓ Backend API accessible: $BACKEND_URL"
    else
        errors+=("✗ Cannot connect to backend API: $BACKEND_URL")
    fi
    
    # Check if LDAP tools are available (optional)
    if command -v ldapsearch &> /dev/null; then
        print_success "✓ LDAP tools found"
    else
        print_warning "⚠ LDAP tools not found (optional for testing)"
    fi
    
    if [[ ${#errors[@]} -gt 0 ]]; then
        print_error "Prerequisites validation failed:"
        for error in "${errors[@]}"; do
            print_error "   $error"
        done
        return 1
    fi
    
    print_success "✅ All prerequisites validated successfully"
    return 0
}

# Function to create configuration file
create_configuration() {
    local config_path="$1"
    
    print_status "Creating configuration file..."
    
    local sync_interval=3600
    local log_level="Information"
    local validate_ssl="true"
    
    if [[ "$ENVIRONMENT" == "Development" ]]; then
        sync_interval=300
        log_level="Debug"
        validate_ssl="false"
    fi
    
    cat > "$config_path" << EOF
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information",
      "System.Net.Http.HttpClient": "Warning",
      "SaasIdentityAgent": "$log_level"
    }
  },
  "Serilog": {
    "Using": ["Serilog.Sinks.Console", "Serilog.Sinks.File"],
    "MinimumLevel": {
      "Default": "Information",
      "Override": {
        "Microsoft": "Warning",
        "System": "Warning",
        "SaasIdentityAgent": "$log_level"
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
          "path": "$LOG_PATH/agent-.log",
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
    "TenantId": "$TENANT_ID",
    "Version": "1.0.0",
    "HeartbeatIntervalSeconds": 60,
    "SyncIntervalSeconds": $sync_interval,
    "CommandCheckIntervalSeconds": 30,
    "MaxRetryAttempts": 3,
    "RetryDelaySeconds": 5,
    "SyncOnlyEnabledUsers": true,
    "LogLevel": "$log_level"
  },
  "Backend": {
    "BaseUrl": "$BACKEND_URL",
    "ApiKey": "$API_KEY",
    "TimeoutSeconds": 30,
    "ValidateSslCertificate": $validate_ssl,
    "ProxyUrl": "",
    "ProxyUsername": "",
    "ProxyPassword": ""
  },
  "ActiveDirectory": {
    "DomainName": "$DOMAIN_NAME",
    "ServiceAccountUsername": "$SERVICE_ACCOUNT",
    "ServiceAccountPassword": "$SERVICE_PASSWORD",
    "DomainController": "",
    "DefaultUserContainer": "CN=Users",
    "DefaultGroupContainer": "CN=Users",
    "UseSecureConnection": true,
    "LdapPort": 636,
    "ConnectionTimeoutSeconds": 30,
    "OrganizationalUnitsToSync": [
      "OU=Users,DC=$(echo $DOMAIN_NAME | sed 's/\./,DC=/g')",
      "OU=Groups,DC=$(echo $DOMAIN_NAME | sed 's/\./,DC=/g')"
    ],
    "OrganizationalUnitsToExclude": [
      "OU=Service Accounts,DC=$(echo $DOMAIN_NAME | sed 's/\./,DC=/g')",
      "OU=Disabled Users,DC=$(echo $DOMAIN_NAME | sed 's/\./,DC=/g')"
    ]
  }
}
EOF
    
    print_success "✓ Configuration file created: $config_path"
}

# Function to create systemd service
create_systemd_service() {
    print_status "Creating systemd service..."
    
    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=SaaS Identity Management Agent
After=network.target
Wants=network.target

[Service]
Type=notify
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_PATH
ExecStart=/usr/bin/dotnet $INSTALL_PATH/SaasIdentityAgent.dll
Restart=always
RestartSec=10
KillSignal=SIGINT
Environment=ASPNETCORE_ENVIRONMENT=$ENVIRONMENT
Environment=DOTNET_PRINT_TELEMETRY_MESSAGE=false
SyslogIdentifier=$SERVICE_NAME

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_PATH $LOG_PATH

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "✓ Systemd service file created"
}

# Function to install agent
install_agent() {
    print_status "Starting agent installation..."
    
    # Check if service exists
    if systemctl list-units --full -all | grep -Fq "$SERVICE_NAME.service"; then
        if [[ "$FORCE" != "true" ]]; then
            print_warning "Service '$SERVICE_NAME' already exists. Use --force to reinstall."
            return 1
        fi
        
        print_status "Stopping existing service..."
        systemctl stop "$SERVICE_NAME" || true
        systemctl disable "$SERVICE_NAME" || true
    fi
    
    # Create service user
    if ! id "$SERVICE_USER" &>/dev/null; then
        print_status "Creating service user: $SERVICE_USER"
        useradd --system --home-dir "$DATA_PATH" --shell /bin/false "$SERVICE_USER"
    fi
    
    # Create directories
    print_status "Creating directories..."
    mkdir -p "$INSTALL_PATH" "$DATA_PATH" "$LOG_PATH"
    
    # Build and publish the application
    print_status "Building application..."
    local source_path="$(dirname "$(dirname "$0")")"  # Go up from Scripts directory
    
    pushd "$source_path" > /dev/null
    dotnet publish -c Release -o "$INSTALL_PATH" --self-contained false
    if [[ $? -ne 0 ]]; then
        print_error "Build failed"
        return 1
    fi
    popd > /dev/null
    
    # Create configuration file
    create_configuration "$INSTALL_PATH/appsettings.json"
    
    # Set permissions
    print_status "Setting permissions..."
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_PATH" "$DATA_PATH" "$LOG_PATH"
    chmod -R 755 "$INSTALL_PATH"
    chmod -R 750 "$DATA_PATH" "$LOG_PATH"
    
    # Create systemd service
    create_systemd_service
    
    # Reload systemd and enable service
    print_status "Enabling and starting service..."
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    
    # Wait for service to start
    sleep 5
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "✅ Service installed and started successfully!"
        systemctl status "$SERVICE_NAME" --no-pager -l
    else
        print_error "Service installed but not running"
        print_status "Service status:"
        systemctl status "$SERVICE_NAME" --no-pager -l
        return 1
    fi
    
    return 0
}

# Function to perform health check
perform_health_check() {
    print_status "Performing health check..."
    
    # Check service status
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "✓ Service Status: Running"
    else
        print_error "❌ Service Status: Not Running"
    fi
    
    # Check log files
    if [[ -d "$LOG_PATH" ]]; then
        local log_files=("$LOG_PATH"/*.log)
        if [[ -f "${log_files[0]}" ]]; then
            local latest_log=$(ls -t "$LOG_PATH"/*.log 2>/dev/null | head -1)
            print_success "✓ Log Files: Found (Latest: $(basename "$latest_log"))"
        else
            print_warning "⚠ Log Files: No log files found"
        fi
    else
        print_error "❌ Log Files: Log directory not found"
    fi
    
    # Check configuration file
    if [[ -f "$INSTALL_PATH/appsettings.json" ]]; then
        print_success "✓ Configuration: Found"
    else
        print_error "❌ Configuration: Missing"
    fi
    
    # Show recent logs
    print_status "Recent service logs:"
    journalctl -u "$SERVICE_NAME" --no-pager -l --since "5 minutes ago" || true
}

# Main execution
main() {
    # Validate prerequisites
    if ! validate_prerequisites; then
        exit 1
    fi
    
    if [[ "$VALIDATE_ONLY" == "true" ]]; then
        print_success "✅ Validation completed successfully. Ready for deployment."
        exit 0
    fi
    
    # Install agent
    if install_agent; then
        perform_health_check
        
        print_success "=== Deployment Summary ==="
        echo -e "${CYAN}Installation Path:${NC} $INSTALL_PATH"
        echo -e "${CYAN}Data Path:${NC} $DATA_PATH"
        echo -e "${CYAN}Log Path:${NC} $LOG_PATH"
        echo -e "${CYAN}Service Name:${NC} $SERVICE_NAME"
        echo -e "${CYAN}Service User:${NC} $SERVICE_USER"
        echo -e "${CYAN}Agent ID:${NC} $AGENT_ID"
        echo -e "${CYAN}Environment:${NC} $ENVIRONMENT"
        
        print_status "=== Next Steps ==="
        echo -e "${NC}1. Monitor service logs: ${YELLOW}journalctl -u $SERVICE_NAME -f${NC}"
        echo -e "${NC}2. Check log files in: ${YELLOW}$LOG_PATH${NC}"
        echo -e "${NC}3. Verify synchronization in the SaaS platform${NC}"
        echo -e "${NC}4. Configure firewall rules if needed${NC}"
        
        print_success "✅ Deployment completed successfully!"
    else
        print_error "❌ Deployment failed!"
        exit 1
    fi
}

# Run main function
main "$@"