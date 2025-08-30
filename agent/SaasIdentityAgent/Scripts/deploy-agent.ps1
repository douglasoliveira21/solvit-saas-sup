<#
.SYNOPSIS
    Advanced deployment script for SaaS Identity Management Agent

.DESCRIPTION
    This script provides a comprehensive deployment solution for the SaaS Identity Management Agent
    including configuration validation, automatic setup, and health checks.

.PARAMETER TenantId
    The tenant ID for the SaaS platform

.PARAMETER BackendUrl
    The URL of the SaaS backend API

.PARAMETER ApiKey
    The API key for authentication with the backend

.PARAMETER DomainName
    The Active Directory domain name

.PARAMETER ServiceAccountUsername
    The AD service account username (format: DOMAIN\username)

.PARAMETER ServiceAccountPassword
    The AD service account password

.PARAMETER InstallPath
    Installation directory (default: C:\Program Files\SaasIdentityAgent)

.PARAMETER Environment
    Deployment environment (Development, Staging, Production)

.PARAMETER ValidateOnly
    Only validate configuration without installing

.PARAMETER Force
    Force reinstallation even if service exists

.EXAMPLE
    .\deploy-agent.ps1 -TenantId "tenant123" -BackendUrl "https://api.example.com" -ApiKey "key123" -DomainName "company.local" -ServiceAccountUsername "COMPANY\svc-saas" -ServiceAccountPassword "Password123"
    
.EXAMPLE
    .\deploy-agent.ps1 -ValidateOnly -TenantId "tenant123"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$true)]
    [string]$BackendUrl,
    
    [Parameter(Mandatory=$true)]
    [string]$ApiKey,
    
    [Parameter(Mandatory=$true)]
    [string]$DomainName,
    
    [Parameter(Mandatory=$true)]
    [string]$ServiceAccountUsername,
    
    [Parameter(Mandatory=$true)]
    [string]$ServiceAccountPassword,
    
    [string]$InstallPath = "C:\Program Files\SaasIdentityAgent",
    
    [ValidateSet("Development", "Staging", "Production")]
    [string]$Environment = "Production",
    
    [switch]$ValidateOnly = $false,
    
    [switch]$Force = $false
)

# Requires Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

$ServiceName = "SaasIdentityAgent"
$DisplayName = "SaaS Identity Management Agent"
$Description = "Agent for synchronizing Active Directory with SaaS Identity Management Platform"
$ExecutableName = "SaasIdentityAgent.exe"
$DataPath = "C:\ProgramData\SaasIdentityAgent"

# Generate unique Agent ID
$AgentId = "AGENT-" + $env:COMPUTERNAME + "-" + (Get-Date -Format "yyyyMMdd-HHmmss")

Write-Host "=== SaaS Identity Management Agent Deployment ===" -ForegroundColor Green
Write-Host "Environment: $Environment" -ForegroundColor Cyan
Write-Host "Agent ID: $AgentId" -ForegroundColor Cyan
Write-Host "Tenant ID: $TenantId" -ForegroundColor Cyan
Write-Host "Backend URL: $BackendUrl" -ForegroundColor Cyan

function Test-Prerequisites {
    Write-Host "\nValidating prerequisites..." -ForegroundColor Yellow
    
    $errors = @()
    
    # Check .NET 6 Runtime
    try {
        $dotnetVersion = dotnet --version 2>$null
        if ($dotnetVersion -and $dotnetVersion.StartsWith("6.")) {
            Write-Host "✓ .NET 6 Runtime found: $dotnetVersion" -ForegroundColor Green
        } else {
            $errors += ".NET 6 Runtime not found or incorrect version"
        }
    } catch {
        $errors += ".NET 6 Runtime not found"
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        Write-Host "✓ PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Green
    } else {
        $errors += "PowerShell 5.0 or higher required"
    }
    
    # Check if domain is reachable
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain()
        if ($domain.Name -eq $DomainName) {
            Write-Host "✓ Domain accessible: $($domain.Name)" -ForegroundColor Green
        } else {
            Write-Warning "Current domain ($($domain.Name)) differs from specified domain ($DomainName)"
        }
    } catch {
        $errors += "Cannot access Active Directory domain: $DomainName"
    }
    
    # Test backend connectivity
    try {
        $response = Invoke-WebRequest -Uri "$BackendUrl/api/health/" -Method GET -TimeoutSec 10 -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            Write-Host "✓ Backend API accessible: $BackendUrl" -ForegroundColor Green
        } else {
            $errors += "Backend API returned status: $($response.StatusCode)"
        }
    } catch {
        $errors += "Cannot connect to backend API: $BackendUrl - $($_.Exception.Message)"
    }
    
    # Test service account credentials
    try {
        $securePassword = ConvertTo-SecureString $ServiceAccountPassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($ServiceAccountUsername, $securePassword)
        
        # Try to create a DirectoryEntry with the credentials
        $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainName", $credential.UserName, $credential.GetNetworkCredential().Password)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        $searcher.Filter = "(objectClass=domain)"
        $result = $searcher.FindOne()
        
        if ($result) {
            Write-Host "✓ Service account credentials validated" -ForegroundColor Green
        } else {
            $errors += "Service account credentials validation failed"
        }
    } catch {
        $errors += "Service account authentication failed: $($_.Exception.Message)"
    }
    
    if ($errors.Count -gt 0) {
        Write-Host "\n❌ Prerequisites validation failed:" -ForegroundColor Red
        foreach ($error in $errors) {
            Write-Host "   • $error" -ForegroundColor Red
        }
        return $false
    }
    
    Write-Host "\n✅ All prerequisites validated successfully" -ForegroundColor Green
    return $true
}

function New-ConfigurationFile {
    param(
        [string]$ConfigPath
    )
    
    Write-Host "Creating configuration file..." -ForegroundColor Yellow
    
    $config = @{
        "Logging" = @{
            "LogLevel" = @{
                "Default" = "Information"
                "Microsoft" = "Warning"
                "Microsoft.Hosting.Lifetime" = "Information"
                "System.Net.Http.HttpClient" = "Warning"
                "SaasIdentityAgent" = if ($Environment -eq "Development") { "Debug" } else { "Information" }
            }
        }
        "Serilog" = @{
            "Using" = @("Serilog.Sinks.Console", "Serilog.Sinks.File", "Serilog.Sinks.EventLog")
            "MinimumLevel" = @{
                "Default" = "Information"
                "Override" = @{
                    "Microsoft" = "Warning"
                    "System" = "Warning"
                    "SaasIdentityAgent" = if ($Environment -eq "Development") { "Debug" } else { "Information" }
                }
            }
            "WriteTo" = @(
                @{
                    "Name" = "Console"
                    "Args" = @{
                        "outputTemplate" = "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}"
                    }
                },
                @{
                    "Name" = "File"
                    "Args" = @{
                        "path" = "$DataPath\logs\agent-.log"
                        "rollingInterval" = "Day"
                        "retainedFileCountLimit" = 30
                        "outputTemplate" = "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}"
                        "fileSizeLimitBytes" = 104857600
                        "rollOnFileSizeLimit" = $true
                    }
                },
                @{
                    "Name" = "EventLog"
                    "Args" = @{
                        "source" = "SaasIdentityAgent"
                        "logName" = "Application"
                        "manageEventSource" = $true
                    }
                }
            )
            "Enrich" = @("FromLogContext", "WithMachineName", "WithThreadId")
        }
        "Agent" = @{
            "AgentId" = $AgentId
            "TenantId" = $TenantId
            "Version" = "1.0.0"
            "HeartbeatIntervalSeconds" = 60
            "SyncIntervalSeconds" = if ($Environment -eq "Development") { 300 } else { 3600 }
            "CommandCheckIntervalSeconds" = 30
            "MaxRetryAttempts" = 3
            "RetryDelaySeconds" = 5
            "SyncOnlyEnabledUsers" = $true
            "LogLevel" = "Information"
        }
        "Backend" = @{
            "BaseUrl" = $BackendUrl
            "ApiKey" = $ApiKey
            "TimeoutSeconds" = 30
            "ValidateSslCertificate" = if ($Environment -eq "Development") { $false } else { $true }
            "ProxyUrl" = ""
            "ProxyUsername" = ""
            "ProxyPassword" = ""
        }
        "ActiveDirectory" = @{
            "DomainName" = $DomainName
            "ServiceAccountUsername" = $ServiceAccountUsername
            "ServiceAccountPassword" = $ServiceAccountPassword
            "DomainController" = ""
            "DefaultUserContainer" = "CN=Users"
            "DefaultGroupContainer" = "CN=Users"
            "UseSecureConnection" = $true
            "LdapPort" = 636
            "ConnectionTimeoutSeconds" = 30
            "OrganizationalUnitsToSync" = @(
                "OU=Users,DC=$($DomainName.Replace('.', ',DC='))",
                "OU=Groups,DC=$($DomainName.Replace('.', ',DC='))"
            )
            "OrganizationalUnitsToExclude" = @(
                "OU=Service Accounts,DC=$($DomainName.Replace('.', ',DC='))",
                "OU=Disabled Users,DC=$($DomainName.Replace('.', ',DC='))"
            )
        }
        "WindowsService" = @{
            "ServiceName" = $ServiceName
            "DisplayName" = $DisplayName
            "Description" = $Description
            "StartType" = "Automatic"
            "Account" = "LocalSystem"
        }
    }
    
    $configJson = $config | ConvertTo-Json -Depth 10
    $configJson | Out-File -FilePath $ConfigPath -Encoding UTF8
    
    Write-Host "✓ Configuration file created: $ConfigPath" -ForegroundColor Green
}

function Install-Agent {
    Write-Host "\nStarting agent installation..." -ForegroundColor Yellow
    
    try {
        # Stop and remove existing service if it exists
        $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existingService) {
            if (-not $Force) {
                Write-Warning "Service '$ServiceName' already exists. Use -Force to reinstall."
                return $false
            }
            
            Write-Host "Stopping existing service..." -ForegroundColor Yellow
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            
            Write-Host "Removing existing service..." -ForegroundColor Yellow
            sc.exe delete $ServiceName
            Start-Sleep -Seconds 3
        }
        
        # Create directories
        @($InstallPath, $DataPath, "$DataPath\logs") | ForEach-Object {
            if (-not (Test-Path $_)) {
                Write-Host "Creating directory: $_" -ForegroundColor Yellow
                New-Item -ItemType Directory -Path $_ -Force | Out-Null
            }
        }
        
        # Copy application files
        Write-Host "Copying application files..." -ForegroundColor Yellow
        $SourcePath = Split-Path -Parent $PSScriptRoot
        
        # Build the application first
        Push-Location $SourcePath
        try {
            Write-Host "Building application..." -ForegroundColor Yellow
            dotnet publish -c Release -o "$InstallPath" --self-contained false
            if ($LASTEXITCODE -ne 0) {
                throw "Build failed with exit code $LASTEXITCODE"
            }
        } finally {
            Pop-Location
        }
        
        # Create configuration file
        $configPath = Join-Path $InstallPath "appsettings.json"
        New-ConfigurationFile -ConfigPath $configPath
        
        # Set permissions
        Write-Host "Setting permissions..." -ForegroundColor Yellow
        icacls $InstallPath /grant "SYSTEM:(OI)(CI)F" /T | Out-Null
        icacls $DataPath /grant "SYSTEM:(OI)(CI)F" /T | Out-Null
        icacls $InstallPath /grant "Administrators:(OI)(CI)F" /T | Out-Null
        icacls $DataPath /grant "Administrators:(OI)(CI)F" /T | Out-Null
        
        # Create the Windows Service
        Write-Host "Creating Windows Service..." -ForegroundColor Yellow
        $ExecutablePath = Join-Path $InstallPath $ExecutableName
        
        $service = New-Service -Name $ServiceName -BinaryPathName $ExecutablePath -DisplayName $DisplayName -Description $Description -StartupType Automatic
        
        # Configure service recovery options
        Write-Host "Configuring service recovery options..." -ForegroundColor Yellow
        sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
        
        # Create Event Log source
        Write-Host "Creating Event Log source..." -ForegroundColor Yellow
        try {
            New-EventLog -LogName Application -Source "SaasIdentityAgent" -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Could not create Event Log source. The service will still function."
        }
        
        # Start the service
        Write-Host "Starting service..." -ForegroundColor Yellow
        Start-Service -Name $ServiceName
        
        # Wait and check service status
        Start-Sleep -Seconds 10
        $serviceStatus = Get-Service -Name $ServiceName
        
        if ($serviceStatus.Status -eq "Running") {
            Write-Host "\n✅ Service installed and started successfully!" -ForegroundColor Green
            Write-Host "Service Status: $($serviceStatus.Status)" -ForegroundColor Green
        } else {
            Write-Warning "Service installed but not running. Status: $($serviceStatus.Status)"
            Write-Host "Check the Event Log or service logs for more information." -ForegroundColor Yellow
        }
        
        return $true
        
    } catch {
        Write-Error "Installation failed: $($_.Exception.Message)"
        Write-Host "Error details: $($_.Exception.ToString())" -ForegroundColor Red
        return $false
    }
}

function Test-AgentHealth {
    Write-Host "\nPerforming health check..." -ForegroundColor Yellow
    
    $healthChecks = @()
    
    # Check service status
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        $healthChecks += @{ Name = "Service Status"; Status = "✓ Running"; Color = "Green" }
    } else {
        $healthChecks += @{ Name = "Service Status"; Status = "❌ Not Running"; Color = "Red" }
    }
    
    # Check log files
    $logPath = "$DataPath\logs"
    if (Test-Path $logPath) {
        $logFiles = Get-ChildItem -Path $logPath -Filter "*.log" | Sort-Object LastWriteTime -Descending
        if ($logFiles.Count -gt 0) {
            $latestLog = $logFiles[0]
            $healthChecks += @{ Name = "Log Files"; Status = "✓ Latest: $($latestLog.Name) ($($latestLog.LastWriteTime))"; Color = "Green" }
        } else {
            $healthChecks += @{ Name = "Log Files"; Status = "⚠ No log files found"; Color = "Yellow" }
        }
    } else {
        $healthChecks += @{ Name = "Log Files"; Status = "❌ Log directory not found"; Color = "Red" }
    }
    
    # Check configuration file
    $configPath = Join-Path $InstallPath "appsettings.json"
    if (Test-Path $configPath) {
        $healthChecks += @{ Name = "Configuration"; Status = "✓ Found"; Color = "Green" }
    } else {
        $healthChecks += @{ Name = "Configuration"; Status = "❌ Missing"; Color = "Red" }
    }
    
    # Display health check results
    Write-Host "\n=== Health Check Results ===" -ForegroundColor Cyan
    foreach ($check in $healthChecks) {
        Write-Host "$($check.Name): $($check.Status)" -ForegroundColor $check.Color
    }
}

# Main execution
try {
    # Validate prerequisites
    if (-not (Test-Prerequisites)) {
        exit 1
    }
    
    if ($ValidateOnly) {
        Write-Host "\n✅ Validation completed successfully. Ready for deployment." -ForegroundColor Green
        exit 0
    }
    
    # Install agent
    if (Install-Agent) {
        Test-AgentHealth
        
        Write-Host "\n=== Deployment Summary ===" -ForegroundColor Green
        Write-Host "Installation Path: $InstallPath" -ForegroundColor Cyan
        Write-Host "Data Path: $DataPath" -ForegroundColor Cyan
        Write-Host "Service Name: $ServiceName" -ForegroundColor Cyan
        Write-Host "Agent ID: $AgentId" -ForegroundColor Cyan
        Write-Host "Environment: $Environment" -ForegroundColor Cyan
        
        Write-Host "\n=== Next Steps ===" -ForegroundColor Yellow
        Write-Host "1. Monitor service logs in: $DataPath\logs" -ForegroundColor White
        Write-Host "2. Check Event Viewer for service events" -ForegroundColor White
        Write-Host "3. Verify synchronization in the SaaS platform" -ForegroundColor White
        Write-Host "4. Configure firewall rules if needed" -ForegroundColor White
        
        Write-Host "\n✅ Deployment completed successfully!" -ForegroundColor Green
    } else {
        Write-Host "\n❌ Deployment failed!" -ForegroundColor Red
        exit 1
    }
    
} catch {
    Write-Error "Deployment script failed: $($_.Exception.Message)"
    Write-Host "Error details: $($_.Exception.ToString())" -ForegroundColor Red
    exit 1
}