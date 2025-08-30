<#
.SYNOPSIS
    Installs the SaaS Identity Management Agent as a Windows Service

.DESCRIPTION
    This script installs and configures the SaaS Identity Management Agent
    as a Windows Service with proper permissions and configuration.

.PARAMETER ServiceAccount
    The service account to run the agent under (default: LocalSystem)

.PARAMETER ServicePassword
    The password for the service account (if not using LocalSystem)

.PARAMETER ConfigFile
    Path to the configuration file (default: appsettings.json)

.PARAMETER InstallPath
    Installation directory (default: C:\Program Files\SaasIdentityAgent)

.EXAMPLE
    .\install-agent.ps1
    
.EXAMPLE
    .\install-agent.ps1 -ServiceAccount "DOMAIN\ServiceAccount" -ServicePassword "Password123"
#>

param(
    [string]$ServiceAccount = "LocalSystem",
    [string]$ServicePassword = "",
    [string]$ConfigFile = "appsettings.json",
    [string]$InstallPath = "C:\Program Files\SaasIdentityAgent"
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

Write-Host "Installing SaaS Identity Management Agent..." -ForegroundColor Green

try {
    # Stop and remove existing service if it exists
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Host "Stopping existing service..." -ForegroundColor Yellow
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        
        Write-Host "Removing existing service..." -ForegroundColor Yellow
        sc.exe delete $ServiceName
        Start-Sleep -Seconds 2
    }

    # Create installation directory
    if (-not (Test-Path $InstallPath)) {
        Write-Host "Creating installation directory: $InstallPath" -ForegroundColor Yellow
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    }

    # Create logs directory
    $LogsPath = Join-Path $InstallPath "logs"
    if (-not (Test-Path $LogsPath)) {
        Write-Host "Creating logs directory: $LogsPath" -ForegroundColor Yellow
        New-Item -ItemType Directory -Path $LogsPath -Force | Out-Null
    }

    # Create data directory for configuration
    $DataPath = "C:\ProgramData\SaasIdentityAgent"
    if (-not (Test-Path $DataPath)) {
        Write-Host "Creating data directory: $DataPath" -ForegroundColor Yellow
        New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
    }

    $DataLogsPath = Join-Path $DataPath "logs"
    if (-not (Test-Path $DataLogsPath)) {
        New-Item -ItemType Directory -Path $DataLogsPath -Force | Out-Null
    }

    # Copy application files
    Write-Host "Copying application files..." -ForegroundColor Yellow
    $SourcePath = Split-Path -Parent $PSScriptRoot
    
    # Copy executable and dependencies
    Copy-Item -Path "$SourcePath\bin\Release\net6.0\*" -Destination $InstallPath -Recurse -Force
    
    # Copy configuration file
    if (Test-Path "$SourcePath\$ConfigFile") {
        Copy-Item -Path "$SourcePath\$ConfigFile" -Destination $InstallPath -Force
    }
    
    # Copy production configuration
    if (Test-Path "$SourcePath\appsettings.Production.json") {
        Copy-Item -Path "$SourcePath\appsettings.Production.json" -Destination $InstallPath -Force
    }

    # Set permissions on installation directory
    Write-Host "Setting permissions..." -ForegroundColor Yellow
    
    # Give service account full control
    if ($ServiceAccount -ne "LocalSystem") {
        icacls $InstallPath /grant "${ServiceAccount}:(OI)(CI)F" /T
        icacls $DataPath /grant "${ServiceAccount}:(OI)(CI)F" /T
    } else {
        icacls $InstallPath /grant "SYSTEM:(OI)(CI)F" /T
        icacls $DataPath /grant "SYSTEM:(OI)(CI)F" /T
    }
    
    # Give Administrators full control
    icacls $InstallPath /grant "Administrators:(OI)(CI)F" /T
    icacls $DataPath /grant "Administrators:(OI)(CI)F" /T

    # Create the Windows Service
    Write-Host "Creating Windows Service..." -ForegroundColor Yellow
    $ExecutablePath = Join-Path $InstallPath $ExecutableName
    
    if ($ServiceAccount -eq "LocalSystem") {
        $service = New-Service -Name $ServiceName -BinaryPathName $ExecutablePath -DisplayName $DisplayName -Description $Description -StartupType Automatic
    } else {
        if ([string]::IsNullOrEmpty($ServicePassword)) {
            Write-Error "Service password is required when using a domain service account."
            exit 1
        }
        $securePassword = ConvertTo-SecureString $ServicePassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($ServiceAccount, $securePassword)
        $service = New-Service -Name $ServiceName -BinaryPathName $ExecutablePath -DisplayName $DisplayName -Description $Description -StartupType Automatic -Credential $credential
    }

    # Configure service recovery options
    Write-Host "Configuring service recovery options..." -ForegroundColor Yellow
    sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000
    
    # Set service to restart on failure
    sc.exe config $ServiceName start= auto

    # Grant Log on as a service right if using domain account
    if ($ServiceAccount -ne "LocalSystem") {
        Write-Host "Granting 'Log on as a service' right to $ServiceAccount..." -ForegroundColor Yellow
        
        # This requires the Carbon PowerShell module or manual configuration
        # For now, we'll just inform the user
        Write-Warning "Please ensure that '$ServiceAccount' has 'Log on as a service' right in Local Security Policy."
    }

    # Create Event Log source
    Write-Host "Creating Event Log source..." -ForegroundColor Yellow
    try {
        New-EventLog -LogName Application -Source "SaasIdentityAgent" -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Could not create Event Log source. The service will still function but may not log to Event Log."
    }

    # Start the service
    Write-Host "Starting service..." -ForegroundColor Yellow
    Start-Service -Name $ServiceName
    
    # Wait a moment and check service status
    Start-Sleep -Seconds 5
    $serviceStatus = Get-Service -Name $ServiceName
    
    if ($serviceStatus.Status -eq "Running") {
        Write-Host "Service installed and started successfully!" -ForegroundColor Green
        Write-Host "Service Status: $($serviceStatus.Status)" -ForegroundColor Green
    } else {
        Write-Warning "Service installed but not running. Status: $($serviceStatus.Status)"
        Write-Host "Check the Event Log or service logs for more information." -ForegroundColor Yellow
    }

    # Display configuration information
    Write-Host "`nInstallation completed!" -ForegroundColor Green
    Write-Host "Installation Path: $InstallPath" -ForegroundColor Cyan
    Write-Host "Data Path: $DataPath" -ForegroundColor Cyan
    Write-Host "Service Name: $ServiceName" -ForegroundColor Cyan
    Write-Host "Service Account: $ServiceAccount" -ForegroundColor Cyan
    
    Write-Host "`nNext Steps:" -ForegroundColor Yellow
    Write-Host "1. Edit the configuration file: $InstallPath\appsettings.json" -ForegroundColor White
    Write-Host "2. Configure the following settings:" -ForegroundColor White
    Write-Host "   - Agent.AgentId (unique identifier)" -ForegroundColor White
    Write-Host "   - Agent.TenantId (your tenant ID)" -ForegroundColor White
    Write-Host "   - Backend.BaseUrl (SaaS backend URL)" -ForegroundColor White
    Write-Host "   - Backend.ApiKey (API key for authentication)" -ForegroundColor White
    Write-Host "   - ActiveDirectory.DomainName (your AD domain)" -ForegroundColor White
    Write-Host "   - ActiveDirectory.ServiceAccountUsername (AD service account)" -ForegroundColor White
    Write-Host "   - ActiveDirectory.ServiceAccountPassword (AD service account password)" -ForegroundColor White
    Write-Host "3. Restart the service: Restart-Service -Name $ServiceName" -ForegroundColor White
    Write-Host "4. Monitor logs in: $DataLogsPath" -ForegroundColor White

} catch {
    Write-Error "Installation failed: $($_.Exception.Message)"
    Write-Host "Error details: $($_.Exception.ToString())" -ForegroundColor Red
    exit 1
}