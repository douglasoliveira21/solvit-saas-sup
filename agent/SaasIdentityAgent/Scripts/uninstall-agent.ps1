<#
.SYNOPSIS
    Uninstalls the SaaS Identity Management Agent Windows Service

.DESCRIPTION
    This script stops and removes the SaaS Identity Management Agent
    Windows Service and optionally removes installation files.

.PARAMETER RemoveFiles
    Remove installation files and data (default: false)

.PARAMETER RemoveLogs
    Remove log files (default: false)

.PARAMETER InstallPath
    Installation directory (default: C:\Program Files\SaasIdentityAgent)

.EXAMPLE
    .\uninstall-agent.ps1
    
.EXAMPLE
    .\uninstall-agent.ps1 -RemoveFiles -RemoveLogs
#>

param(
    [switch]$RemoveFiles = $false,
    [switch]$RemoveLogs = $false,
    [string]$InstallPath = "C:\Program Files\SaasIdentityAgent"
)

# Requires Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

$ServiceName = "SaasIdentityAgent"
$DataPath = "C:\ProgramData\SaasIdentityAgent"

Write-Host "Uninstalling SaaS Identity Management Agent..." -ForegroundColor Yellow

try {
    # Check if service exists
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if ($service) {
        Write-Host "Found service: $($service.DisplayName)" -ForegroundColor Cyan
        
        # Stop the service if running
        if ($service.Status -eq "Running") {
            Write-Host "Stopping service..." -ForegroundColor Yellow
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            
            # Wait for service to stop
            $timeout = 30
            $elapsed = 0
            while ((Get-Service -Name $ServiceName).Status -eq "Running" -and $elapsed -lt $timeout) {
                Start-Sleep -Seconds 1
                $elapsed++
            }
            
            if ((Get-Service -Name $ServiceName).Status -eq "Running") {
                Write-Warning "Service did not stop within $timeout seconds. Forcing termination..."
                # Force kill the process if needed
                $processes = Get-Process -Name "SaasIdentityAgent" -ErrorAction SilentlyContinue
                if ($processes) {
                    $processes | Stop-Process -Force
                }
            } else {
                Write-Host "Service stopped successfully." -ForegroundColor Green
            }
        }
        
        # Remove the service
        Write-Host "Removing Windows Service..." -ForegroundColor Yellow
        sc.exe delete $ServiceName
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Service removed successfully." -ForegroundColor Green
        } else {
            Write-Warning "Failed to remove service. Exit code: $LASTEXITCODE"
        }
        
    } else {
        Write-Host "Service not found. It may have already been removed." -ForegroundColor Yellow
    }
    
    # Remove Event Log source
    Write-Host "Removing Event Log source..." -ForegroundColor Yellow
    try {
        Remove-EventLog -Source "SaasIdentityAgent" -ErrorAction SilentlyContinue
        Write-Host "Event Log source removed." -ForegroundColor Green
    } catch {
        Write-Warning "Could not remove Event Log source: $($_.Exception.Message)"
    }
    
    # Remove installation files if requested
    if ($RemoveFiles) {
        Write-Host "Removing installation files..." -ForegroundColor Yellow
        
        if (Test-Path $InstallPath) {
            try {
                Remove-Item -Path $InstallPath -Recurse -Force
                Write-Host "Installation files removed from: $InstallPath" -ForegroundColor Green
            } catch {
                Write-Warning "Could not remove installation files: $($_.Exception.Message)"
                Write-Host "You may need to manually delete: $InstallPath" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Installation directory not found: $InstallPath" -ForegroundColor Yellow
        }
        
        # Remove data directory
        if (Test-Path $DataPath) {
            try {
                if ($RemoveLogs) {
                    Remove-Item -Path $DataPath -Recurse -Force
                    Write-Host "Data directory removed: $DataPath" -ForegroundColor Green
                } else {
                    # Keep logs but remove other data
                    $logsPath = Join-Path $DataPath "logs"
                    Get-ChildItem -Path $DataPath -Exclude "logs" | Remove-Item -Recurse -Force
                    Write-Host "Data directory cleaned (logs preserved): $DataPath" -ForegroundColor Green
                }
            } catch {
                Write-Warning "Could not remove data directory: $($_.Exception.Message)"
                Write-Host "You may need to manually delete: $DataPath" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "Installation files preserved. Use -RemoveFiles to remove them." -ForegroundColor Cyan
        Write-Host "Installation Path: $InstallPath" -ForegroundColor Cyan
        Write-Host "Data Path: $DataPath" -ForegroundColor Cyan
    }
    
    # Remove logs if requested
    if ($RemoveLogs -and -not $RemoveFiles) {
        $logsPath = Join-Path $DataPath "logs"
        if (Test-Path $logsPath) {
            try {
                Remove-Item -Path $logsPath -Recurse -Force
                Write-Host "Log files removed from: $logsPath" -ForegroundColor Green
            } catch {
                Write-Warning "Could not remove log files: $($_.Exception.Message)"
            }
        }
    }
    
    Write-Host "`nUninstallation completed successfully!" -ForegroundColor Green
    
    if (-not $RemoveFiles) {
        Write-Host "`nNote: Installation files have been preserved." -ForegroundColor Yellow
        Write-Host "To completely remove all files, run: .\uninstall-agent.ps1 -RemoveFiles -RemoveLogs" -ForegroundColor Yellow
    }
    
} catch {
    Write-Error "Uninstallation failed: $($_.Exception.Message)"
    Write-Host "Error details: $($_.Exception.ToString())" -ForegroundColor Red
    exit 1
}