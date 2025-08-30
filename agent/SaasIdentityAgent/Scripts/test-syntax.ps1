# Teste de sintaxe para verificar as correções

# Teste de hash table simples
$healthChecks = @()
$healthChecks += @{ Name = "Service Status"; Status = "[OK] Running"; Color = "Green" }
$healthChecks += @{ Name = "Configuration"; Status = "[OK] Found"; Color = "Green" }

# Teste de estrutura WriteTo
$config = @{
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
                "path" = "C:\\logs\\agent-.log"
                "rollingInterval" = "Day"
            }
        }
    )
}

# Teste de mensagens
Write-Host "[SUCCESS] All prerequisites validated successfully" -ForegroundColor Green
Write-Host "[SUCCESS] Service installed and started successfully!" -ForegroundColor Green
Write-Host "[SUCCESS] Validation completed successfully. Ready for deployment." -ForegroundColor Green
Write-Host "[SUCCESS] Deployment completed successfully!" -ForegroundColor Green
Write-Host "[ERROR] Deployment failed!" -ForegroundColor Red

Write-Host "Syntax test completed successfully!" -ForegroundColor Cyan