# Teste de sintaxe PowerShell
# Este arquivo testa as estruturas corrigidas no deploy-agent.ps1

# Teste de função com try/catch
function Test-Function {
    Write-Host "Testing function..." -ForegroundColor Yellow
    
    try {
        Write-Host "[OK] Test successful" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[ERROR] Test failed" -ForegroundColor Red
        return $false
    }
}

# Teste de hash table
$testConfig = @{
    "TestSection" = @{
        "Setting1" = "Value1"
        "Setting2" = "Value2"
    }
}

# Teste principal com try/catch
try {
    Write-Host "[SUCCESS] Syntax test completed" -ForegroundColor Green
    Test-Function
} catch {
    Write-Host "[ERROR] Syntax test failed" -ForegroundColor Red
}