# Test script to diagnose password policy retrieval issues
# This will show exactly what ADSI is returning

Write-Host "Password Policy Diagnostic Test" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host ""

try {
    # Connect to domain
    Write-Host "Connecting to domain..." -ForegroundColor Yellow
    $RootDSE = [ADSI]"LDAP://RootDSE"
    $DomainDN = $RootDSE.defaultNamingContext[0]
    Write-Host "Domain DN: $DomainDN" -ForegroundColor Green
    
    $Domain = [ADSI]"LDAP://$DomainDN"
    Write-Host "Connected successfully!" -ForegroundColor Green
    Write-Host ""
    
    # Test each property individually
    Write-Host "Testing individual properties:" -ForegroundColor Yellow
    Write-Host "------------------------------" -ForegroundColor Yellow
    
    # Test maxPwdAge
    Write-Host "`nTesting maxPwdAge:" -ForegroundColor White
    try {
        $maxPwdAgeRaw = $Domain.maxPwdAge
        Write-Host "  Raw value type: $($maxPwdAgeRaw.GetType().FullName)" -ForegroundColor Gray
        
        if ($maxPwdAgeRaw) {
            if ($maxPwdAgeRaw -is [System.__ComObject]) {
                Write-Host "  Value is a COM object - attempting to read..." -ForegroundColor Yellow
                # Try different methods to read the value
                try {
                    $value = $Domain.InvokeGet("maxPwdAge")
                    Write-Host "  InvokeGet value: $value" -ForegroundColor Green
                    Write-Host "  InvokeGet type: $($value.GetType().FullName)" -ForegroundColor Gray
                }
                catch {
                    Write-Host "  InvokeGet failed: $_" -ForegroundColor Red
                }
            }
            elseif ($maxPwdAgeRaw -is [System.Int64[]]) {
                Write-Host "  Value is Int64 array: $($maxPwdAgeRaw[0])" -ForegroundColor Green
            }
            elseif ($maxPwdAgeRaw -is [System.Int64]) {
                Write-Host "  Value is Int64: $maxPwdAgeRaw" -ForegroundColor Green
            }
            else {
                Write-Host "  Unknown type, value: $maxPwdAgeRaw" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "  No value returned" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  Error: $_" -ForegroundColor Red
    }
    
    # Test minPwdLength
    Write-Host "`nTesting minPwdLength:" -ForegroundColor White
    try {
        $minPwdLength = $Domain.minPwdLength
        Write-Host "  Raw value: $minPwdLength" -ForegroundColor Green
        Write-Host "  Type: $($minPwdLength.GetType().FullName)" -ForegroundColor Gray
        if ($minPwdLength -is [System.Array]) {
            Write-Host "  Array value[0]: $($minPwdLength[0])" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  Error: $_" -ForegroundColor Red
    }
    
    # Test pwdHistoryLength
    Write-Host "`nTesting pwdHistoryLength:" -ForegroundColor White
    try {
        $pwdHistoryLength = $Domain.pwdHistoryLength
        Write-Host "  Raw value: $pwdHistoryLength" -ForegroundColor Green
        Write-Host "  Type: $($pwdHistoryLength.GetType().FullName)" -ForegroundColor Gray
        if ($pwdHistoryLength -is [System.Array]) {
            Write-Host "  Array value[0]: $($pwdHistoryLength[0])" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  Error: $_" -ForegroundColor Red
    }
    
    # Test lockoutThreshold
    Write-Host "`nTesting lockoutThreshold:" -ForegroundColor White
    try {
        $lockoutThreshold = $Domain.lockoutThreshold
        Write-Host "  Raw value: $lockoutThreshold" -ForegroundColor Green
        Write-Host "  Type: $($lockoutThreshold.GetType().FullName)" -ForegroundColor Gray
        if ($lockoutThreshold -is [System.Array]) {
            Write-Host "  Array value[0]: $($lockoutThreshold[0])" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  Error: $_" -ForegroundColor Red
    }
    
    # Try alternative method using DirectoryEntry
    Write-Host "`n`nTrying alternative method with DirectoryEntry:" -ForegroundColor Yellow
    Write-Host "----------------------------------------------" -ForegroundColor Yellow
    
    $DE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainDN")
    
    Write-Host "`nUsing Properties collection:" -ForegroundColor White
    foreach ($propName in @("maxPwdAge", "minPwdLength", "pwdHistoryLength", "lockoutThreshold")) {
        try {
            $prop = $DE.Properties[$propName]
            if ($prop -and $prop.Count -gt 0) {
                Write-Host "  $propName : $($prop[0]) (Type: $($prop[0].GetType().FullName))" -ForegroundColor Green
            }
            else {
                Write-Host "  $propName : No value" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "  $propName : Error - $_" -ForegroundColor Red
        }
    }
    
    $DE.Close()
    
}
catch {
    Write-Error "Test failed: $_"
    Write-Host ""
    Write-Host "Stack trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}

Write-Host ""
Write-Host "Test complete!" -ForegroundColor Cyan
