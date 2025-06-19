# Diagnostic script for DC Infrastructure Assessment
# This will help identify why searches are returning no results

param(
    [string]$OutputPath = "C:\AD_Assessment"
)

Write-Host "=== DC Infrastructure Diagnostic ===" -ForegroundColor Cyan
Write-Host ""

# Load core if needed
if (-not $Global:Config) {
    $CoreScript = Join-Path (Split-Path $MyInvocation.MyCommand.Path) "00-AD-Assessment-Core.ps1"
    if (Test-Path $CoreScript) {
        . $CoreScript -OutputPath $OutputPath
    }
}

# Get domain info
$DomainInfo = Get-ADSIDomainInfo
Write-Host "Domain Info Retrieved:" -ForegroundColor Yellow
Write-Host "  Domain DN: $($DomainInfo.DomainDN)" -ForegroundColor White
Write-Host "  Domain Name: $($DomainInfo.DomainName)" -ForegroundColor White
Write-Host ""

# Test 1: Check Configuration Naming Context
Write-Host "Test 1: Checking Configuration Naming Context..." -ForegroundColor Yellow
try {
    $RootDSE = [ADSI]"LDAP://RootDSE"
    $ConfigDN = $RootDSE.configurationNamingContext[0]
    Write-Host "  Config DN: $ConfigDN" -ForegroundColor Green
    
    # Try to connect to it
    $ConfigContainer = [ADSI]"LDAP://$ConfigDN"
    Write-Host "  Successfully connected to Config container" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
}

# Test 2: Check for Partitions Container
Write-Host "`nTest 2: Checking Partitions Container..." -ForegroundColor Yellow
try {
    $PartitionsPath = "LDAP://CN=Partitions,$ConfigDN"
    Write-Host "  Trying to connect to: $PartitionsPath" -ForegroundColor Gray
    
    $PartitionsContainer = [ADSI]$PartitionsPath
    Write-Host "  Successfully connected to Partitions container" -ForegroundColor Green
    
    # Try searching
    $PartitionsSearcher = [adsisearcher]"(objectClass=crossRef)"
    $PartitionsSearcher.SearchRoot = $PartitionsContainer
    $PartitionsSearcher.PageSize = 10
    
    $Results = $PartitionsSearcher.FindAll()
    Write-Host "  Found $($Results.Count) crossRef objects" -ForegroundColor Green
    
    if ($Results.Count -gt 0) {
        Write-Host "  Sample crossRef objects:" -ForegroundColor Gray
        $i = 0
        foreach ($Result in $Results) {
            if ($i -ge 3) { break }
            $Props = $Result.Properties
            $Name = if ($Props['name']) { $Props['name'][0] } else { "No name" }
            Write-Host "    - $Name" -ForegroundColor White
            $i++
        }
    }
    
    $Results.Dispose()
    $PartitionsSearcher.Dispose()
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
}

# Test 3: Check Sites Container
Write-Host "`nTest 3: Checking Sites Container..." -ForegroundColor Yellow
try {
    $SitesPath = "LDAP://CN=Sites,$ConfigDN"
    Write-Host "  Trying to connect to: $SitesPath" -ForegroundColor Gray
    
    $SitesContainer = [ADSI]$SitesPath
    Write-Host "  Successfully connected to Sites container" -ForegroundColor Green
    
    # List immediate children
    Write-Host "  Immediate children of Sites container:" -ForegroundColor Gray
    foreach ($Child in $SitesContainer.Children) {
        $ChildName = $Child.Name
        $ChildClass = $Child.SchemaClassName
        Write-Host "    - $ChildName (Class: $ChildClass)" -ForegroundColor White
    }
    
    # Try searching for sites
    $SitesSearcher = [adsisearcher]"(objectClass=site)"
    $SitesSearcher.SearchRoot = $SitesContainer
    $SitesSearcher.PageSize = 10
    
    $SiteResults = $SitesSearcher.FindAll()
    Write-Host "  Found $($SiteResults.Count) site objects" -ForegroundColor Green
    
    if ($SiteResults.Count -gt 0) {
        foreach ($Site in $SiteResults) {
            $SiteName = if ($Site.Properties['name']) { $Site.Properties['name'][0] } else { "Unknown" }
            Write-Host "    - Site: $SiteName" -ForegroundColor White
        }
    }
    
    $SiteResults.Dispose()
    $SitesSearcher.Dispose()
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
}

# Test 4: Check Domain Controllers
Write-Host "`nTest 4: Checking Domain Controllers..." -ForegroundColor Yellow
try {
    # Method 1: Using userAccountControl
    Write-Host "  Method 1: Searching by userAccountControl flag..." -ForegroundColor Gray
    $DCSearcher = [adsisearcher]"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
    $DCSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
    $DCSearcher.PageSize = 100
    
    $DCResults = $DCSearcher.FindAll()
    Write-Host "  Found $($DCResults.Count) DCs using UAC flag" -ForegroundColor Green
    
    foreach ($DC in $DCResults) {
        $DCName = if ($DC.Properties['name']) { $DC.Properties['name'][0] } else { "Unknown" }
        Write-Host "    - DC: $DCName" -ForegroundColor White
    }
    
    $DCResults.Dispose()
    $DCSearcher.Dispose()
    
    # Method 2: Using Domain Controllers OU
    Write-Host "`n  Method 2: Checking Domain Controllers OU..." -ForegroundColor Gray
    $DCOUPath = "LDAP://OU=Domain Controllers,$($DomainInfo.DomainDN)"
    try {
        $DCOU = [ADSI]$DCOUPath
        Write-Host "  Successfully connected to Domain Controllers OU" -ForegroundColor Green
        
        $DCOUSearcher = [adsisearcher]"(objectClass=computer)"
        $DCOUSearcher.SearchRoot = $DCOU
        $DCOUResults = $DCOUSearcher.FindAll()
        Write-Host "  Found $($DCOUResults.Count) computers in Domain Controllers OU" -ForegroundColor Green
        
        $DCOUResults.Dispose()
        $DCOUSearcher.Dispose()
    } catch {
        Write-Host "  Could not access Domain Controllers OU: $_" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
}

# Test 5: Check Schema Container
Write-Host "`nTest 5: Checking Schema Container..." -ForegroundColor Yellow
try {
    $SchemaDN = $RootDSE.schemaNamingContext[0]
    $SchemaPath = "LDAP://$SchemaDN"
    Write-Host "  Schema DN: $SchemaDN" -ForegroundColor Gray
    
    $SchemaContainer = [ADSI]$SchemaPath
    Write-Host "  Successfully connected to Schema container" -ForegroundColor Green
    
    # Try to get schema version
    $SchemaSearcher = [adsisearcher]"(objectClass=dMD)"
    $SchemaSearcher.SearchRoot = $SchemaContainer
    $SchemaSearcher.PropertiesToLoad.Add('objectversion')
    
    $SchemaResults = $SchemaSearcher.FindAll()
    if ($SchemaResults.Count -gt 0) {
        $Version = if ($SchemaResults[0].Properties['objectversion']) {
            $SchemaResults[0].Properties['objectversion'][0]
        } else { "Not found" }
        Write-Host "  Schema Version: $Version" -ForegroundColor Green
    }
    
    $SchemaResults.Dispose()
    $SchemaSearcher.Dispose()
    
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
}

# Test 6: Check System Container for Trusts
Write-Host "`nTest 6: Checking System Container for Trusts..." -ForegroundColor Yellow
try {
    $SystemPath = "LDAP://CN=System,$($DomainInfo.DomainDN)"
    Write-Host "  Trying to connect to: $SystemPath" -ForegroundColor Gray
    
    $SystemContainer = [ADSI]$SystemPath
    Write-Host "  Successfully connected to System container" -ForegroundColor Green
    
    # Search for trusts
    $TrustSearcher = [adsisearcher]"(objectClass=trustedDomain)"
    $TrustSearcher.SearchRoot = $SystemContainer
    $TrustSearcher.PageSize = 10
    
    $TrustResults = $TrustSearcher.FindAll()
    Write-Host "  Found $($TrustResults.Count) trust relationships" -ForegroundColor Green
    
    if ($TrustResults.Count -gt 0) {
        foreach ($Trust in $TrustResults) {
            $TrustName = if ($Trust.Properties['name']) { $Trust.Properties['name'][0] } else { "Unknown" }
            Write-Host "    - Trust: $TrustName" -ForegroundColor White
        }
    }
    
    $TrustResults.Dispose()
    $TrustSearcher.Dispose()
    
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
}

# Test 7: Check Inter-Site Transports
Write-Host "`nTest 7: Checking Inter-Site Transports..." -ForegroundColor Yellow
try {
    $TransportsPath = "LDAP://CN=Inter-Site Transports,CN=Sites,$ConfigDN"
    Write-Host "  Trying to connect to: $TransportsPath" -ForegroundColor Gray
    
    $TransportsContainer = [ADSI]$TransportsPath
    Write-Host "  Successfully connected to Inter-Site Transports" -ForegroundColor Green
    
    # List transport containers
    Write-Host "  Transport containers:" -ForegroundColor Gray
    foreach ($Transport in $TransportsContainer.Children) {
        $TransportName = $Transport.Name
        Write-Host "    - $TransportName" -ForegroundColor White
        
        # Check for site links in this transport
        $LinkSearcher = [adsisearcher]"(objectClass=siteLink)"
        $LinkSearcher.SearchRoot = $Transport
        $LinkResults = $LinkSearcher.FindAll()
        Write-Host "      Found $($LinkResults.Count) site links" -ForegroundColor Gray
        
        $LinkResults.Dispose()
        $LinkSearcher.Dispose()
    }
    
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
}

Write-Host "`n=== Diagnostic Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor Yellow
Write-Host "- If you see errors above, it may indicate permission issues or missing containers" -ForegroundColor White
Write-Host "- Zero results may indicate the searches are looking in the wrong locations" -ForegroundColor White
Write-Host "- Check that you have appropriate permissions to read configuration partition" -ForegroundColor White
