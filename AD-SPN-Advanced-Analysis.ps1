# Advanced SPN Analysis and Duplicate Detection
# Version 5.0 - ADSI Implementation (No AD Module Required)
# No WinRM Dependencies

#Requires -Version 5.1

param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\AD_Assessment",
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile
)

# Dot source the core infrastructure if not already loaded
if (-not $Global:Config) {
    $CoreScript = Join-Path (Split-Path $MyInvocation.MyCommand.Path) "00-AD-Assessment-Core.ps1"
    if (Test-Path $CoreScript) {
        # Build parameters hash table for splatting
        $CoreParams = @{
            OutputPath = $OutputPath
        }
        
        # Only add ConfigFile if it's not empty
        if (![string]::IsNullOrEmpty($ConfigFile)) {
            $CoreParams['ConfigFile'] = $ConfigFile
        }
        
        # Load core script with splatting
        . $CoreScript @CoreParams
    } else {
        Write-Error "Core infrastructure script not found: $CoreScript"
        exit 1
    }
}

function Get-AdvancedSPNAnalysis {
    Write-Log "=== Starting Advanced SPN Analysis and Duplicate Detection (ADSI) ==="
    
    $ScriptStartTime = Get-Date
    
    # Get domain info
    $DomainInfo = Get-ADSIDomainInfo
    if (!$DomainInfo) {
        Write-Error "Failed to get domain information"
        return
    }
    
    Write-Host "Gathering all Service Principal Names with advanced analysis via ADSI..." -ForegroundColor Yellow
    
    $AllSPNs = @()
    $DuplicateSPNs = @()
    $SPNStatistics = @{}
    
    # Get all objects with SPNs using ADSI
    $SPNProperties = @(
        'serviceprincipalname', 'objectclass', 'name', 'samaccountname', 
        'useraccountcontrol', 'distinguishedname', 'description'
    )
    
    $SPNSearcher = [adsisearcher]"(servicePrincipalName=*)"
    $SPNSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
    $SPNSearcher.PageSize = 1000
    $SPNSearcher.PropertiesToLoad.AddRange($SPNProperties)
    
    try {
        $SPNResults = $SPNSearcher.FindAll()
        $ObjectsWithSPNs = @()
        
        # Build objects collection
        foreach ($SPNResult in $SPNResults) {
            $SPNProps = $SPNResult.Properties
            
            $ObjectsWithSPNs += [PSCustomObject]@{
                Name = if ($SPNProps['name']) { $SPNProps['name'][0] } else { "" }
                SamAccountName = if ($SPNProps['samaccountname']) { $SPNProps['samaccountname'][0] } else { "" }
                ObjectClass = if ($SPNProps['objectclass']) { $SPNProps['objectclass'][-1] } else { "unknown" }  # Get last element (most specific)
                UserAccountControl = if ($SPNProps['useraccountcontrol']) { [int]$SPNProps['useraccountcontrol'][0] } else { 0 }
                DistinguishedName = if ($SPNProps['distinguishedname']) { $SPNProps['distinguishedname'][0] } else { "" }
                Description = if ($SPNProps['description']) { $SPNProps['description'][0] } else { "" }
                ServicePrincipalNames = if ($SPNProps['serviceprincipalname']) { $SPNProps['serviceprincipalname'] } else { @() }
                SPNCount = if ($SPNProps['serviceprincipalname']) { $SPNProps['serviceprincipalname'].Count } else { 0 }
            }
        }
        
        $SPNResults.Dispose()
        $SPNSearcher.Dispose()
        
        Write-Host "Processing $($ObjectsWithSPNs.Count) objects with SPNs..." -ForegroundColor Green
        
        $ProcessedCount = 0
        foreach ($Object in $ObjectsWithSPNs) {
            $ProcessedCount++
            
            if ($ProcessedCount % 20 -eq 0) {
                $PercentComplete = ($ProcessedCount / $ObjectsWithSPNs.Count) * 100
                Write-Progress -Activity "Analyzing Service Principal Names (ADSI)" `
                    -Status "Processing object $ProcessedCount of $($ObjectsWithSPNs.Count)" `
                    -PercentComplete $PercentComplete `
                    -CurrentOperation "Object: $($Object.Name)"
            }
            
            # Get UAC analysis for this object
            $UACAnalysis = Get-UACSummary -UACValue $Object.UserAccountControl
            
            # Determine if object is enabled
            $ObjectEnabled = switch ($Object.ObjectClass) {
                "user" { !$UACAnalysis.IsDisabled }
                "computer" { !$UACAnalysis.IsDisabled }
                default { $true }  # Assume enabled for other object types
            }
            
            foreach ($SPN in $Object.ServicePrincipalNames) {
                # Parse SPN components
                $SPNParts = $SPN -split '/'
                $ServiceClass = $SPNParts[0]
                $ServiceName = if ($SPNParts.Count -gt 1) { $SPNParts[1] } else { "" }
                $Port = ""
                $InstanceName = ""
                
                if ($ServiceName -match '^(.+):(\d+)$') {
                    $ServiceName = $Matches[1]
                    $Port = $Matches[2]
                }
                
                if ($SPNParts.Count -gt 2) {
                    $InstanceName = $SPNParts[2]
                }
                
                # Categorize SPN type
                $SPNCategory = switch -Regex ($ServiceClass) {
                    '^HTTP$' { "Web Services" }
                    '^HTTPS$' { "Web Services" }
                    '^MSSQLSvc$' { "SQL Server" }
                    '^HOST$' { "Host Services" }
                    '^DNS$' { "DNS Services" }
                    '^LDAP$' { "Directory Services" }
                    '^Kerberos$' { "Kerberos" }
                    '^exchangeMDB$' { "Exchange" }
                    '^exchangeAB$' { "Exchange" }
                    '^exchangeRFR$' { "Exchange" }
                    '^SMTP$' { "Mail Services" }
                    '^IMAP$' { "Mail Services" }
                    '^POP$' { "Mail Services" }
                    '^FTP$' { "File Transfer" }
                    '^CIFS$' { "File Services" }
                    '^NFS$' { "File Services" }
                    '^Dfsr-*' { "DFS Replication" }
                    '^TERMSRV$' { "Terminal Services" }
                    '^WSMAN$' { "WS-Management" }
                    '^RestrictedKrbHost$' { "Restricted Kerberos" }
                    '^GC$' { "Global Catalog" }
                    '^E3514235-4B06-11D1-AB04-00C04FC2DCD2$' { "Directory Service Agent" }
                    default { "Other" }
                }
                
                # Risk assessment
                $RiskLevel = "Low"
                $RiskFactors = @()
                
                # High risk factors
                if ($ServiceClass -in @("HTTP", "HTTPS", "MSSQLSvc", "Kerberos")) {
                    $RiskLevel = "Medium"
                    $RiskFactors += "High-value service type"
                }
                
                if ($ServiceClass -eq "HOST" -and $Object.ObjectClass -eq "user") {
                    $RiskLevel = "High"  # User account with HOST SPN is unusual
                    $RiskFactors += "User account with HOST SPN"
                }
                
                # Check for delegation risks using ADUAC analysis
                if ($UACAnalysis.TrustedForDelegation) {
                    $RiskLevel = "High"
                    $RiskFactors += "Unconstrained delegation enabled"
                }
                
                if ($UACAnalysis.TrustedForAuthDelegation) {
                    if ($RiskLevel -eq "Low") { $RiskLevel = "Medium" }
                    $RiskFactors += "Constrained delegation enabled"
                }
                
                # Password policy violations
                if ($UACAnalysis.PasswordNeverExpires -and $Object.ObjectClass -eq "user") {
                    if ($RiskLevel -eq "Low") { $RiskLevel = "Medium" }
                    $RiskFactors += "Password never expires"
                }
                
                if ($UACAnalysis.DontRequirePreauth) {
                    $RiskLevel = "High"
                    $RiskFactors += "Kerberos preauth not required"
                }
                
                if ($UACAnalysis.UseDESKeyOnly) {
                    $RiskLevel = "High"
                    $RiskFactors += "Uses DES encryption only"
                }
                
                # Service account analysis
                $IsServiceAccount = $false
                if ($Object.ObjectClass -eq "user") {
                    foreach ($Pattern in $Global:Config.SecuritySettings.ServiceAccountIdentifiers) {
                        if ($Object.SamAccountName -match $Pattern -or $Object.Description -match $Pattern) {
                            $IsServiceAccount = $true
                            break
                        }
                    }
                }
                
                $SPNObject = [PSCustomObject]@{
                    ServicePrincipalName = $SPN
                    OwnerName = $Object.Name
                    OwnerSamAccountName = $Object.SamAccountName
                    OwnerType = $Object.ObjectClass
                    OwnerEnabled = $ObjectEnabled
                    OwnerDistinguishedName = $Object.DistinguishedName
                    OwnerDescription = $Object.Description
                    ServiceClass = $ServiceClass
                    ServiceName = $ServiceName
                    Port = $Port
                    InstanceName = $InstanceName
                    SPNCategory = $SPNCategory
                    RiskLevel = $RiskLevel
                    RiskFactors = $RiskFactors -join '; '
                    IsServiceAccount = $IsServiceAccount
                    
                    # Enhanced ADUAC Analysis
                    UserAccountControl = $Object.UserAccountControl
                    UACFlags = $UACAnalysis.FlagsString
                    TrustedForDelegation = $UACAnalysis.TrustedForDelegation
                    TrustedForAuthDelegation = $UACAnalysis.TrustedForAuthDelegation
                    PasswordNeverExpires = $UACAnalysis.PasswordNeverExpires
                    DontRequirePreauth = $UACAnalysis.DontRequirePreauth
                    UseDESKeyOnly = $UACAnalysis.UseDESKeyOnly
                    SmartCardRequired = $UACAnalysis.SmartCardRequired
                    
                    # Service-specific analysis
                    IsDatabaseService = $ServiceClass -like "*SQL*"
                    IsWebService = $ServiceClass -in @("HTTP", "HTTPS")
                    IsExchangeService = $ServiceClass -like "exchange*"
                    IsHostService = $ServiceClass -eq "HOST"
                    IsKerberosService = $ServiceClass -eq "Kerberos"
                }
                
                $AllSPNs += $SPNObject
                
                # Track statistics
                if (!$SPNStatistics.ContainsKey($ServiceClass)) {
                    $SPNStatistics[$ServiceClass] = 0
                }
                $SPNStatistics[$ServiceClass]++
            }
        }
        
        Write-Progress -Activity "Analyzing Service Principal Names" -Completed
        
        # Duplicate SPN Detection with configurable threshold
        Write-Host "Checking for duplicate SPNs..." -ForegroundColor Yellow
        
        $SPNGroups = $AllSPNs | Group-Object ServicePrincipalName
        foreach ($SPNGroup in $SPNGroups) {
            if ($SPNGroup.Count -gt $Global:Config.SPNDuplicateThreshold) {
                foreach ($DuplicateSPN in $SPNGroup.Group) {
                    $DuplicateSPNs += [PSCustomObject]@{
                        ServicePrincipalName = $DuplicateSPN.ServicePrincipalName
                        OwnerName = $DuplicateSPN.OwnerName
                        OwnerSamAccountName = $DuplicateSPN.OwnerSamAccountName
                        OwnerType = $DuplicateSPN.OwnerType
                        OwnerEnabled = $DuplicateSPN.OwnerEnabled
                        ServiceClass = $DuplicateSPN.ServiceClass
                        ServiceName = $DuplicateSPN.ServiceName
                        SPNCategory = $DuplicateSPN.SPNCategory
                        IssueType = "Duplicate SPN"
                        Severity = "High"
                        IssueDescription = "SPN exists on $($SPNGroup.Count) different objects"
                        TotalDuplicates = $SPNGroup.Count
                        RiskLevel = $DuplicateSPN.RiskLevel
                        RiskFactors = $DuplicateSPN.RiskFactors
                        RecommendedAction = "Remove duplicate SPN registrations to prevent authentication failures"
                        Impact = "May cause Kerberos authentication failures or service unavailability"
                    }
                }
            }
        }
        
        # Export results (PowerBI-optimized naming)
        $AllSPNs | Export-Csv "$Global:OutputPath\SPNs_Advanced_Analysis.csv" -NoTypeInformation
        
        if ($DuplicateSPNs.Count -gt 0) {
            $DuplicateSPNs | Export-Csv "$Global:OutputPath\SPNs_Duplicate.csv" -NoTypeInformation
        } else {
            # Create empty file to indicate assessment was run
            @() | Export-Csv "$Global:OutputPath\SPNs_Duplicate.csv" -NoTypeInformation
        }
        
        # SPN Statistics by Service Class
        $SPNStats = @()
        foreach ($ServiceClass in $SPNStatistics.Keys) {
            $ClassSPNs = $AllSPNs | Where-Object {$_.ServiceClass -eq $ServiceClass}
            $HighRiskCount = ($ClassSPNs | Where-Object {$_.RiskLevel -eq "High"}).Count
            $MediumRiskCount = ($ClassSPNs | Where-Object {$_.RiskLevel -eq "Medium"}).Count
            $DuplicateCount = ($DuplicateSPNs | Where-Object {$_.ServiceClass -eq $ServiceClass}).Count
            
            $SPNStats += [PSCustomObject]@{
                ServiceClass = $ServiceClass
                Count = $SPNStatistics[$ServiceClass]
                PercentageOfTotal = [math]::Round(($SPNStatistics[$ServiceClass] / $AllSPNs.Count) * 100, 2)
                HighRiskCount = $HighRiskCount
                MediumRiskCount = $MediumRiskCount
                DuplicateCount = $DuplicateCount
                Category = ($ClassSPNs | Select-Object -First 1).SPNCategory
                CommonOwnerType = ($ClassSPNs | Group-Object OwnerType | Sort-Object Count -Descending | Select-Object -First 1).Name
            }
        }
        
        $SPNStats | Sort-Object Count -Descending | Export-Csv "$Global:OutputPath\SPNs_Statistics.csv" -NoTypeInformation
        
        # High-Risk SPNs Report
        $HighRiskSPNs = $AllSPNs | Where-Object {$_.RiskLevel -eq "High"}
        if ($HighRiskSPNs.Count -gt 0) {
            $HighRiskSPNs | Export-Csv "$Global:OutputPath\SPNs_High_Risk.csv" -NoTypeInformation
        }
        
        # Service Account SPNs Analysis
        $ServiceAccountSPNs = $AllSPNs | Where-Object {$_.IsServiceAccount -eq $true}
        if ($ServiceAccountSPNs.Count -gt 0) {
            $ServiceAccountSPNs | Export-Csv "$Global:OutputPath\SPNs_Service_Accounts.csv" -NoTypeInformation
        }
        
        # SPNs by Category Report
        $SPNsByCategory = $AllSPNs | Group-Object SPNCategory | ForEach-Object {
            [PSCustomObject]@{
                Category = $_.Name
                Count = $_.Count
                HighRiskCount = ($_.Group | Where-Object {$_.RiskLevel -eq "High"}).Count
                DuplicateCount = ($DuplicateSPNs | Where-Object {$_.SPNCategory -eq $_.Name}).Count
                CommonServiceClasses = ($_.Group | Group-Object ServiceClass | Sort-Object Count -Descending | Select-Object -First 3).Name -join '; '
                PercentageOfTotal = [math]::Round(($_.Count / $AllSPNs.Count) * 100, 2)
            }
        } | Sort-Object Count -Descending
        
        $SPNsByCategory | Export-Csv "$Global:OutputPath\SPNs_By_Category.csv" -NoTypeInformation
        
        # Delegation Analysis Report
        $DelegationSPNs = $AllSPNs | Where-Object {$_.TrustedForDelegation -eq $true -or $_.TrustedForAuthDelegation -eq $true}
        if ($DelegationSPNs.Count -gt 0) {
            $DelegationSPNs | Export-Csv "$Global:OutputPath\SPNs_With_Delegation.csv" -NoTypeInformation
        }
        
        # Summary Statistics
        $SPNSummary = [PSCustomObject]@{
            TotalSPNs = $AllSPNs.Count
            UniqueObjectsWithSPNs = $ObjectsWithSPNs.Count
            UniqueSPNTypes = ($AllSPNs | Select-Object -ExpandProperty ServiceClass -Unique).Count
            UniqueCategories = ($AllSPNs | Select-Object -ExpandProperty SPNCategory -Unique).Count
            DuplicateSPNs = ($DuplicateSPNs | Select-Object -ExpandProperty ServicePrincipalName -Unique).Count
            HighRiskSPNs = ($AllSPNs | Where-Object {$_.RiskLevel -eq "High"}).Count
            MediumRiskSPNs = ($AllSPNs | Where-Object {$_.RiskLevel -eq "Medium"}).Count
            ServiceAccountSPNs = $ServiceAccountSPNs.Count
            DelegationEnabledSPNs = $DelegationSPNs.Count
            UnconstrainedDelegationSPNs = ($AllSPNs | Where-Object {$_.TrustedForDelegation -eq $true}).Count
            ConstrainedDelegationSPNs = ($AllSPNs | Where-Object {$_.TrustedForAuthDelegation -eq $true}).Count
            WebServiceSPNs = ($AllSPNs | Where-Object {$_.IsWebService -eq $true}).Count
            DatabaseServiceSPNs = ($AllSPNs | Where-Object {$_.IsDatabaseService -eq $true}).Count
            ExchangeServiceSPNs = ($AllSPNs | Where-Object {$_.IsExchangeService -eq $true}).Count
            ProcessingTime = ((Get-Date) - $ScriptStartTime).TotalMinutes
            UsedADSI = $true
            RequiredWinRM = $false
        }
        
        $SPNSummary | Export-Csv "$Global:OutputPath\SPNs_Summary_Stats.csv" -NoTypeInformation
        
        Write-Log "Advanced SPN analysis completed. Found $($AllSPNs.Count) SPNs, $($DuplicateSPNs.Count) duplicates"
        Write-Log "SPN analysis completed in $([math]::Round($SPNSummary.ProcessingTime, 2)) minutes"
        
    } catch {
        Write-Log "Critical error in SPN analysis: $($_.Exception.Message)"
        throw
    } finally {
        [GC]::Collect()
    }
}

# Execute the assessment if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Get-AdvancedSPNAnalysis
    Write-Host "Advanced SPN Analysis completed. Results in: $Global:OutputPath" -ForegroundColor Green
}
