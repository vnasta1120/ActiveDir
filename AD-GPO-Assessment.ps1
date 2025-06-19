# Group Policy Assessment with ADSI Implementation
# Version 5.0 - ADSI Implementation (No AD Module Required)
# No WinRM Dependencies

#Requires -Version 5.1

param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\AD_Assessment",
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile
)

# Dot source the core infrastructure (always reload for fresh variables)
if ($true) {  # Changed from if (-not $Global:Config) to force reload
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

function Get-GPOAssessment {
    Write-Log "=== Starting Group Policy Assessment (ADSI) ==="
    
    $ScriptStartTime = Get-Date
    
    # Get domain info
    $DomainInfo = Get-ADSIDomainInfo
    if (!$DomainInfo) {
        Write-Error "Failed to get domain information"
        return
    }
    
    try {
        # 1. Get all Group Policy Objects
        Write-Host "Getting all Group Policy Objects via ADSI..." -ForegroundColor Yellow
        
        $GPODetails = @()
        $GPOProperties = @(
            'name', 'displayname', 'distinguishedname', 'whencreated', 'whenchanged',
            'gpcfilesyspath', 'gpcfunctionality', 'flags', 'versionnumber'
        )
        
        $GPOSearcher = [adsisearcher]"(objectClass=groupPolicyContainer)"
        $GPOSearcher.SearchRoot = [ADSI]"LDAP://CN=Policies,CN=System,$($DomainInfo.DomainDN)"
        $GPOSearcher.PageSize = 100
        $GPOSearcher.PropertiesToLoad.AddRange($GPOProperties)
        
        $GPOResults = $GPOSearcher.FindAll()
        $TotalGPOs = $GPOResults.Count
        Write-Log "Found $TotalGPOs GPOs"
        
        $ProcessedCount = 0
        
        foreach ($GPOResult in $GPOResults) {
            $ProcessedCount++
            
            if ($ProcessedCount % $Global:Config.ComputerProgressInterval -eq 0) {
                $PercentComplete = ($ProcessedCount / $TotalGPOs) * 100
                $ETA = Get-ETA -Current $ProcessedCount -Total $TotalGPOs -StartTime $ScriptStartTime
                
                Write-Progress -Activity "Processing GPOs (ADSI)" `
                    -Status "Processing GPO $ProcessedCount of $TotalGPOs - ETA: $ETA" `
                    -PercentComplete $PercentComplete `
                    -CurrentOperation "GPO: $($GPOResult.Properties['displayname'][0])"
            }
            
            try {
                $GPOProps = $GPOResult.Properties
                
                $GPOName = if ($GPOProps['displayname']) { $GPOProps['displayname'][0] } else { 
                    if ($GPOProps['name']) { $GPOProps['name'][0] } else { "Unknown" }
                }
                $GPOID = if ($GPOProps['name']) { $GPOProps['name'][0] } else { "" }
                $GPODistinguishedName = if ($GPOProps['distinguishedname']) { $GPOProps['distinguishedname'][0] } else { "" }
                $CreatedTime = ConvertTo-DateTime -Value $GPOProps['whencreated'][0] -Format "GeneralizedTime"
                $ModifiedTime = ConvertTo-DateTime -Value $GPOProps['whenchanged'][0] -Format "GeneralizedTime"
                $FileSysPath = if ($GPOProps['gpcfilesyspath']) { $GPOProps['gpcfilesyspath'][0] } else { "" }
                $GPCFunctionality = if ($GPOProps['gpcfunctionality']) { $GPOProps['gpcfunctionality'][0] } else { 0 }
                $Flags = if ($GPOProps['flags']) { $GPOProps['flags'][0] } else { 0 }
                $VersionNumber = if ($GPOProps['versionnumber']) { $GPOProps['versionnumber'][0] } else { 0 }
                
                # Determine GPO status from flags
                $GPOStatus = switch ($Flags) {
                    0 { "Enabled" }
                    1 { "User Configuration Disabled" }
                    2 { "Computer Configuration Disabled" }
                    3 { "All Settings Disabled" }
                    default { "Unknown" }
                }
                
                # Check for GPO links by searching gPLink attributes
                $GPOLinks = @()
                $LinksCount = 0
                
                try {
                    # Search for objects that link to this GPO
                    $LinkSearcher = [adsisearcher]"(gPLink=*$GPOID*)"
                    $LinkSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
                    $LinkSearcher.PageSize = 100
                    $LinkSearcher.PropertiesToLoad.AddRange(@('distinguishedname', 'name', 'gplink'))
                    
                    $LinkResults = $LinkSearcher.FindAll()
                    
                    foreach ($LinkResult in $LinkResults) {
                        $LinkProps = $LinkResult.Properties
                        $LinkDN = $LinkProps['distinguishedname'][0]
                        $LinkName = if ($LinkProps['name']) { $LinkProps['name'][0] } else { "Unknown" }
                        
                        $GPOLinks += $LinkName
                    }
                    
                    $LinksCount = $LinkResults.Count
                    $LinkResults.Dispose()
                    $LinkSearcher.Dispose()
                    
                } catch {
                    # GPO link detection failed - not critical
                }
                
                # Basic settings count estimation (without WinRM, this is limited)
                $ComputerSettingsCount = 0
                $UserSettingsCount = 0
                $TotalSettings = 0
                
                # Estimate based on GPC functionality flags
                if ($GPCFunctionality -band 1) { $ComputerSettingsCount = 1 }  # Computer settings present
                if ($GPCFunctionality -band 2) { $UserSettingsCount = 1 }      # User settings present
                $TotalSettings = $ComputerSettingsCount + $UserSettingsCount
                
                # Check for scripts (limited without file system access)
                $HasScripts = $false
                $ScriptCount = 0
                $ScriptTypes = ""
                
                # Age analysis
                $AgeInDays = if ($ModifiedTime) { (Get-Date) - $ModifiedTime } else { $null }
                $IsStale = $AgeInDays -and $AgeInDays.TotalDays -gt 365
                
                $GPOObject = [PSCustomObject]@{
                    GPOName = $GPOName
                    GPOId = $GPOID
                    Description = ""  # Not easily available via ADSI
                    CreatedTime = $CreatedTime
                    ModifiedTime = $ModifiedTime
                    Status = $GPOStatus
                    Flags = $Flags
                    VersionNumber = $VersionNumber
                    GpcFunctionality = $GPCFunctionality
                    FileSysPath = $FileSysPath
                    ComputerSettingsCount = $ComputerSettingsCount
                    UserSettingsCount = $UserSettingsCount
                    TotalSettings = $TotalSettings
                    LinksCount = $LinksCount
                    LinkedOUs = $GPOLinks -join '; '
                    IsLinked = $LinksCount -gt 0
                    HasScripts = $HasScripts
                    ScriptCount = $ScriptCount
                    ScriptTypes = $ScriptTypes
                    AgeInDays = if ($AgeInDays) { [math]::Round($AgeInDays.TotalDays) } else { $null }
                    IsStale = $IsStale
                    DistinguishedName = $GPODistinguishedName
                    AssessmentMethod = "ADSI"
                    AssessmentLimitations = "Limited settings analysis without file system access"
                }
                
                $GPODetails += $GPOObject
                
            } catch {
                Write-Log "Error processing GPO: $($_.Exception.Message)"
            }
        }
        
        $GPOResults.Dispose()
        $GPOSearcher.Dispose()
        
        Write-Progress -Activity "Processing GPOs" -Completed
        
        # Export GPO details
        $GPODetails | Export-Csv "$Global:OutputPath\GPO_Details.csv" -NoTypeInformation
        
        # 2. Get domain-level GPO links
        Write-Host "Checking domain and root-level GPO links..." -ForegroundColor Yellow
        
        $DomainLinks = @()
        try {
            # Get domain root gPLink
            $DomainSearcher = [adsisearcher]"(distinguishedName=$($DomainInfo.DomainDN))"
            $DomainSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
            $DomainSearcher.PropertiesToLoad.Add('gplink')
            
            $DomainResults = $DomainSearcher.FindAll()
            
            if ($DomainResults.Count -gt 0 -and $DomainResults[0].Properties['gplink']) {
                $GPLinks = $DomainResults[0].Properties['gplink'][0]
                
                # Parse gPLink attribute (format: [LDAP://cn={GUID},cn=policies,cn=system,DC=domain,DC=com;0])
                $LinkPattern = '\[LDAP://cn=\{([^}]+)\}[^;]*;(\d+)\]'
                $Matches = [regex]::Matches($GPLinks, $LinkPattern)
                
                foreach ($Match in $Matches) {
                    $GPOGUID = $Match.Groups[1].Value
                    $LinkOptions = [int]$Match.Groups[2].Value
                    
                    # Find the GPO name from our GPO details
                    $LinkedGPO = $GPODetails | Where-Object {$_.GPOId -eq "{$GPOGUID}"}
                    $GPODisplayName = if ($LinkedGPO) { $LinkedGPO.GPOName } else { "Unknown GPO" }
                    
                    $DomainLinks += [PSCustomObject]@{
                        Target = "Domain Root"
                        TargetDN = $DomainInfo.DomainDN
                        GPOName = $GPODisplayName
                        GPOID = "{$GPOGUID}"
                        Enabled = ($LinkOptions -band 1) -eq 0  # Link is enabled if bit 0 is not set
                        Enforced = ($LinkOptions -band 2) -ne 0  # Link is enforced if bit 1 is set
                        LinkOptions = $LinkOptions
                    }
                }
            }
            
            $DomainResults.Dispose()
            $DomainSearcher.Dispose()
            
        } catch {
            Write-Log "Error getting domain GPO links: $($_.Exception.Message)"
        }
        
        if ($DomainLinks.Count -gt 0) {
            $DomainLinks | Export-Csv "$Global:OutputPath\GPO_Domain_Links.csv" -NoTypeInformation
        }
        
        # 3. Login Scripts from User Objects
        Write-Host "Checking for login scripts assigned to user accounts..." -ForegroundColor Yellow
        
        $UserScripts = @()
        $ScriptSearcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(scriptPath=*))"
        $ScriptSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
        $ScriptSearcher.PageSize = 1000
        $ScriptSearcher.PropertiesToLoad.AddRange(@('samaccountname', 'name', 'scriptpath'))
        
        $ScriptResults = $ScriptSearcher.FindAll()
        
        foreach ($ScriptResult in $ScriptResults) {
            $ScriptProps = $ScriptResult.Properties
            $ScriptPath = $ScriptProps['scriptpath'][0]
            
            $ScriptType = switch -Regex ($ScriptPath) {
                '\.ps1$' { "PowerShell"; break }
                '\.vbs$' { "VBScript"; break }
                '\.(bat|cmd)$' { "Batch"; break }
                default { "Other" }
            }
            
            $UserScripts += [PSCustomObject]@{
                UserName = if ($ScriptProps['samaccountname']) { $ScriptProps['samaccountname'][0] } else { "" }
                DisplayName = if ($ScriptProps['name']) { $ScriptProps['name'][0] } else { "" }
                ScriptPath = $ScriptPath
                ScriptType = $ScriptType
                ScriptFileName = Split-Path $ScriptPath -Leaf
            }
        }
        
        $ScriptResults.Dispose()
        $ScriptSearcher.Dispose()
        
        if ($UserScripts.Count -gt 0) {
            $UserScripts | Export-Csv "$Global:OutputPath\GPO_User_Login_Scripts.csv" -NoTypeInformation
        }
        
        # 4. Organizational Unit Structure Analysis
        Write-Host "Analyzing OU structure for GPO targeting..." -ForegroundColor Yellow
        
        $OUStructure = @()
        $OUSearcher = [adsisearcher]"(objectClass=organizationalUnit)"
        $OUSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
        $OUSearcher.PageSize = 1000
        $OUSearcher.PropertiesToLoad.AddRange(@('name', 'distinguishedname', 'gplink', 'gpoptions'))
        
        $OUResults = $OUSearcher.FindAll()
        
        foreach ($OUResult in $OUResults) {
            $OUProps = $OUResult.Properties
            $OUName = if ($OUProps['name']) { $OUProps['name'][0] } else { "" }
            $OUDN = if ($OUProps['distinguishedname']) { $OUProps['distinguishedname'][0] } else { "" }
            $GPLink = if ($OUProps['gplink']) { $OUProps['gplink'][0] } else { "" }
            $GPOptions = if ($OUProps['gpoptions']) { $OUProps['gpoptions'][0] } else { 0 }
            
            # Count linked GPOs
            $LinkedGPOCount = 0
            $LinkedGPONames = @()
            
            if ($GPLink) {
                $LinkPattern = '\[LDAP://cn=\{([^}]+)\}'
                $GPOMatches = [regex]::Matches($GPLink, $LinkPattern)
                $LinkedGPOCount = $GPOMatches.Count
                
                foreach ($GPOMatch in $GPOMatches) {
                    $GPOGUID = $GPOMatch.Groups[1].Value
                    $LinkedGPO = $GPODetails | Where-Object {$_.GPOId -eq "{$GPOGUID}"}
                    if ($LinkedGPO) {
                        $LinkedGPONames += $LinkedGPO.GPOName
                    }
                }
            }
            
            # Calculate OU depth
            $OUDepth = ($OUDN -split ",OU=").Count - 1
            
            $OUStructure += [PSCustomObject]@{
                OUName = $OUName
                DistinguishedName = $OUDN
                OUDepth = $OUDepth
                HasGPOLinks = $LinkedGPOCount -gt 0
                LinkedGPOCount = $LinkedGPOCount
                LinkedGPONames = $LinkedGPONames -join '; '
                GPOInheritanceBlocked = ($GPOptions -band 1) -ne 0
                GPOptions = $GPOptions
            }
        }
        
        $OUResults.Dispose()
        $OUSearcher.Dispose()
        
        if ($OUStructure.Count -gt 0) {
            $OUStructure | Export-Csv "$Global:OutputPath\GPO_OU_Structure.csv" -NoTypeInformation
        }
        
        # 5. Generate comprehensive statistics
        $GPOStats = [PSCustomObject]@{
            TotalGPOs = $GPODetails.Count
            LinkedGPOs = ($GPODetails | Where-Object {$_.IsLinked -eq $true}).Count
            UnlinkedGPOs = ($GPODetails | Where-Object {$_.IsLinked -eq $false}).Count
            DisabledGPOs = ($GPODetails | Where-Object {$_.Status -like "*Disabled*"}).Count
            StaleGPOs = ($GPODetails | Where-Object {$_.IsStale -eq $true}).Count
            GPOsWithScripts = ($GPODetails | Where-Object {$_.HasScripts -eq $true}).Count
            TotalScriptsInGPOs = ($GPODetails | Measure-Object -Property ScriptCount -Sum).Sum
            UsersWithLoginScripts = $UserScripts.Count
            DomainLevelGPOs = $DomainLinks.Count
            TotalOUs = $OUStructure.Count
            OUsWithGPOLinks = ($OUStructure | Where-Object {$_.HasGPOLinks -eq $true}).Count
            OUsWithInheritanceBlocked = ($OUStructure | Where-Object {$_.GPOInheritanceBlocked -eq $true}).Count
            AverageGPOAge = if ($GPODetails.Count -gt 0) { [math]::Round(($GPODetails | Where-Object {$_.AgeInDays -ne $null} | Measure-Object -Property AgeInDays -Average).Average, 1) } else { 0 }
            ProcessingTime = ((Get-Date) - $ScriptStartTime).TotalMinutes
            AssessmentMethod = "ADSI"
            RequiredWinRM = $false
            Limitations = "GPO settings analysis limited without file system access; Script detection incomplete"
        }
        
        $GPOStats | Export-Csv "$Global:OutputPath\GPO_Summary_Stats.csv" -NoTypeInformation
        
        # 6. Script Language Summary
        $AllScriptTypes = @()
        $AllScriptTypes += $GPODetails | Where-Object {$_.ScriptTypes} | Select-Object -ExpandProperty ScriptTypes
        $AllScriptTypes += $UserScripts | Select-Object -ExpandProperty ScriptType
        
        $ScriptLanguageSummary = $AllScriptTypes | 
            Where-Object {$_} |
            ForEach-Object {$_ -split '; '} |
            Group-Object |
            Select-Object @{N='Language';E={$_.Name}}, Count |
            Sort-Object Count -Descending
        
        if ($ScriptLanguageSummary.Count -gt 0) {
            $ScriptLanguageSummary | Export-Csv "$Global:OutputPath\GPO_Script_Language_Summary.csv" -NoTypeInformation
        }
        
        # 7. GPO Health Analysis
        $GPOHealthAnalysis = @()
        foreach ($GPO in $GPODetails) {
            $HealthIssues = @()
            $HealthStatus = "Healthy"
            
            if (!$GPO.IsLinked) {
                $HealthIssues += "Unlinked GPO"
                $HealthStatus = "Warning"
            }
            
            if ($GPO.IsStale) {
                $HealthIssues += "Not modified in over 1 year"
                $HealthStatus = "Warning"
            }
            
            if ($GPO.Status -like "*Disabled*") {
                $HealthIssues += "GPO disabled"
                if ($HealthStatus -eq "Healthy") { $HealthStatus = "Information" }
            }
            
            if ($GPO.TotalSettings -eq 0) {
                $HealthIssues += "No settings detected"
                $HealthStatus = "Warning"
            }
            
            $GPOHealthAnalysis += [PSCustomObject]@{
                GPOName = $GPO.GPOName
                GPOId = $GPO.GPOId
                HealthStatus = $HealthStatus
                HealthIssues = $HealthIssues -join '; '
                IsLinked = $GPO.IsLinked
                IsStale = $GPO.IsStale
                Status = $GPO.Status
                AgeInDays = $GPO.AgeInDays
                RecommendedAction = if ($HealthIssues.Count -gt 0) {
                    if (!$GPO.IsLinked) { "Review if GPO is needed or link to appropriate container" }
                    elseif ($GPO.IsStale) { "Review and update GPO settings" }
                    else { "Review GPO configuration" }
                } else { "No action required" }
            }
        }
        
        $GPOHealthAnalysis | Export-Csv "$Global:OutputPath\GPO_Health_Analysis.csv" -NoTypeInformation
        
        Write-Log "GPO assessment completed in $([math]::Round($GPOStats.ProcessingTime, 2)) minutes"
        
    } catch {
        Write-Log "Critical error in GPO assessment: $($_.Exception.Message)"
        throw
    } finally {
        [GC]::Collect()
    }
}

# Execute the assessment if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Get-GPOAssessment
    Write-Host "Group Policy Assessment completed. Results in: $Global:OutputPath" -ForegroundColor Green
}
