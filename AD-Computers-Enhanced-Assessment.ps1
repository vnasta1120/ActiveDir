# Enhanced AD Computers Assessment with ADUAC Implementation
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

function Get-ADComputersAssessmentEnhanced {
    Write-Log "=== Starting Enhanced AD Computers Assessment with ADUAC Analysis (ADSI) ==="
    
    $ScriptStartTime = Get-Date
    $InactiveThreshold = (Get-Date).AddDays(-$Global:Config.InactiveComputerDays)
    
    # Get domain info
    $DomainInfo = Get-ADSIDomainInfo
    if (!$DomainInfo) {
        Write-Error "Failed to get domain information"
        return
    }
    
    Write-Host "Getting total computer count via ADSI..." -ForegroundColor Yellow
    
    # Count total computers first
    $CountSearcher = [adsisearcher]"(&(objectCategory=computer))"
    $CountSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
    $CountSearcher.PageSize = 1000
    $CountResults = $CountSearcher.FindAll()
    $TotalComputerCount = $CountResults.Count
    $CountResults.Dispose()
    $CountSearcher.Dispose()
    
    Write-Log "Total AD Computers found: $TotalComputerCount"
    
    $AllComputers = @()
    $CorruptedComputers = @()
    $ComputersWithSPNs = @()
    $ComputersWithoutLAPS = @()
    $ProcessedCount = 0
    
    # Get all computer properties needed for enhanced analysis
    $ComputerProperties = @(
        'name', 'dnshostname', 'useraccountcontrol', 'operatingsystem', 
        'operatingsystemversion', 'lastlogontimestamp', 'whencreated',
        'description', 'distinguishedname', 'serviceprincipalname',
        'pwdlastset', 'location', 'ms-mcs-admpwd', 'ms-mcs-admpwdexpirationtime',
        'objectsid', 'isdeleted', 'samaccountname'
    )
    
    # Create main searcher with paging
    $Searcher = [adsisearcher]"(&(objectCategory=computer))"
    $Searcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
    $Searcher.PageSize = $Global:Config.BatchSize
    $Searcher.PropertiesToLoad.AddRange($ComputerProperties)
    
    Write-Host "Processing $TotalComputerCount computers with enhanced ADUAC analysis via ADSI..." -ForegroundColor Green
    
    try {
        $Results = $Searcher.FindAll()
        
        foreach ($Result in $Results) {
            $ProcessedCount++
            
            if ($ProcessedCount % $Global:Config.ComputerProgressInterval -eq 0) {
                $PercentComplete = ($ProcessedCount / $TotalComputerCount) * 100
                $ETA = Get-ETA -Current $ProcessedCount -Total $TotalComputerCount -StartTime $ScriptStartTime
                
                Write-Progress -Activity "Processing AD Computers with Enhanced ADUAC Analysis (ADSI)" `
                    -Status "Processing computer $ProcessedCount of $TotalComputerCount - ETA: $ETA" `
                    -PercentComplete $PercentComplete `
                    -CurrentOperation "Analyzing: $($Result.Properties['name'][0])"
            }
            
            try {
                $ComputerProps = $Result.Properties
                
                # Extract core properties
                $ComputerName = if ($ComputerProps['name']) { $ComputerProps['name'][0] } else { "" }
                $DNSHostName = if ($ComputerProps['dnshostname']) { $ComputerProps['dnshostname'][0] } else { "" }
                $OSVersion = if ($ComputerProps['operatingsystem']) { $ComputerProps['operatingsystem'][0] } else { "Unknown" }
                $OSVersionNumber = if ($ComputerProps['operatingsystemversion']) { $ComputerProps['operatingsystemversion'][0] } else { "" }
                $Description = if ($ComputerProps['description']) { $ComputerProps['description'][0] } else { "" }
                $DistinguishedName = if ($ComputerProps['distinguishedname']) { $ComputerProps['distinguishedname'][0] } else { "" }
                $Location = if ($ComputerProps['location']) { $ComputerProps['location'][0] } else { "" }
                $SamAccountName = if ($ComputerProps['samaccountname']) { $ComputerProps['samaccountname'][0] } else { "" }
                
                # Convert timestamps
                $LastLogon = ConvertTo-DateTime -Value $ComputerProps['lastlogontimestamp'][0] -Format "FileTime"
                $WhenCreated = ConvertTo-DateTime -Value $ComputerProps['whencreated'][0] -Format "GeneralizedTime"
                $PasswordLastSet = ConvertTo-DateTime -Value $ComputerProps['pwdlastset'][0] -Format "FileTime"
                
                # Enhanced UAC Analysis for computers using ADUAC enumeration
                $UAC = if ($ComputerProps['useraccountcontrol']) { [int]$ComputerProps['useraccountcontrol'][0] } else { 0 }
                $UACAnalysis = Get-UACSummary -UACValue $UAC
                
                # ENHANCED COMPUTER ANALYSIS with configurable thresholds
                $CorruptionIssues = @()
                
                # 1. OS Architecture and Compliance Detection
                $Architecture = "Unknown"
                if ($OSVersionNumber -match "x64|64-bit") { $Architecture = "x64" }
                elseif ($OSVersionNumber -match "x86|32-bit") { $Architecture = "x86" }
                
                $OSType = if ($OSVersion -like "*Server*") { "Server" } else { "Workstation" }
                $IsCompliant = $false
                $IsSupported = $false
                $OSCategory = "Unknown"
                
                # Enhanced OS Compliance with 2003-2022 detection
                switch -Regex ($OSVersion) {
                    "Server 2022" { $IsCompliant = $true; $IsSupported = $true; $OSCategory = "Modern" }
                    "Server 2019" { $IsCompliant = $true; $IsSupported = $true; $OSCategory = "Modern" }
                    "Server 2016" { $IsCompliant = $true; $IsSupported = $true; $OSCategory = "Modern" }
                    "Windows 11" { $IsCompliant = $true; $IsSupported = $true; $OSCategory = "Modern" }
                    "Windows 10" { $IsCompliant = $true; $IsSupported = $true; $OSCategory = "Modern" }
                    "Server 2012 R2" { $IsCompliant = $false; $IsSupported = $true; $OSCategory = "Legacy-Supported" }
                    "Server 2012" { $IsCompliant = $false; $IsSupported = $true; $OSCategory = "Legacy-Supported" }
                    "Windows 8.1" { $IsCompliant = $false; $IsSupported = $true; $OSCategory = "Legacy-Supported" }
                    "Windows 8" { $IsCompliant = $false; $IsSupported = $false; $OSCategory = "End-of-Life" }
                    "Server 2008 R2" { $IsCompliant = $false; $IsSupported = $false; $OSCategory = "End-of-Life" }
                    "Server 2008" { $IsCompliant = $false; $IsSupported = $false; $OSCategory = "End-of-Life" }
                    "Windows 7" { $IsCompliant = $false; $IsSupported = $false; $OSCategory = "End-of-Life" }
                    "Vista" { $IsCompliant = $false; $IsSupported = $false; $OSCategory = "End-of-Life" }
                    "Server 2003" { $IsCompliant = $false; $IsSupported = $false; $OSCategory = "End-of-Life" }
                    "Windows XP" { $IsCompliant = $false; $IsSupported = $false; $OSCategory = "End-of-Life" }
                    "Windows 2000" { $IsCompliant = $false; $IsSupported = $false; $OSCategory = "End-of-Life" }
                    default { $OSCategory = "Unknown" }
                }
                
                # 2. Activity Analysis with configurable threshold
                $IsActive = $false
                $IsStale = $false
                if ($LastLogon) {
                    $IsActive = $LastLogon -gt $InactiveThreshold
                    $IsStale = !$IsActive
                }
                
                # 3. Password Age Analysis with configurable threshold
                $PasswordAge = if ($PasswordLastSet) {
                    (Get-Date) - $PasswordLastSet
                } else { $null }
                
                if ($PasswordAge -and $PasswordAge.TotalDays -gt $Global:Config.OldComputerPasswordDays) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Old Computer Password"
                        Severity = "Medium"
                        Description = "Computer password age exceeds $($Global:Config.OldComputerPasswordDays) days ($([math]::Round($PasswordAge.TotalDays)) days)"
                    }
                }
                
                # 4. Service Principal Name Analysis
                $SPNCount = 0
                $SPNTypes = @()
                $HasDuplicateSPN = $false
                $ServicePrincipalNames = ""
                
                if ($ComputerProps['serviceprincipalname']) {
                    $SPNs = $ComputerProps['serviceprincipalname']
                    $SPNCount = $SPNs.Count
                    $ServicePrincipalNames = $SPNs -join '; '
                    
                    foreach ($SPN in $SPNs) {
                        $SPNType = $SPN.Split('/')[0]
                        if ($SPNType -notin $SPNTypes) {
                            $SPNTypes += $SPNType
                        }
                        
                        # Check for duplicate SPNs (simplified check - would need full directory scan for complete validation)
                        # For now, we'll mark this as potential and let the SPN analysis script do the full check
                    }
                    
                    # Track computers with SPNs
                    $ComputersWithSPNs += [PSCustomObject]@{
                        ComputerName = $ComputerName
                        SPNCount = $SPNCount
                        SPNTypes = $SPNTypes -join '; '
                        ServicePrincipalNames = $ServicePrincipalNames
                        HasDuplicates = $HasDuplicateSPN
                    }
                }
                
                # 5. LAPS Deployment Verification
                $HasLAPS = $false
                $LAPSPasswordSet = $false
                $LAPSExpirationTime = $null
                
                if ($ComputerProps['ms-mcs-admpwd']) {
                    $HasLAPS = $true
                    $LAPSPasswordSet = $true
                }
                
                if ($ComputerProps['ms-mcs-admpwdexpirationtime']) {
                    $LAPSExpirationTime = ConvertTo-DateTime -Value $ComputerProps['ms-mcs-admpwdexpirationtime'][0] -Format "FileTime"
                }
                
                if (!$HasLAPS -and $OSType -eq "Workstation") {
                    $ComputersWithoutLAPS += [PSCustomObject]@{
                        ComputerName = $ComputerName
                        OperatingSystem = $OSVersion
                        LastLogonDate = $LastLogon
                        Enabled = !$UACAnalysis.IsDisabled
                        MissingLAPS = $true
                    }
                }
                
                # 6. BitLocker Status Detection (via Registry check - limited without WinRM)
                $HasBitLocker = $false
                $BitLockerRecoveryKeys = 0
                
                # Search for BitLocker recovery information in AD
                try {
                    $BitLockerSearcher = [adsisearcher]"(&(objectClass=msFVE-RecoveryInformation)(distinguishedName=*$ComputerName*))"
                    $BitLockerSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
                    $BitLockerResults = $BitLockerSearcher.FindAll()
                    
                    if ($BitLockerResults.Count -gt 0) {
                        $HasBitLocker = $true
                        $BitLockerRecoveryKeys = $BitLockerResults.Count
                    }
                    
                    $BitLockerResults.Dispose()
                    $BitLockerSearcher.Dispose()
                } catch {
                    # BitLocker detection failed - not critical
                }
                
                # 7. Computer Delegation Analysis using ADUAC
                $DelegationType = "None"
                if ($UACAnalysis.TrustedForDelegation) { 
                    $DelegationType = "Unconstrained" 
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Unconstrained Delegation Computer"
                        Severity = "High"
                        Description = "Computer account trusted for unconstrained delegation (TRUSTED_FOR_DELEGATION)"
                    }
                }
                elseif ($UACAnalysis.TrustedForAuthDelegation) { 
                    $DelegationType = "Constrained" 
                }
                
                # 8. Domain Join Date Tracking
                $DomainJoinDate = $WhenCreated
                $DaysSinceJoin = if ($DomainJoinDate) { 
                    (Get-Date) - $DomainJoinDate 
                } else { $null }
                
                # 9. End-of-Life OS Detection with configurable severity
                if ($Global:Config.HighRiskThresholds.EndOfLifeOS -and $OSCategory -eq "End-of-Life") {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "End-of-Life Operating System"
                        Severity = "High"
                        Description = "Operating system no longer supported: $OSVersion"
                    }
                }
                
                # 10. Stale Computer Detection with configurable threshold
                if ($IsStale -and !$UACAnalysis.IsDisabled) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Stale Active Computer"
                        Severity = "Medium"
                        Description = "Enabled computer not seen in $($Global:Config.InactiveComputerDays)+ days"
                    }
                }
                
                # 11. Enhanced Security Analysis using ADUAC
                $SecurityRiskFactors = @()
                
                if ($UACAnalysis.IsDisabled -ne ($UAC -band 2)) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "UAC Enabled State Conflict"
                        Severity = "High"
                        Description = "UAC disabled flag conflicts with calculated state"
                    }
                }
                
                if ($UACAnalysis.DontRequirePreauth) {
                    $SecurityRiskFactors += "No Preauth Required"
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Computer Kerberos Preauth Not Required"
                        Severity = "High"
                        Description = "Computer configured with DONT_REQ_PREAUTH flag"
                    }
                }
                
                if ($UACAnalysis.UseDESKeyOnly) {
                    $SecurityRiskFactors += "DES Keys Only"
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Computer Uses Weak Encryption (DES Only)"
                        Severity = "High"
                        Description = "Computer configured to use DES encryption only"
                    }
                }
                
                # 12. Missing Core Attributes (Critical)
                if (!$ComputerName) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Missing Computer Name"
                        Severity = "Critical"
                        Description = "Computer object missing required name"
                    }
                }
                
                if (!$DistinguishedName) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Missing DistinguishedName"
                        Severity = "Critical"
                        Description = "Computer object missing distinguished name"
                    }
                }
                
                # 13. Tombstoned Object Detection (Critical)
                $IsDeleted = if ($ComputerProps['isdeleted']) { [bool]$ComputerProps['isdeleted'][0] } else { $false }
                if ($IsDeleted) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Tombstoned Object"
                        Severity = "Critical"
                        Description = "Computer object is marked as deleted but still accessible"
                    }
                }
                
                # Create enhanced computer object (PowerBI-optimized)
                $ComputerObject = [PSCustomObject]@{
                    ComputerName = $ComputerName
                    DNSHostName = $DNSHostName
                    Enabled = !$UACAnalysis.IsDisabled
                    OperatingSystem = $OSVersion
                    OperatingSystemVersion = $OSVersionNumber
                    Architecture = $Architecture
                    OSType = $OSType
                    OSCategory = $OSCategory
                    IsCompliant = $IsCompliant
                    IsSupported = $IsSupported
                    IsActive = $IsActive
                    IsStale = $IsStale
                    LastLogonDate = $LastLogon
                    WhenCreated = $WhenCreated
                    DomainJoinDate = $DomainJoinDate
                    DaysSinceJoin = if ($DaysSinceJoin) { [math]::Round($DaysSinceJoin.TotalDays) } else { $null }
                    Description = $Description
                    DistinguishedName = $DistinguishedName
                    Location = $Location
                    
                    # Enhanced Security Attributes using ADUAC
                    UserAccountControl = $UAC
                    UACFlags = $UACAnalysis.FlagsString
                    IsDisabled = $UACAnalysis.IsDisabled
                    PasswordLastSet = $PasswordLastSet
                    PasswordAgeDays = if ($PasswordAge) { [math]::Round($PasswordAge.TotalDays) } else { $null }
                    SPNCount = $SPNCount
                    SPNTypes = $SPNTypes -join '; '
                    ServicePrincipalNames = $ServicePrincipalNames
                    HasDuplicateSPN = $HasDuplicateSPN
                    DelegationType = $DelegationType
                    TrustedForDelegation = $UACAnalysis.TrustedForDelegation
                    TrustedForAuthDelegation = $UACAnalysis.TrustedForAuthDelegation
                    DontRequirePreauth = $UACAnalysis.DontRequirePreauth
                    UseDESKeyOnly = $UACAnalysis.UseDESKeyOnly
                    HasLAPS = $HasLAPS
                    LAPSPasswordSet = $LAPSPasswordSet
                    LAPSExpirationTime = $LAPSExpirationTime
                    HasBitLocker = $HasBitLocker
                    BitLockerRecoveryKeys = $BitLockerRecoveryKeys
                    SecurityRiskFactors = $SecurityRiskFactors -join '; '
                    
                    # Configurable Corruption Analysis
                    CorruptionIssuesCount = $CorruptionIssues.Count
                    CorruptionLevel = Get-CorruptionLevel -Issues $CorruptionIssues
                    HasCorruption = $CorruptionIssues.Count -gt 0
                    CorruptionSummary = if ($CorruptionIssues.Count -gt 0) { 
                        ($CorruptionIssues.Issue -join '; ') 
                    } else { 
                        "No Issues Detected" 
                    }
                }
                
                $AllComputers += $ComputerObject
                
                # Track corrupted computers
                if ($CorruptionIssues.Count -gt 0) {
                    foreach ($Issue in $CorruptionIssues) {
                        $CorruptedComputers += [PSCustomObject]@{
                            ComputerName = $ComputerName
                            OperatingSystem = $OSVersion
                            OSCategory = $OSCategory
                            IssueType = $Issue.Issue
                            Severity = $Issue.Severity
                            IssueDescription = $Issue.Description
                            Enabled = !$UACAnalysis.IsDisabled
                            LastLogonDate = $LastLogon
                            UACFlags = $UACAnalysis.FlagsString
                        }
                    }
                }
                
                # Export in configurable batches
                if ($AllComputers.Count -ge ($Global:Config.OutputSettings.ExportBatchSize / 2)) {  # Smaller batches for computers
                    $AllComputers | Export-Csv "$Global:OutputPath\Computers_Enhanced.csv" -NoTypeInformation -Append
                    $AllComputers = @()
                }
                
            } catch {
                Write-Log "Error processing computer $ComputerName : $($_.Exception.Message)"
            }
        }
        
        # Export remaining computers
        if ($AllComputers.Count -gt 0) {
            $AllComputers | Export-Csv "$Global:OutputPath\Computers_Enhanced.csv" -NoTypeInformation -Append
        }
        
        Write-Progress -Activity "Processing AD Computers" -Completed
        
        # Generate Enhanced Computer Reports
        if ($Global:Config.OutputSettings.PowerBIOptimized) {
            # Export corrupted computers
            if ($CorruptedComputers.Count -gt 0) {
                $CorruptedComputers | Export-Csv "$Global:OutputPath\Computers_Corrupted.csv" -NoTypeInformation
            }
            
            # Computers With SPNs
            if ($ComputersWithSPNs.Count -gt 0) {
                $ComputersWithSPNs | Export-Csv "$Global:OutputPath\Computers_With_SPNs.csv" -NoTypeInformation
            }
            
            # Computers Without LAPS
            if ($ComputersWithoutLAPS.Count -gt 0) {
                $ComputersWithoutLAPS | Export-Csv "$Global:OutputPath\Computers_Without_LAPS.csv" -NoTypeInformation
            }
            
            # End-of-Life Systems
            $EoLSystems = $CorruptedComputers | Where-Object {$_.IssueType -eq "End-of-Life Operating System"}
            if ($EoLSystems.Count -gt 0) {
                $EoLSystems | Export-Csv "$Global:OutputPath\Computers_End_of_Life.csv" -NoTypeInformation
            }
            
            # Computers with Delegation Rights
            $AllComputersData = Import-Csv "$Global:OutputPath\Computers_Enhanced.csv"
            $DelegationComputers = $AllComputersData | Where-Object {$_.DelegationType -ne "None"}
            if ($DelegationComputers.Count -gt 0) {
                $DelegationComputers | Export-Csv "$Global:OutputPath\Computers_With_Delegation.csv" -NoTypeInformation
            }
            
            # Stale Computers
            $StaleComputers = $AllComputersData | Where-Object {$_.IsStale -eq "True"}
            if ($StaleComputers.Count -gt 0) {
                $StaleComputers | Export-Csv "$Global:OutputPath\Computers_Stale.csv" -NoTypeInformation
            }
        }
        
        $ProcessingTime = ((Get-Date) - $ScriptStartTime).TotalMinutes
        Write-Log "Enhanced computer assessment completed in $([math]::Round($ProcessingTime, 2)) minutes"
        
        # Cleanup
        $Results.Dispose()
        $Searcher.Dispose()
        [GC]::Collect()
        
    } catch {
        Write-Log "Critical error in enhanced computer assessment: $($_.Exception.Message)"
        throw
    }
}

# Execute the assessment if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Get-ADComputersAssessmentEnhanced
    Write-Host "Enhanced Computers Assessment completed. Results in: $Global:OutputPath" -ForegroundColor Green
}
