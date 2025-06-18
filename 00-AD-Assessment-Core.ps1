# Enhanced AD Users Assessment with ADUAC Implementation
# Version 5.0 - ADSI Implementation (No AD Module Required)
# Self-contained version - No dependencies

#Requires -Version 5.1

param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\AD_Assessment",
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile
)

# DEFINE ALL FUNCTIONS AT SCRIPT LEVEL - NO CONDITIONAL BLOCKS!

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    if ($Global:LogFile) {
        $LogMessage | Out-File -FilePath $Global:LogFile -Append -ErrorAction SilentlyContinue
    }
    Write-Host $LogMessage
}

function Get-ADSIDomainInfo {
    try {
        $RootDSE = [ADSI]"LDAP://RootDSE"
        $DomainDN = $RootDSE.defaultNamingContext[0]
        $Domain = [ADSI]"LDAP://$DomainDN"
        
        return @{
            DomainDN = $DomainDN
            DomainName = $Domain.name[0]
            DistinguishedName = $DomainDN
        }
    }
    catch {
        Write-Warning "Failed to get domain info via ADSI: $($_.Exception.Message)"
        return $null
    }
}

function ConvertTo-DateTime {
    param(
        [object]$Value,
        [string]$Format = "FileTime"
    )
    
    try {
        if (!$Value -or $Value -eq 0 -or $Value -eq "0") {
            return $null
        }
        
        switch ($Format) {
            "FileTime" {
                if ($Value -is [string]) {
                    $Value = [long]$Value
                }
                return [DateTime]::FromFileTime($Value)
            }
            "GeneralizedTime" {
                $dateString = $Value.ToString()
                if ($dateString -match '(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})') {
                    return [DateTime]::ParseExact($Matches[0], "yyyyMMddHHmmss", $null)
                }
                return $null
            }
            default {
                return [DateTime]$Value
            }
        }
    }
    catch {
        return $null
    }
}

function Get-UACSummary {
    param([int]$UACValue)
    
    $Flags = @{
        ACCOUNTDISABLE = 0x0002
        LOCKOUT = 0x0010
        PASSWD_NOTREQD = 0x0020
        NORMAL_ACCOUNT = 0x0200
        WORKSTATION_TRUST_ACCOUNT = 0x1000
        SERVER_TRUST_ACCOUNT = 0x2000
        DONT_EXPIRE_PASSWORD = 0x10000
        SMARTCARD_REQUIRED = 0x40000
        TRUSTED_FOR_DELEGATION = 0x80000
        NOT_DELEGATED = 0x100000
        USE_DES_KEY_ONLY = 0x200000
        DONT_REQ_PREAUTH = 0x400000
        PASSWORD_EXPIRED = 0x800000
        TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    }
    
    $ActiveFlags = @()
    foreach ($Flag in $Flags.GetEnumerator()) {
        if ($UACValue -band $Flag.Value) {
            $ActiveFlags += $Flag.Key
        }
    }
    
    return @{
        RawValue = $UACValue
        Flags = $ActiveFlags
        FlagsString = $ActiveFlags -join '; '
        IsDisabled = ($UACValue -band 0x0002) -ne 0
        IsLocked = ($UACValue -band 0x0010) -ne 0
        PasswordNeverExpires = ($UACValue -band 0x10000) -ne 0
        PasswordNotRequired = ($UACValue -band 0x0020) -ne 0
        SmartCardRequired = ($UACValue -band 0x40000) -ne 0
        TrustedForDelegation = ($UACValue -band 0x80000) -ne 0
        TrustedForAuthDelegation = ($UACValue -band 0x1000000) -ne 0
        DontRequirePreauth = ($UACValue -band 0x400000) -ne 0
        IsNormalAccount = ($UACValue -band 0x0200) -ne 0
        IsComputerAccount = (($UACValue -band 0x1000) -ne 0) -or (($UACValue -band 0x2000) -ne 0)
        PasswordExpired = ($UACValue -band 0x800000) -ne 0
        NotDelegated = ($UACValue -band 0x100000) -ne 0
        UseDESKeyOnly = ($UACValue -band 0x200000) -ne 0
    }
}

function Test-AccountType {
    param(
        [string]$SamAccountName,
        [string]$Description,
        [object]$UACAnalysis,
        [int]$AdminCount = 0
    )
    
    $ServiceIndicators = @("svc", "service", "app", "sql", "system", "iis")
    $AdminIndicators = @("admin", "adm", "_a$", "-admin", ".admin")
    
    $IsServiceAccount = $false
    foreach ($Pattern in $ServiceIndicators) {
        if ($SamAccountName -match $Pattern -or $Description -match $Pattern) {
            $IsServiceAccount = $true
            break
        }
    }
    
    $IsAdminAccount = $false
    if ($AdminCount -eq 1) {
        $IsAdminAccount = $true
    }
    else {
        foreach ($Pattern in $AdminIndicators) {
            if ($SamAccountName -match $Pattern) {
                $IsAdminAccount = $true
                break
            }
        }
    }
    
    if ($UACAnalysis.IsComputerAccount) {
        return "Computer Account"
    }
    elseif ($IsServiceAccount) {
        return "Service Account"
    }
    elseif ($IsAdminAccount) {
        return "Admin Account"
    }
    elseif ($UACAnalysis.IsNormalAccount) {
        return "Standard User"
    }
    else {
        return "Special Account"
    }
}

function Get-CorruptionLevel {
    param([array]$Issues)
    
    if (!$Issues -or $Issues.Count -eq 0) { return "Clean" }
    
    $CriticalCount = ($Issues | Where-Object {$_.Severity -eq "Critical"}).Count
    $HighCount = ($Issues | Where-Object {$_.Severity -eq "High"}).Count
    $MediumCount = ($Issues | Where-Object {$_.Severity -eq "Medium"}).Count
    $LowCount = ($Issues | Where-Object {$_.Severity -eq "Low"}).Count
    
    if ($CriticalCount -gt 0) { return "Critical" }
    elseif ($HighCount -gt 0) { return "High" }
    elseif ($MediumCount -gt 0) { return "Medium" }
    elseif ($LowCount -gt 0) { return "Low" }
    else { return "Clean" }
}

function Get-ETA {
    param(
        [int]$Current,
        [int]$Total,
        [datetime]$StartTime
    )
    
    if ($Current -eq 0) { return "Calculating..." }
    
    $ElapsedTime = (Get-Date) - $StartTime
    $ItemsPerSecond = $Current / $ElapsedTime.TotalSeconds
    $RemainingItems = $Total - $Current
    $EstimatedSeconds = $RemainingItems / $ItemsPerSecond
    
    if ($EstimatedSeconds -gt 3600) {
        return "{0:N1} hours" -f ($EstimatedSeconds / 3600)
    } elseif ($EstimatedSeconds -gt 60) {
        return "{0:N0} minutes" -f ($EstimatedSeconds / 60)
    } else {
        return "{0:N0} seconds" -f $EstimatedSeconds
    }
}

# INITIALIZE GLOBAL CONFIGURATION
$Global:Config = @{
    InactiveUserDays = 90
    InactiveComputerDays = 90
    StalePasswordDays = 180
    BatchSize = 100
    ProgressUpdateInterval = 10
    CircularGroupDepthLimit = 20
    
    MediumRiskThresholds = @{
        ExcessiveBadPasswordCount = 100
    }
    
    OutputSettings = @{
        ExportBatchSize = 1000
        PowerBIOptimized = $true
    }
    
    SecuritySettings = @{
        ServiceAccountIdentifiers = @("svc", "service", "app", "sql", "system", "iis")
        AdminAccountIdentifiers = @("admin", "adm", "_a$", "-admin", ".admin")
    }
}

# Set up global variables
$Global:OutputPath = $OutputPath
$Global:StartTime = Get-Date

# Create output directory
if (!(Test-Path $Global:OutputPath)) {
    New-Item -ItemType Directory -Path $Global:OutputPath -Force | Out-Null
}

# Create log file
$Global:LogFile = "$Global:OutputPath\AD_Assessment_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Try to load core script to override defaults (optional)
$CoreScript = Join-Path (Split-Path $MyInvocation.MyCommand.Path) "00-AD-Assessment-Core.ps1"
if (Test-Path $CoreScript) {
    try {
        . $CoreScript -OutputPath $OutputPath -ConfigFile $ConfigFile
        Write-Host "Core infrastructure loaded - configuration may have been updated" -ForegroundColor Green
    } catch {
        Write-Host "Core script found but failed to load. Using defaults." -ForegroundColor Yellow
    }
} else {
    Write-Host "Core script not found. Using default configuration." -ForegroundColor Yellow
}

# MAIN ASSESSMENT FUNCTION
function Get-ADUsersAssessmentEnhanced {
    Write-Log "=== Starting Enhanced AD Users Assessment with ADUAC Enumeration (ADSI) ==="
    
    $ScriptStartTime = Get-Date
    $InactiveThreshold = (Get-Date).AddDays(-$Global:Config.InactiveUserDays)
    $StalePasswordThreshold = (Get-Date).AddDays(-$Global:Config.StalePasswordDays)
    
    # Get domain info
    $DomainInfo = Get-ADSIDomainInfo
    if (!$DomainInfo) {
        Write-Error "Failed to get domain information"
        return
    }
    
    Write-Host "Getting total user count via ADSI..." -ForegroundColor Yellow
    
    # Count total users first
    $CountSearcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user))"
    $CountSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
    $CountSearcher.PageSize = 1000
    $CountResults = $CountSearcher.FindAll()
    $TotalUserCount = $CountResults.Count
    $CountResults.Dispose()
    $CountSearcher.Dispose()
    
    Write-Log "Total AD Users found: $TotalUserCount"
    
    # Initialize collections
    $AllUsers = @()
    $CorruptedUsers = @()
    $ProcessedCount = 0
    
    # Get all user properties needed for enhanced analysis
    $UserProperties = @(
        'samaccountname', 'displayname', 'userprincipalname', 'useraccountcontrol',
        'lastlogontimestamp', 'pwdlastset', 'whencreated', 'description',
        'department', 'title', 'manager', 'memberof', 'distinguishedname', 
        'mail', 'employeeid', 'badpwdcount', 'lockouttime', 'logonworkstations',
        'sidhistory', 'admincount', 'objectsid', 'isdeleted'
    )
    
    # Create main searcher with paging
    $Searcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user))"
    $Searcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
    $Searcher.PageSize = $Global:Config.BatchSize
    $Searcher.PropertiesToLoad.AddRange($UserProperties)
    
    Write-Host "Processing $TotalUserCount users with enhanced ADUAC analysis via ADSI..." -ForegroundColor Green
    
    try {
        $Results = $Searcher.FindAll()
        
        foreach ($Result in $Results) {
            $ProcessedCount++
            
            # Update progress at configurable intervals
            if ($ProcessedCount % $Global:Config.ProgressUpdateInterval -eq 0) {
                $PercentComplete = ($ProcessedCount / $TotalUserCount) * 100
                $ETA = Get-ETA -Current $ProcessedCount -Total $TotalUserCount -StartTime $ScriptStartTime
                
                Write-Progress -Activity "Processing AD Users with Enhanced ADUAC Analysis (ADSI)" `
                    -Status "Processing user $ProcessedCount of $TotalUserCount - ETA: $ETA" `
                    -PercentComplete $PercentComplete `
                    -CurrentOperation "Analyzing: $($Result.Properties['samaccountname'][0])"
            }
            
            try {
                $UserProps = $Result.Properties
                
                # Extract core properties
                $SamAccountName = if ($UserProps['samaccountname']) { $UserProps['samaccountname'][0] } else { "" }
                $DisplayName = if ($UserProps['displayname']) { $UserProps['displayname'][0] } else { "" }
                $UPN = if ($UserProps['userprincipalname']) { $UserProps['userprincipalname'][0] } else { "" }
                $Email = if ($UserProps['mail']) { $UserProps['mail'][0] } else { "" }
                $EmployeeID = if ($UserProps['employeeid']) { $UserProps['employeeid'][0] } else { "" }
                $Description = if ($UserProps['description']) { $UserProps['description'][0] } else { "" }
                $Department = if ($UserProps['department']) { $UserProps['department'][0] } else { "" }
                $Title = if ($UserProps['title']) { $UserProps['title'][0] } else { "" }
                $DistinguishedName = if ($UserProps['distinguishedname']) { $UserProps['distinguishedname'][0] } else { "" }
                
                # Convert timestamps
                $LastLogon = ConvertTo-DateTime -Value $UserProps['lastlogontimestamp'][0] -Format "FileTime"
                $PwdLastSet = ConvertTo-DateTime -Value $UserProps['pwdlastset'][0] -Format "FileTime"
                $WhenCreated = ConvertTo-DateTime -Value $UserProps['whencreated'][0] -Format "GeneralizedTime"
                
                # UAC Analysis
                $UAC = if ($UserProps['useraccountcontrol']) { [int]$UserProps['useraccountcontrol'][0] } else { 0 }
                $UACAnalysis = Get-UACSummary -UACValue $UAC
                
                # Additional properties for corruption analysis
                $BadPwdCount = if ($UserProps['badpwdcount']) { [int]$UserProps['badpwdcount'][0] } else { 0 }
                $LockoutTime = if ($UserProps['lockouttime']) { $UserProps['lockouttime'][0] } else { $null }
                $LogonWorkstations = if ($UserProps['logonworkstations']) { $UserProps['logonworkstations'][0] } else { "" }
                $AdminCount = if ($UserProps['admincount']) { [int]$UserProps['admincount'][0] } else { 0 }
                $ObjectSID = if ($UserProps['objectsid']) { $UserProps['objectsid'][0] } else { $null }
                $IsDeleted = if ($UserProps['isdeleted']) { [bool]$UserProps['isdeleted'][0] } else { $false }
                
                # SIDHistory analysis
                $SIDHistoryCount = 0
                $SIDHistoryIssues = 0
                if ($UserProps['sidhistory']) {
                    $SIDHistoryCount = $UserProps['sidhistory'].Count
                    $SIDHistoryIssues = $SIDHistoryCount
                }
                
                # Group membership analysis
                $GroupCount = 0
                $MemberOfGroups = ""
                if ($UserProps['memberof']) {
                    $GroupCount = $UserProps['memberof'].Count
                    $GroupNames = @()
                    foreach ($GroupDN in $UserProps['memberof']) {
                        if ($GroupDN -match '^CN=([^,]+)') {
                            $GroupNames += $Matches[1]
                        }
                    }
                    $MemberOfGroups = $GroupNames -join '; '
                }
                
                # CORRUPTION DETECTION
                $CorruptionIssues = @()
                
                # 1. Missing Required Attributes (Critical)
                if (!$SamAccountName) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Missing SamAccountName"
                        Severity = "Critical"
                        Description = "User account missing required SamAccountName"
                    }
                }
                
                if (!$ObjectSID) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Missing ObjectSID"
                        Severity = "Critical"
                        Description = "User account missing security identifier"
                    }
                }
                
                if (!$DistinguishedName) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Missing DistinguishedName"
                        Severity = "Critical"
                        Description = "User account missing distinguished name"
                    }
                }
                
                # 2. UAC Flag Conflicts (High)
                $UserEnabled = !$UACAnalysis.IsDisabled
                
                # 3. Enhanced Password Policy Violations (High)
                if ($UACAnalysis.PasswordNeverExpires -and $UACAnalysis.TrustedForDelegation) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Password Never Expires with Delegation"
                        Severity = "High"
                        Description = "Account has DONT_EXPIRE_PASSWORD and TRUSTED_FOR_DELEGATION flags"
                    }
                }
                
                if ($UACAnalysis.PasswordNotRequired) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Password Not Required"
                        Severity = "High"
                        Description = "Account configured with PASSWD_NOTREQD flag"
                    }
                }
                
                # 4. Bad Password Count (Medium)
                if ($BadPwdCount -gt $Global:Config.MediumRiskThresholds.ExcessiveBadPasswordCount) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Excessive Bad Password Count"
                        Severity = "Medium"
                        Description = "Bad password count exceeds threshold: $BadPwdCount > $($Global:Config.MediumRiskThresholds.ExcessiveBadPasswordCount)"
                    }
                }
                
                # 5. Ancient Lockout Times (Low)
                if ($LockoutTime -and [long]$LockoutTime -gt 0) {
                    $LockoutDate = ConvertTo-DateTime -Value $LockoutTime -Format "FileTime"
                    if ($LockoutDate -and $LockoutDate -lt (Get-Date).AddYears(-1)) {
                        $CorruptionIssues += [PSCustomObject]@{
                            Issue = "Ancient Lockout Time"
                            Severity = "Low"
                            Description = "Lockout time older than 1 year"
                        }
                    }
                }
                
                # 6. Delegation Analysis
                $DelegationType = "None"
                $DelegationRisk = "Low"
                
                if ($UACAnalysis.TrustedForDelegation) {
                    $DelegationType = "Unconstrained"
                    $DelegationRisk = "High"
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Unconstrained Delegation"
                        Severity = "High"
                        Description = "Account trusted for unconstrained delegation (TRUSTED_FOR_DELEGATION)"
                    }
                }
                elseif ($UACAnalysis.TrustedForAuthDelegation) {
                    $DelegationType = "Constrained"
                    $DelegationRisk = "Medium"
                }
                
                # 7. Advanced Security Analysis
                $SecurityRiskFactors = @()
                
                if ($UACAnalysis.DontRequirePreauth) {
                    $SecurityRiskFactors += "No Preauth Required"
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Kerberos Preauth Not Required"
                        Severity = "High"
                        Description = "Account configured with DONT_REQ_PREAUTH flag"
                    }
                }
                
                if ($UACAnalysis.SmartCardRequired -and !$UserEnabled) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Smart Card Required but Disabled"
                        Severity = "Medium"
                        Description = "Account requires smart card but is disabled"
                    }
                }
                
                if ($UACAnalysis.UseDESKeyOnly) {
                    $SecurityRiskFactors += "DES Keys Only"
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Weak Encryption (DES Only)"
                        Severity = "High"
                        Description = "Account configured to use DES encryption only"
                    }
                }
                
                # 8. Orphaned SIDHistory Detection (Medium)
                if ($SIDHistoryIssues -gt 0) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Orphaned SIDHistory Entry"
                        Severity = "Medium"
                        Description = "Account has $SIDHistoryIssues potentially orphaned SIDHistory entries"
                    }
                }
                
                # 9. Tombstoned Object Detection (Critical)
                if ($IsDeleted) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Tombstoned Object"
                        Severity = "Critical"
                        Description = "User object is marked as deleted but still accessible"
                    }
                }
                
                # 10. Account Type Detection
                $AccountType = Test-AccountType -SamAccountName $SamAccountName -Description $Description -UACAnalysis $UACAnalysis -AdminCount $AdminCount
                
                # 11. Activity Analysis
                $IsActive = $UserEnabled -and (
                    ($LastLogon -and $LastLogon -gt $InactiveThreshold) -or 
                    ($PwdLastSet -and $PwdLastSet -gt $InactiveThreshold)
                )
                
                $IsStale = $LastLogon -and $LastLogon -lt $InactiveThreshold
                if ($IsStale -and $UserEnabled) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Stale Active Account"
                        Severity = "Medium"
                        Description = "Enabled account not used in $($Global:Config.InactiveUserDays)+ days"
                    }
                }
                
                # 12. Password Age Analysis
                $PasswordAge = if ($PwdLastSet) { (Get-Date) - $PwdLastSet } else { $null }
                $HasStalePassword = $PasswordAge -and $PasswordAge.TotalDays -gt $Global:Config.StalePasswordDays
                
                if ($HasStalePassword -and $UserEnabled) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Stale Password"
                        Severity = "Medium"  
                        Description = "Password older than $($Global:Config.StalePasswordDays) days"
                    }
                }
                
                # 13. Service Account Risk Assessment
                $IsServiceAccount = $AccountType -eq "Service Account"
                
                if ($IsServiceAccount) {
                    if ($UACAnalysis.PasswordNeverExpires -and $UACAnalysis.TrustedForDelegation) {
                        $CorruptionIssues += [PSCustomObject]@{
                            Issue = "Risky Service Account Config"
                            Severity = "High"
                            Description = "Service account with password never expires AND delegation rights"
                        }
                    }
                    if ($AdminCount -eq 1) {
                        $CorruptionIssues += [PSCustomObject]@{
                            Issue = "Service Account with Admin Rights"
                            Severity = "High"
                            Description = "Service account has administrative privileges"
                        }
                    }
                }
                
                # 14. Disabled but Still Grouped Detection
                if (!$UserEnabled -and $GroupCount -gt 1) {
                    $CorruptionIssues += [PSCustomObject]@{
                        Issue = "Disabled But Still Grouped"
                        Severity = "Medium"
                        Description = "Disabled account still member of $GroupCount groups"
                    }
                }
                
                # Create enhanced user object
                $UserObject = [PSCustomObject]@{
                    SamAccountName = $SamAccountName
                    DisplayName = $DisplayName
                    UserPrincipalName = $UPN
                    EmailAddress = $Email
                    EmployeeID = $EmployeeID
                    Enabled = $UserEnabled
                    LastLogonDate = $LastLogon
                    PasswordLastSet = $PwdLastSet
                    WhenCreated = $WhenCreated
                    Description = $Description
                    Department = $Department
                    Title = $Title
                    AccountType = $AccountType
                    IsActive = $IsActive
                    IsStale = $IsStale
                    
                    # Enhanced Security Attributes
                    UserAccountControl = $UAC
                    UACFlags = $UACAnalysis.FlagsString
                    IsDisabled = $UACAnalysis.IsDisabled
                    IsLocked = $UACAnalysis.IsLocked
                    PasswordNeverExpires = $UACAnalysis.PasswordNeverExpires
                    PasswordNotRequired = $UACAnalysis.PasswordNotRequired
                    SmartCardRequired = $UACAnalysis.SmartCardRequired
                    DelegationType = $DelegationType
                    DelegationRisk = $DelegationRisk
                    TrustedForDelegation = $UACAnalysis.TrustedForDelegation
                    TrustedForAuthDelegation = $UACAnalysis.TrustedForAuthDelegation
                    DontRequirePreauth = $UACAnalysis.DontRequirePreauth
                    NotDelegated = $UACAnalysis.NotDelegated
                    UseDESKeyOnly = $UACAnalysis.UseDESKeyOnly
                    PasswordExpired = $UACAnalysis.PasswordExpired
                    
                    # Enhanced Analysis
                    BadPasswordCount = $BadPwdCount
                    LockoutTime = $LockoutTime
                    LogonWorkstations = $LogonWorkstations
                    PasswordAgeDays = if ($PasswordAge) { [math]::Round($PasswordAge.TotalDays) } else { $null }
                    HasStalePassword = $HasStalePassword
                    SIDHistoryCount = $SIDHistoryCount
                    SIDHistoryIssues = $SIDHistoryIssues
                    GroupCount = $GroupCount
                    MemberOfGroups = $MemberOfGroups
                    AdminCount = $AdminCount
                    SecurityRiskFactors = $SecurityRiskFactors -join '; '
                    
                    # Corruption Analysis
                    CorruptionIssuesCount = $CorruptionIssues.Count
                    CorruptionLevel = Get-CorruptionLevel -Issues $CorruptionIssues
                    HasCorruption = $CorruptionIssues.Count -gt 0
                    CorruptionSummary = if ($CorruptionIssues.Count -gt 0) { 
                        ($CorruptionIssues.Issue -join '; ') 
                    } else { 
                        "No Issues Detected" 
                    }
                }
                
                $AllUsers += $UserObject
                
                # Track corrupted users
                if ($CorruptionIssues.Count -gt 0) {
                    foreach ($Issue in $CorruptionIssues) {
                        $CorruptedUsers += [PSCustomObject]@{
                            SamAccountName = $SamAccountName
                            DisplayName = $DisplayName
                            AccountType = $AccountType
                            IssueType = $Issue.Issue
                            Severity = $Issue.Severity
                            IssueDescription = $Issue.Description
                            Enabled = $UserEnabled
                            LastLogonDate = $LastLogon
                            UACFlags = $UACAnalysis.FlagsString
                        }
                    }
                }
                
                # Export in batches
                if ($AllUsers.Count -ge $Global:Config.OutputSettings.ExportBatchSize) {
                    $AllUsers | Export-Csv "$Global:OutputPath\Users_Enhanced.csv" -NoTypeInformation -Append
                    $AllUsers = @()
                }
                
            } catch {
                Write-Log "Error processing user $SamAccountName : $($_.Exception.Message)"
            }
        }
        
        # Export remaining users
        if ($AllUsers.Count -gt 0) {
            $AllUsers | Export-Csv "$Global:OutputPath\Users_Enhanced.csv" -NoTypeInformation -Append
        }
        
        Write-Progress -Activity "Processing AD Users" -Completed
        Write-Log "Enhanced user processing completed. Generating advanced reports..."
        
        # Generate Enhanced Reports
        if ($Global:Config.OutputSettings.PowerBIOptimized) {
            $AllUsersData = Import-Csv "$Global:OutputPath\Users_Enhanced.csv"
            
            # Export corrupted users
            if ($CorruptedUsers.Count -gt 0) {
                $CorruptedUsers | Export-Csv "$Global:OutputPath\Users_Corrupted.csv" -NoTypeInformation
            }
            
            # High Risk Service Accounts
            $HighRiskServiceAccounts = $AllUsersData | Where-Object {
                $_.AccountType -eq "Service Account" -and 
                ($_.CorruptionLevel -eq "High" -or $_.CorruptionLevel -eq "Critical" -or
                 $_.DelegationRisk -eq "High" -or $_.AdminCount -eq 1)
            }
            if ($HighRiskServiceAccounts.Count -gt 0) {
                $HighRiskServiceAccounts | Export-Csv "$Global:OutputPath\Service_Accounts_High_Risk.csv" -NoTypeInformation
            }
            
            # Stale Admin Accounts
            $StaleAdminAccounts = $AllUsersData | Where-Object {
                $_.AccountType -eq "Admin Account" -and $_.IsStale -eq "True"
            }
            if ($StaleAdminAccounts.Count -gt 0) {
                $StaleAdminAccounts | Export-Csv "$Global:OutputPath\Admin_Accounts_Stale.csv" -NoTypeInformation
            }
            
            # Disabled But Still Grouped
            $DisabledButGrouped = $CorruptedUsers | Where-Object {$_.IssueType -eq "Disabled But Still Grouped"}
            if ($DisabledButGrouped.Count -gt 0) {
                $DisabledButGrouped | Export-Csv "$Global:OutputPath\Users_Disabled_But_Grouped.csv" -NoTypeInformation
            }
            
            # Accounts with Delegation Rights
            $DelegationAccounts = $AllUsersData | Where-Object {$_.DelegationType -ne "None"}
            if ($DelegationAccounts.Count -gt 0) {
                $DelegationAccounts | Export-Csv "$Global:OutputPath\Users_With_Delegation_Rights.csv" -NoTypeInformation
            }
            
            # Stale Accounts by Type
            $StaleAccounts = $AllUsersData | Where-Object {$_.IsStale -eq "True"}
            if ($StaleAccounts.Count -gt 0) {
                $StaleAccounts | Export-Csv "$Global:OutputPath\Users_Stale_Accounts.csv" -NoTypeInformation
            }
        }
        
        $ProcessingTime = ((Get-Date) - $ScriptStartTime).TotalMinutes
        Write-Log "Enhanced user assessment completed in $([math]::Round($ProcessingTime, 2)) minutes"
        
        # Cleanup
        $Results.Dispose()
        $Searcher.Dispose()
        [GC]::Collect()
        
    } catch {
        Write-Log "Critical error in enhanced user assessment: $($_.Exception.Message)"
        throw
    }
}

# EXECUTE THE ASSESSMENT
Write-Host "`nStarting AD Users Enhanced Assessment..." -ForegroundColor Cyan
Get-ADUsersAssessmentEnhanced
Write-Host "`nEnhanced Users Assessment completed. Results in: $Global:OutputPath" -ForegroundColor Green
