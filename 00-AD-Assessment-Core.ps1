# Enhanced Active Directory Assessment - Core Infrastructure
# Version 5.0 - Complete Universal Edition with ADSI Implementation
# No Active Directory Module or WinRM Dependencies
# Core configuration and utility functions for all assessment scripts

#Requires -Version 5.1

param(
    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ($_ -and !(Test-Path $_ -PathType Leaf)) {
            throw "ConfigFile path '$_' does not exist"
        }
        return $true
    })]
    [string]$ConfigFile,
    
    [Parameter(Mandatory = $false)]
    [ValidateScript({Test-Path $_ -IsValid})]
    [string]$OutputPath = "C:\AD_Assessment",
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$InactiveUserDays,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$InactiveComputerDays,
    
    [Parameter(Mandatory = $false)]
    [bool]$UseAutoDetection = $true
)

#region ADUAC Enumeration - Complete UserAccountControl Flags
Add-Type -TypeDefinition @"
[System.Flags]
public enum ADUAC
{
    SCRIPT                          = 0x0001,
    ACCOUNTDISABLE                  = 0x0002,
    HOMEDIR_REQUIRED                = 0x0008,
    LOCKOUT                         = 0x0010,
    PASSWD_NOTREQD                  = 0x0020,
    PASSWD_CANT_CHANGE              = 0x0040,
    ENCRYPTED_TEXT_PWD_ALLOWED      = 0x0080,
    TEMP_DUPLICATE_ACCOUNT          = 0x0100,
    NORMAL_ACCOUNT                  = 0x0200,
    INTERDOMAIN_TRUST_ACCOUNT       = 0x0800,
    WORKSTATION_TRUST_ACCOUNT       = 0x1000,
    SERVER_TRUST_ACCOUNT            = 0x2000,
    DONT_EXPIRE_PASSWORD            = 0x10000,
    MNS_LOGON_ACCOUNT              = 0x20000,
    SMARTCARD_REQUIRED             = 0x40000,
    TRUSTED_FOR_DELEGATION         = 0x80000,
    NOT_DELEGATED                  = 0x100000,
    USE_DES_KEY_ONLY               = 0x200000,
    DONT_REQ_PREAUTH               = 0x400000,
    PASSWORD_EXPIRED               = 0x800000,
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
}
"@ -ErrorAction SilentlyContinue
#endregion

#region ADSI Helper Functions - ALL WITH GLOBAL SCOPE
function global:Get-ADSIDomainInfo {
    <#
    .SYNOPSIS
    Gets domain information using ADSI
    #>
    try {
        $RootDSE = [ADSI]"LDAP://RootDSE"
        $DomainDN = $RootDSE.defaultNamingContext[0]
        $ConfigDN = $RootDSE.configurationNamingContext[0]
        $SchemaDN = $RootDSE.schemaNamingContext[0]
        
        $Domain = [ADSI]"LDAP://$DomainDN"
        
        # Get domain mode - property with hyphen needs quotes
        $DomainMode = $null
        try {
            if ($Domain.Properties.Contains('msDS-Behavior-Version')) {
                $DomainMode = $Domain.'msDS-Behavior-Version'[0]
            }
        }
        catch {
            # If property doesn't exist, default to 0
            $DomainMode = 0
        }
        
        return @{
            DomainDN = $DomainDN
            ConfigDN = $ConfigDN
            SchemaDN = $SchemaDN
            DomainName = $Domain.name[0]
            NetBIOSName = if ($Domain.nETBIOSName) { $Domain.nETBIOSName[0] } else { "" }
            DomainMode = $DomainMode
            DistinguishedName = $DomainDN
        }
    }
    catch {
        Write-Warning "Failed to get domain info via ADSI: $($_.Exception.Message)"
        return $null
    }
}

function global:Get-ADSIPasswordPolicy {
    <#
    .SYNOPSIS
    Gets password policy using ADSI - Fixed for COM object handling
    #>
    try {
        $DomainInfo = Get-ADSIDomainInfo
        if (!$DomainInfo) { return $null }
        
        # Use DirectoryEntry for better compatibility
        $DE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($DomainInfo.DomainDN)")
        
        # Initialize return values
        $MaxPwdAgeDays = 0
        $MinPwdAgeDays = 0
        
        # Handle maxPwdAge COM object
        try {
            $maxPwdAgeProp = $DE.Properties["maxPwdAge"]
            if ($maxPwdAgeProp -and $maxPwdAgeProp.Count -gt 0) {
                $maxPwdAgeValue = $maxPwdAgeProp[0]
                
                # For COM objects, use InvokeGet
                if ($maxPwdAgeValue -is [System.__ComObject]) {
                    try {
                        # Try to get the actual Int64 value using InvokeGet
                        $actualValue = $DE.InvokeGet("maxPwdAge")
                        if ($actualValue -and $actualValue -ne 0) {
                            # Convert from negative 100-nanosecond intervals to days
                            $MaxPwdAgeDays = [Math]::Abs([Int64]$actualValue) / 864000000000
                            $MaxPwdAgeDays = [int]$MaxPwdAgeDays
                        }
                    }
                    catch {
                        Write-Verbose "Could not get maxPwdAge via InvokeGet: $_"
                        # Use default of 42 days if we can't read it
                        $MaxPwdAgeDays = 42
                    }
                }
                elseif ($maxPwdAgeValue -is [Int64]) {
                    if ($maxPwdAgeValue -ne 0) {
                        $MaxPwdAgeDays = [Math]::Abs($maxPwdAgeValue) / 864000000000
                        $MaxPwdAgeDays = [int]$MaxPwdAgeDays
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error processing maxPwdAge: $_"
            # Use a reasonable default
            $MaxPwdAgeDays = 42
        }
        
        # Handle minPwdAge COM object (similar approach)
        try {
            $minPwdAgeProp = $DE.Properties["minPwdAge"]
            if ($minPwdAgeProp -and $minPwdAgeProp.Count -gt 0) {
                $minPwdAgeValue = $minPwdAgeProp[0]
                
                if ($minPwdAgeValue -is [System.__ComObject]) {
                    try {
                        $actualValue = $DE.InvokeGet("minPwdAge")
                        if ($actualValue -and $actualValue -ne 0) {
                            $MinPwdAgeDays = [Math]::Abs([Int64]$actualValue) / 864000000000
                            $MinPwdAgeDays = [int]$MinPwdAgeDays
                        }
                    }
                    catch {
                        Write-Verbose "Could not get minPwdAge via InvokeGet: $_"
                        $MinPwdAgeDays = 1  # Default to 1 day
                    }
                }
                elseif ($minPwdAgeValue -is [Int64]) {
                    if ($minPwdAgeValue -ne 0) {
                        $MinPwdAgeDays = [Math]::Abs($minPwdAgeValue) / 864000000000
                        $MinPwdAgeDays = [int]$MinPwdAgeDays
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error processing minPwdAge: $_"
            $MinPwdAgeDays = 1
        }
        
        # Get the simple integer values (these work fine based on diagnostic)
        $MinPasswordLength = 0
        if ($DE.Properties["minPwdLength"].Count -gt 0) {
            $MinPasswordLength = [int]$DE.Properties["minPwdLength"][0]
        }
        
        $PasswordHistoryLength = 0
        if ($DE.Properties["pwdHistoryLength"].Count -gt 0) {
            $PasswordHistoryLength = [int]$DE.Properties["pwdHistoryLength"][0]
        }
        
        $LockoutThreshold = 0
        if ($DE.Properties["lockoutThreshold"].Count -gt 0) {
            $LockoutThreshold = [int]$DE.Properties["lockoutThreshold"][0]
        }
        
        # Handle lockout duration and observation window (likely COM objects too)
        $LockoutDuration = 0
        $LockoutObservationWindow = 0
        
        try {
            $lockoutDurationProp = $DE.Properties["lockoutDuration"]
            if ($lockoutDurationProp -and $lockoutDurationProp.Count -gt 0) {
                $lockoutDurationValue = $lockoutDurationProp[0]
                if ($lockoutDurationValue -is [System.__ComObject]) {
                    try {
                        $actualValue = $DE.InvokeGet("lockoutDuration")
                        if ($actualValue) {
                            $LockoutDuration = [Math]::Abs([Int64]$actualValue)
                        }
                    }
                    catch {
                        Write-Verbose "Could not get lockoutDuration: $_"
                    }
                }
                elseif ($lockoutDurationValue -is [Int64]) {
                    $LockoutDuration = [Math]::Abs($lockoutDurationValue)
                }
            }
        }
        catch {
            Write-Verbose "Error processing lockoutDuration: $_"
        }
        
        try {
            $observationWindowProp = $DE.Properties["lockOutObservationWindow"]
            if ($observationWindowProp -and $observationWindowProp.Count -gt 0) {
                $observationWindowValue = $observationWindowProp[0]
                if ($observationWindowValue -is [System.__ComObject]) {
                    try {
                        $actualValue = $DE.InvokeGet("lockOutObservationWindow")
                        if ($actualValue) {
                            $LockoutObservationWindow = [Math]::Abs([Int64]$actualValue)
                        }
                    }
                    catch {
                        Write-Verbose "Could not get lockOutObservationWindow: $_"
                    }
                }
                elseif ($observationWindowValue -is [Int64]) {
                    $LockoutObservationWindow = [Math]::Abs($observationWindowValue)
                }
            }
        }
        catch {
            Write-Verbose "Error processing lockOutObservationWindow: $_"
        }
        
        # Clean up
        $DE.Close()
        $DE.Dispose()
        
        # Return the collected policy information
        return @{
            MaxPasswordAge = $MaxPwdAgeDays
            MinPasswordAge = $MinPwdAgeDays
            MinPasswordLength = $MinPasswordLength
            PasswordHistoryLength = $PasswordHistoryLength
            LockoutThreshold = $LockoutThreshold
            LockoutDuration = $LockoutDuration
            LockoutObservationWindow = $LockoutObservationWindow
        }
    }
    catch {
        Write-Warning "Failed to get password policy via ADSI: $($_.Exception.Message)"
        return $null
    }
}

function global:Search-ADSI {
    <#
    .SYNOPSIS
    Performs ADSI search with paging support
    #>
    param(
        [string]$Filter,
        [string]$SearchBase,
        [string[]]$Properties = @(),
        [int]$PageSize = 1000,
        [string]$SearchScope = "Subtree"
    )
    
    try {
        if (!$SearchBase) {
            $DomainInfo = Get-ADSIDomainInfo
            $SearchBase = $DomainInfo.DomainDN
        }
        
        $Searcher = [adsisearcher]""
        $Searcher.SearchRoot = [ADSI]"LDAP://$SearchBase"
        $Searcher.Filter = $Filter
        $Searcher.PageSize = $PageSize
        $Searcher.SearchScope = $SearchScope
        
        if ($Properties.Count -gt 0) {
            $Searcher.PropertiesToLoad.AddRange($Properties)
        }
        
        $Results = $Searcher.FindAll()
        
        $Objects = @()
        foreach ($Result in $Results) {
            $Object = @{}
            foreach ($Property in $Result.Properties.Keys) {
                $Value = $Result.Properties[$Property]
                if ($Value.Count -eq 1) {
                    $Object[$Property] = $Value[0]
                } else {
                    $Object[$Property] = $Value
                }
            }
            $Objects += [PSCustomObject]$Object
        }
        
        $Results.Dispose()
        $Searcher.Dispose()
        
        return $Objects
    }
    catch {
        Write-Error "ADSI Search failed: $($_.Exception.Message)"
        return @()
    }
}

function global:ConvertTo-DateTime {
    <#
    .SYNOPSIS
    Converts various AD timestamp formats to DateTime
    #>
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
                # Handle YYYYMMDDHHMMSS.0Z format
                $dateString = $Value.ToString()
                if ($dateString -match '(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})') {
                    return [DateTime]::ParseExact($Matches[0], "yyyyMMddHHmmss", $null)
                }
                return $null
            }
            "UTCTime" {
                return [DateTime]::ParseExact($Value, "yyMMddHHmmssZ", $null)
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
#endregion

#region Configuration Management
$Global:Config = @{}

function global:Get-ADAssessmentConfiguration {
    param(
        [string]$ConfigFilePath,
        [bool]$AutoDetect = $true
    )
    
    # Default configuration with secure fallbacks
    $DefaultConfig = @{
        # Thresholds
        InactiveUserDays = 90
        InactiveComputerDays = 90
        StalePasswordDays = 180
        ExcessiveBadPasswordCount = 100
        OldComputerPasswordDays = 60
        MaxDenyACEs = 10
        CircularGroupDepthLimit = 20
        SPNDuplicateThreshold = 1
        
        # Batch Processing
        BatchSize = 100
        MaxParallelJobs = 8
        ProgressUpdateInterval = 10
        ComputerProgressInterval = 5
        
        # Corruption Detection Severity Thresholds
        CriticalThresholds = @{
            MissingCoreAttributes = $true
            TombstonedObjects = $true
            UnreadableACLs = $true
        }
        
        HighRiskThresholds = @{
            UnconstrainedDelegation = $true
            PasswordNeverExpiresWithDelegation = $true
            ExcessiveDenyACEs = 10
            EndOfLifeOS = $true
            DuplicateSPNs = $true
        }
        
        MediumRiskThresholds = @{
            OrphanedSIDHistory = $true
            ExcessiveBadPasswordCount = 100
            StaleActiveAccounts = 90
            OldComputerPasswords = 60
        }
        
        # Output Settings
        OutputSettings = @{
            ExportBatchSize = 1000
            UseUTF8Encoding = $true
            PowerBIOptimized = $true
            GenerateExecutiveSummary = $true
        }
        
        # Security Settings
        SecuritySettings = @{
            PrivilegedGroups = @(
                "Domain Admins", "Enterprise Admins", "Schema Admins",
                "Administrators", "Account Operators", "Backup Operators",
                "Server Operators", "Domain Controllers", "Read-only Domain Controllers",
                "Group Policy Creator Owners", "Cryptographic Operators"
            )
            ServiceAccountIdentifiers = @("svc", "service", "app", "sql", "system", "iis")
            AdminAccountIdentifiers = @("admin", "adm", "_a$", "-admin", ".admin")
        }
        
        # Assessment Features
        Features = @{
            EnableCircularGroupDetection = $true
            EnableAdvancedSPNAnalysis = $true
            EnableCMDBValidation = $true
            EnableDNSAssessment = $true
            EnableDHCPAssessment = $true
            EnableCertificateAssessment = $true
            EnableGPOAssessment = $true
            EnableSharesAssessment = $true
            EnablePrintersAssessment = $true
            EnableInfrastructureAssessment = $true
            EnableApplicationsAssessment = $true
            EnableSecurityAssessment = $true
        }
    }
    
    # Load from file if specified
    if ($ConfigFilePath -and (Test-Path $ConfigFilePath)) {
        Write-Host "Loading configuration from: $ConfigFilePath" -ForegroundColor Green
        try {
            $FileConfig = Import-PowerShellDataFile -Path $ConfigFilePath
            foreach ($Key in $FileConfig.Keys) {
                $DefaultConfig[$Key] = $FileConfig[$Key]
            }
            Write-Host "Configuration loaded successfully from file" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to load config file: $($_.Exception.Message). Using auto-detection."
            $AutoDetect = $true
        }
    }
    
    # Auto-detect organizational settings if enabled
    if ($AutoDetect) {
        Write-Host "Auto-detecting organizational settings via ADSI..." -ForegroundColor Yellow
        
        try {
            $PasswordPolicy = Get-ADSIPasswordPolicy
            if ($PasswordPolicy) {
                # Use password max age as baseline for inactive user detection
                if ($PasswordPolicy.MaxPasswordAge -gt 0) {
                    $DefaultConfig.InactiveUserDays = [math]::Min($PasswordPolicy.MaxPasswordAge, 120)
                    Write-Host "Auto-detected inactive user threshold: $($DefaultConfig.InactiveUserDays) days" -ForegroundColor Green
                }
                
                # Set stale password threshold to 2x max password age
                if ($PasswordPolicy.MaxPasswordAge -gt 0) {
                    $DefaultConfig.StalePasswordDays = [math]::Min($PasswordPolicy.MaxPasswordAge * 2, 365)
                    Write-Host "Auto-detected stale password threshold: $($DefaultConfig.StalePasswordDays) days" -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Warning "Auto-detection failed: $($_.Exception.Message). Using secure defaults."
        }
        
        try {
            $DomainInfo = Get-ADSIDomainInfo
            if ($DomainInfo) {
                $DefaultConfig.DomainFunctionalLevel = $DomainInfo.DomainMode
                Write-Host "Detected domain functional level: $($DomainInfo.DomainMode)" -ForegroundColor Green
                
                # Adjust features based on functional level
                if ($DomainInfo.DomainMode -lt 3) { # Windows2008R2Domain = 4
                    Write-Warning "Domain functional level below 2008 R2. Some features may be limited."
                    $DefaultConfig.SupportsFineGrainedPasswordPolicy = $false
                }
                else {
                    $DefaultConfig.SupportsFineGrainedPasswordPolicy = $true
                }
            }
        }
        catch {
            Write-Warning "Could not detect domain functional level: $($_.Exception.Message)"
            $DefaultConfig.SupportsFineGrainedPasswordPolicy = $true
        }
    }
    
    return $DefaultConfig
}

function global:Get-UACSummary {
    <#
    .SYNOPSIS
    Converts UserAccountControl value to human-readable flags using ADUAC enumeration
    #>
    param(
        [Parameter(Mandatory = $true)]
        [int]$UACValue
    )
    
    $UACFlags = [ADUAC]$UACValue
    $ActiveFlags = @()
    
    # Check each flag and build readable list
    $AllFlags = [Enum]::GetValues([ADUAC])
    foreach ($Flag in $AllFlags) {
        if ($UACFlags.HasFlag($Flag)) {
            $ActiveFlags += $Flag.ToString()
        }
    }
    
    return @{
        RawValue = $UACValue
        Flags = $ActiveFlags
        FlagsString = $ActiveFlags -join '; '
        IsDisabled = $UACFlags.HasFlag([ADUAC]::ACCOUNTDISABLE)
        IsLocked = $UACFlags.HasFlag([ADUAC]::LOCKOUT)
        PasswordNeverExpires = $UACFlags.HasFlag([ADUAC]::DONT_EXPIRE_PASSWORD)
        PasswordNotRequired = $UACFlags.HasFlag([ADUAC]::PASSWD_NOTREQD)
        SmartCardRequired = $UACFlags.HasFlag([ADUAC]::SMARTCARD_REQUIRED)
        TrustedForDelegation = $UACFlags.HasFlag([ADUAC]::TRUSTED_FOR_DELEGATION)
        TrustedForAuthDelegation = $UACFlags.HasFlag([ADUAC]::TRUSTED_TO_AUTH_FOR_DELEGATION)
        DontRequirePreauth = $UACFlags.HasFlag([ADUAC]::DONT_REQ_PREAUTH)
        IsNormalAccount = $UACFlags.HasFlag([ADUAC]::NORMAL_ACCOUNT)
        IsComputerAccount = $UACFlags.HasFlag([ADUAC]::WORKSTATION_TRUST_ACCOUNT) -or $UACFlags.HasFlag([ADUAC]::SERVER_TRUST_ACCOUNT)
        PasswordExpired = $UACFlags.HasFlag([ADUAC]::PASSWORD_EXPIRED)
        NotDelegated = $UACFlags.HasFlag([ADUAC]::NOT_DELEGATED)
        UseDESKeyOnly = $UACFlags.HasFlag([ADUAC]::USE_DES_KEY_ONLY)
    }
}

function global:Test-AccountType {
    <#
    .SYNOPSIS
    Intelligently determines account type based on naming patterns and UAC flags
    #>
    param(
        [string]$SamAccountName,
        [string]$Description,
        [object]$UACAnalysis,
        [int]$AdminCount = 0
    )
    
    $ServiceIndicators = $Global:Config.SecuritySettings.ServiceAccountIdentifiers
    $AdminIndicators = $Global:Config.SecuritySettings.AdminAccountIdentifiers
    
    # Check for service account patterns
    $IsServiceAccount = $false
    foreach ($Pattern in $ServiceIndicators) {
        if ($SamAccountName -match $Pattern -or $Description -match $Pattern) {
            $IsServiceAccount = $true
            break
        }
    }
    
    # Check for admin account patterns
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
    
    # Determine account type with precedence rules
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

function global:Get-CorruptionLevel {
    <#
    .SYNOPSIS
    Determines corruption level based on configurable severity thresholds
    #>
    param(
        [array]$Issues
    )
    
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
#endregion

#region Utility Functions
function global:Get-ETA {
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

function global:Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Write-Host $LogMessage
    # Don't try to write to file until we know directory exists
}

function global:Initialize-LogFile {
    # This function creates the log file after directory is confirmed
    param([string]$Path)
    
    try {
        # Test writing to the log file
        "Log initialized at $(Get-Date)" | Out-File -FilePath $Path -Force
        return $true
    }
    catch {
        Write-Warning "Cannot write to log file: $($_.Exception.Message)"
        return $false
    }
}
#endregion

#region Global Configuration Initialization
# Load configuration on script start
Write-Host "Initializing Enhanced AD Assessment Core Infrastructure..." -ForegroundColor Cyan
Write-Host "Script version timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

$Global:Config = Get-ADAssessmentConfiguration -ConfigFilePath $ConfigFile -AutoDetect $UseAutoDetection

# Override with command-line parameters if specified
if ($PSBoundParameters.ContainsKey('InactiveUserDays')) {
    $Global:Config.InactiveUserDays = $InactiveUserDays
    Write-Host "Using command-line inactive user threshold: $InactiveUserDays days" -ForegroundColor Green
}

if ($PSBoundParameters.ContainsKey('InactiveComputerDays')) {
    $Global:Config.InactiveComputerDays = $InactiveComputerDays
    Write-Host "Using command-line inactive computer threshold: $InactiveComputerDays days" -ForegroundColor Green
}

# Global variables
$Global:OutputPath = $OutputPath
$Global:StartTime = Get-Date
$Global:ProgressPreference = 'Continue'

# Create output directory first - before any log file attempts
Write-Host "Checking output directory: $Global:OutputPath" -ForegroundColor Yellow

if (!(Test-Path $Global:OutputPath)) {
    Write-Host "Output directory does not exist. Attempting to create..." -ForegroundColor Yellow
    try {
        New-Item -ItemType Directory -Path $Global:OutputPath -Force -ErrorAction Stop | Out-Null
        Write-Host "Output directory created successfully at: $Global:OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create output directory at $Global:OutputPath : $($_.Exception.Message)"
        
        # Try current directory as fallback
        $Global:OutputPath = Join-Path (Get-Location) "AD_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Write-Host "Attempting to use fallback directory: $Global:OutputPath" -ForegroundColor Yellow
        
        try {
            New-Item -ItemType Directory -Path $Global:OutputPath -Force -ErrorAction Stop | Out-Null
            Write-Host "Fallback directory created successfully" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to create fallback directory. Exiting."
            exit 1
        }
    }
}
else {
    Write-Host "Output directory already exists: $Global:OutputPath" -ForegroundColor Green
}

# Now create log file after directory is confirmed to exist
$Global:LogFile = Join-Path $Global:OutputPath "AD_Assessment_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Write-Host "Initializing log file: $Global:LogFile" -ForegroundColor Yellow

if (Initialize-LogFile -Path $Global:LogFile) {
    Write-Host "Log file initialized successfully" -ForegroundColor Green
    # Redefine Write-Log to actually write to file now
    function global:Write-Log {
        param($Message)
        $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
        Write-Host $LogMessage
        try {
            $LogMessage | Out-File -FilePath $Global:LogFile -Append -ErrorAction Stop
        }
        catch {
            # Silently continue if we can't write to log
        }
    }
}
else {
    Write-Warning "Log file could not be initialized. Continuing without file logging."
}

Write-Host "`nConfiguration Summary:" -ForegroundColor Yellow
Write-Host "- Inactive User Threshold: $($Global:Config.InactiveUserDays) days" -ForegroundColor White
Write-Host "- Inactive Computer Threshold: $($Global:Config.InactiveComputerDays) days" -ForegroundColor White
Write-Host "- Stale Password Threshold: $($Global:Config.StalePasswordDays) days" -ForegroundColor White
Write-Host "- Output Directory: $Global:OutputPath" -ForegroundColor White
Write-Host "- Log File: $Global:LogFile" -ForegroundColor White
Write-Host "- Using ADSI (No AD Module Required)" -ForegroundColor Green
Write-Host ""

Write-Log "Enhanced AD Assessment Core Infrastructure Initialized"
Write-Log "Configuration: Inactive Users: $($Global:Config.InactiveUserDays)d, Inactive Computers: $($Global:Config.InactiveComputerDays)d"
Write-Log "ADSI-based implementation - No AD Module or WinRM dependencies"

# Test ADSI connectivity
try {
    $DomainTest = Get-ADSIDomainInfo
    if ($DomainTest) {
        Write-Host "ADSI connectivity verified - Domain: $($DomainTest.DomainName)" -ForegroundColor Green
        Write-Log "ADSI connectivity verified - Domain: $($DomainTest.DomainName)"
    }
    else {
        Write-Warning "ADSI connectivity test failed"
    }
}
catch {
    Write-Error "Failed to initialize ADSI connectivity: $($_.Exception.Message)"
    exit 1
}

Write-Host "Core infrastructure ready. Run individual assessment scripts." -ForegroundColor Green
#endregion
