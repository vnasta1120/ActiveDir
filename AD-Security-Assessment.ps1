# AD Security Assessment with ADSI Implementation
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
if ($true) {
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

function Get-ADSecurityAssessment {
    Write-Log "=== Starting AD Security Assessment (ADSI) ==="
    
    $ScriptStartTime = Get-Date
    
    # Get domain info
    $DomainInfo = Get-ADSIDomainInfo
    if (!$DomainInfo) {
        Write-Error "Failed to get domain information"
        return
    }
    
    try {
        # 1. Password Policy Analysis
        Write-Host "Getting Password Policy via ADSI..." -ForegroundColor Yellow
        
        $PasswordPolicy = Get-ADSIPasswordPolicy
        if ($PasswordPolicy) {
            # Calculate lockout duration and observation window in minutes
            $LockoutDurationMinutes = 0
            if ($PasswordPolicy.LockoutDuration -ne 0) {
                $LockoutDurationMinutes = [int]($PasswordPolicy.LockoutDuration / 600000000)
            }
            
            $LockoutObservationMinutes = 0
            if ($PasswordPolicy.LockoutObservationWindow -ne 0) {
                $LockoutObservationMinutes = [int]($PasswordPolicy.LockoutObservationWindow / 600000000)
            }
            
            $PasswordPolicyReport = [PSCustomObject]@{
                ComplexityEnabled = "Unknown"  # Not easily available via ADSI
                MinPasswordLength = $PasswordPolicy.MinPasswordLength
                PasswordHistoryCount = $PasswordPolicy.PasswordHistoryLength
                MaxPasswordAgeDays = $PasswordPolicy.MaxPasswordAge
                MinPasswordAgeDays = $PasswordPolicy.MinPasswordAge
                LockoutDurationMinutes = $LockoutDurationMinutes
                LockoutThreshold = $PasswordPolicy.LockoutThreshold
                LockoutObservationWindowMinutes = $LockoutObservationMinutes
                ReversibleEncryptionEnabled = "Unknown"  # Not easily available via ADSI
                AutoDetectedInactiveThreshold = $Global:Config.InactiveUserDays
                AssessmentMethod = "ADSI"
            }
            
            $PasswordPolicyReport | Export-Csv "$Global:OutputPath\Security_Password_Policy.csv" -NoTypeInformation
        }
        
        # 2. Fine-Grained Password Policies (if supported)
        Write-Host "Checking for Fine-Grained Password Policies..." -ForegroundColor Yellow
        
        $FGPPDetails = @()
        if ($Global:Config.SupportsFineGrainedPasswordPolicy) {
            try {
                $FGPPSearcher = [adsisearcher]"(objectClass=msDS-PasswordSettings)"
                $FGPPSearcher.SearchRoot = [ADSI]"LDAP://CN=Password Settings Container,CN=System,$($DomainInfo.DomainDN)"
                $FGPPSearcher.PageSize = 100
                $FGPPSearcher.PropertiesToLoad.AddRange(@(
                    'name', 'msds-passwordsettingsprecedence', 'msds-minimumpasswordlength',
                    'msds-passwordhistorylength', 'msds-maximumpasswordage', 'msds-passwordcomplexityenabled',
                    'msds-psoappliesto'
                ))
                
                $FGPPResults = $FGPPSearcher.FindAll()
                
                foreach ($FGPPResult in $FGPPResults) {
                    $FGPPProps = $FGPPResult.Properties
                    
                    # Get applied to objects
                    $AppliesTo = ""
                    if ($FGPPProps['msds-psoappliesto']) {
                        $AppliedObjects = @()
                        foreach ($AppliedDN in $FGPPProps['msds-psoappliesto']) {
                            # Extract name from DN
                            if ($AppliedDN -match '^CN=([^,]+)') {
                                $AppliedObjects += $Matches[1]
                            }
                        }
                        $AppliesTo = $AppliedObjects -join '; '
                    }
                    
                    # Handle password age with Int64.MinValue check and safe conversion
                    $MaxPasswordAgeDays = 0
                    if ($FGPPProps['msds-maximumpasswordage']) {
                        $MaxPwdAgeValue = $FGPPProps['msds-maximumpasswordage'][0]
                        if ($MaxPwdAgeValue -ne [Int64]::MinValue -and $MaxPwdAgeValue -ne 0) {
                            # Password ages are stored as negative values
                            # Use safe conversion method
                            try {
                                $MaxPasswordAgeDays = [int]([Math]::Abs([decimal]$MaxPwdAgeValue) / 864000000000)
                            }
                            catch {
                                # Fallback: manually handle the conversion
                                if ($MaxPwdAgeValue -lt 0) {
                                    $MaxPasswordAgeDays = [int]((-$MaxPwdAgeValue) / 864000000000)
                                } else {
                                    $MaxPasswordAgeDays = [int]($MaxPwdAgeValue / 864000000000)
                                }
                            }
                        }
                    }
                    
                    $FGPPDetails += [PSCustomObject]@{
                        Name = if ($FGPPProps['name']) { $FGPPProps['name'][0] } else { "" }
                        Precedence = if ($FGPPProps['msds-passwordsettingsprecedence']) { $FGPPProps['msds-passwordsettingsprecedence'][0] } else { 0 }
                        MinPasswordLength = if ($FGPPProps['msds-minimumpasswordlength']) { $FGPPProps['msds-minimumpasswordlength'][0] } else { 0 }
                        PasswordHistoryCount = if ($FGPPProps['msds-passwordhistorylength']) { $FGPPProps['msds-passwordhistorylength'][0] } else { 0 }
                        MaxPasswordAgeDays = $MaxPasswordAgeDays
                        ComplexityEnabled = if ($FGPPProps['msds-passwordcomplexityenabled']) { [bool]$FGPPProps['msds-passwordcomplexityenabled'][0] } else { $false }
                        AppliesTo = $AppliesTo
                        AppliedObjectCount = if ($FGPPProps['msds-psoappliesto']) { $FGPPProps['msds-psoappliesto'].Count } else { 0 }
                    }
                }
                
                $FGPPResults.Dispose()
                $FGPPSearcher.Dispose()
                
                if ($FGPPDetails.Count -gt 0) {
                    $FGPPDetails | Export-Csv "$Global:OutputPath\Security_Fine_Grained_Password_Policies.csv" -NoTypeInformation
                }
            } catch {
                Write-Log "Error retrieving Fine-Grained Password Policies: $($_.Exception.Message)"
            }
        }
        
        # 3. Privileged Groups Analysis with configurable group list
        Write-Host "Analyzing Privileged Groups..." -ForegroundColor Yellow
        
        $PrivilegedGroups = $Global:Config.SecuritySettings.PrivilegedGroups
        $PrivilegedGroupMembers = @()
        $GroupAnalysis = @()
        
        foreach ($GroupName in $PrivilegedGroups) {
            try {
                # Search for the group
                $GroupSearcher = [adsisearcher]"(&(objectCategory=group)(|(name=$GroupName)(samAccountName=$GroupName)))"
                $GroupSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
                $GroupSearcher.PropertiesToLoad.AddRange(@('name', 'samaccountname', 'distinguishedname', 'member', 'description'))
                
                $GroupResults = $GroupSearcher.FindAll()
                
                foreach ($GroupResult in $GroupResults) {
                    $GroupProps = $GroupResult.Properties
                    $GroupDN = $GroupProps['distinguishedname'][0]
                    $ActualGroupName = $GroupProps['name'][0]
                    $GroupSamAccountName = if ($GroupProps['samaccountname']) { $GroupProps['samaccountname'][0] } else { "" }
                    $GroupDescription = if ($GroupProps['description']) { $GroupProps['description'][0] } else { "" }
                    $Members = if ($GroupProps['member']) { $GroupProps['member'] } else { @() }
                    
                    $GroupAnalysis += [PSCustomObject]@{
                        GroupName = $ActualGroupName
                        GroupSamAccountName = $GroupSamAccountName
                        GroupDescription = $GroupDescription
                        MemberCount = $Members.Count
                        DistinguishedName = $GroupDN
                    }
                    
                    # Analyze each member
                    foreach ($MemberDN in $Members) {
                        try {
                            # Get member details
                            $MemberSearcher = [adsisearcher]"(distinguishedName=$MemberDN)"
                            $MemberSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
                            $MemberSearcher.PropertiesToLoad.AddRange(@(
                                'name', 'samaccountname', 'objectclass', 'useraccountcontrol', 
                                'lastlogontimestamp', 'pwdlastset', 'objectsid'
                            ))
                            
                            $MemberResults = $MemberSearcher.FindAll()
                            
                            if ($MemberResults.Count -gt 0) {
                                $MemberProps = $MemberResults[0].Properties
                                $MemberName = if ($MemberProps['name']) { $MemberProps['name'][0] } else { "" }
                                $MemberSamAccountName = if ($MemberProps['samaccountname']) { $MemberProps['samaccountname'][0] } else { "" }
                                $MemberObjectClass = if ($MemberProps['objectclass']) { $MemberProps['objectclass'][-1] } else { "unknown" }
                                $MemberUAC = if ($MemberProps['useraccountcontrol']) { [int]$MemberProps['useraccountcontrol'][0] } else { 0 }
                                $MemberLastLogon = ConvertTo-DateTime -Value $MemberProps['lastlogontimestamp'][0] -Format "FileTime"
                                $MemberPwdLastSet = ConvertTo-DateTime -Value $MemberProps['pwdlastset'][0] -Format "FileTime"
                                $MemberSID = if ($MemberProps['objectsid']) { 
                                    try {
                                        (New-Object System.Security.Principal.SecurityIdentifier($MemberProps['objectsid'][0], 0)).Value
                                    } catch {
                                        "Error reading SID"
                                    }
                                } else { "" }
                                
                                # Enhanced with ADUAC analysis for user members
                                $UACFlags = ""
                                $PasswordNeverExpires = $false
                                $TrustedForDelegation = $false
                                $IsEnabled = $true
                                
                                if ($MemberObjectClass -eq "user") {
                                    $UACAnalysis = Get-UACSummary -UACValue $MemberUAC
                                    $UACFlags = $UACAnalysis.FlagsString
                                    $PasswordNeverExpires = $UACAnalysis.PasswordNeverExpires
                                    $TrustedForDelegation = $UACAnalysis.TrustedForDelegation
                                    $IsEnabled = !$UACAnalysis.IsDisabled
                                }
                                
                                $PrivilegedGroupMembers += [PSCustomObject]@{
                                    GroupName = $ActualGroupName
                                    GroupSamAccountName = $GroupSamAccountName
                                    MemberName = $MemberName
                                    MemberSamAccountName = $MemberSamAccountName
                                    MemberType = $MemberObjectClass
                                    MemberSID = $MemberSID
                                    MemberDistinguishedName = $MemberDN
                                    Enabled = $IsEnabled
                                    LastLogonDate = $MemberLastLogon
                                    PasswordLastSet = $MemberPwdLastSet
                                    UACFlags = $UACFlags
                                    PasswordNeverExpires = $PasswordNeverExpires
                                    TrustedForDelegation = $TrustedForDelegation
                                    RiskLevel = if ($TrustedForDelegation -and $PasswordNeverExpires) { "High" } 
                                               elseif ($TrustedForDelegation -or $PasswordNeverExpires -or !$IsEnabled) { "Medium" } 
                                               else { "Low" }
                                }
                            }
                            
                            $MemberResults.Dispose()
                            $MemberSearcher.Dispose()
                            
                        } catch {
                            Write-Log "Error analyzing member $MemberDN : $($_.Exception.Message)"
                        }
                    }
                }
                
                $GroupResults.Dispose()
                $GroupSearcher.Dispose()
                
            } catch {
                Write-Log "Error finding group $GroupName : $($_.Exception.Message)"
            }
        }
        
        # Export privileged group analysis
        if ($GroupAnalysis.Count -gt 0) {
            $GroupAnalysis | Export-Csv "$Global:OutputPath\Security_Privileged_Groups.csv" -NoTypeInformation
        }
        
        if ($PrivilegedGroupMembers.Count -gt 0) {
            $PrivilegedGroupMembers | Export-Csv "$Global:OutputPath\Security_Privileged_Group_Members.csv" -NoTypeInformation
        }
        
        # 4. Stale/Inactive Privileged Accounts using configurable threshold
        Write-Host "Checking for stale privileged accounts..." -ForegroundColor Yellow
        
        $StaleThreshold = (Get-Date).AddDays(-$Global:Config.InactiveUserDays)
        $StalePrivAccounts = @()
        $PrivUsers = $PrivilegedGroupMembers | Where-Object {$_.MemberType -eq "user"} | Select-Object -ExpandProperty MemberSamAccountName -Unique
        
        foreach ($UserSamAccountName in $PrivUsers) {
            $UserMembership = $PrivilegedGroupMembers | Where-Object {$_.MemberSamAccountName -eq $UserSamAccountName} | Select-Object -First 1
            
            if ($UserMembership) {
                $IsStale = (!$UserMembership.Enabled) -or 
                          ($UserMembership.LastLogonDate -and $UserMembership.LastLogonDate -lt $StaleThreshold) -or
                          ($UserMembership.PasswordLastSet -and $UserMembership.PasswordLastSet -lt (Get-Date).AddDays(-$Global:Config.StalePasswordDays))
                
                if ($IsStale) {
                    $StaleReason = @()
                    if (!$UserMembership.Enabled) { $StaleReason += "Disabled" }
                    if ($UserMembership.LastLogonDate -and $UserMembership.LastLogonDate -lt $StaleThreshold) { $StaleReason += "Inactive ($($Global:Config.InactiveUserDays)+ days)" }
                    if ($UserMembership.PasswordLastSet -and $UserMembership.PasswordLastSet -lt (Get-Date).AddDays(-$Global:Config.StalePasswordDays)) { $StaleReason += "Old password ($($Global:Config.StalePasswordDays)+ days)" }
                    
                    $StalePrivAccounts += [PSCustomObject]@{
                        UserName = $UserMembership.MemberName
                        SamAccountName = $UserMembership.MemberSamAccountName
                        PrivilegedGroups = ($PrivilegedGroupMembers | Where-Object {$_.MemberSamAccountName -eq $UserSamAccountName} | Select-Object -ExpandProperty GroupName) -join '; '
                        Enabled = $UserMembership.Enabled
                        LastLogon = $UserMembership.LastLogonDate
                        PasswordLastSet = $UserMembership.PasswordLastSet
                        UACFlags = $UserMembership.UACFlags
                        PasswordNeverExpires = $UserMembership.PasswordNeverExpires
                        Status = $StaleReason -join '; '
                        RiskLevel = $UserMembership.RiskLevel
                        RecommendedAction = if (!$UserMembership.Enabled) { "Remove from privileged groups or delete account" } else { "Review account necessity and update access" }
                    }
                }
            }
        }
        
        if ($StalePrivAccounts.Count -gt 0) {
            $StalePrivAccounts | Export-Csv "$Global:OutputPath\Security_Stale_Privileged_Accounts.csv" -NoTypeInformation
        }
        
        # 5. Built-in Administrator Account Analysis
        Write-Host "Analyzing Built-in Administrator account..." -ForegroundColor Yellow
        
        try {
            $AdminSearcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(objectSid=*-500))"
            $AdminSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
            $AdminSearcher.PropertiesToLoad.AddRange(@(
                'name', 'samaccountname', 'useraccountcontrol', 'lastlogontimestamp', 
                'pwdlastset', 'description', 'badpwdcount'
            ))
            
            $AdminResults = $AdminSearcher.FindAll()
            $BuiltinAdminAnalysis = @()
            
            foreach ($AdminResult in $AdminResults) {
                $AdminProps = $AdminResult.Properties
                $AdminUAC = if ($AdminProps['useraccountcontrol']) { [int]$AdminProps['useraccountcontrol'][0] } else { 0 }
                $AdminUACAnalysis = Get-UACSummary -UACValue $AdminUAC
                
                $BuiltinAdminAnalysis += [PSCustomObject]@{
                    Name = if ($AdminProps['name']) { $AdminProps['name'][0] } else { "" }
                    SamAccountName = if ($AdminProps['samaccountname']) { $AdminProps['samaccountname'][0] } else { "" }
                    Description = if ($AdminProps['description']) { $AdminProps['description'][0] } else { "" }
                    Enabled = !$AdminUACAnalysis.IsDisabled
                    LastLogonDate = ConvertTo-DateTime -Value $AdminProps['lastlogontimestamp'][0] -Format "FileTime"
                    PasswordLastSet = ConvertTo-DateTime -Value $AdminProps['pwdlastset'][0] -Format "FileTime"
                    BadPasswordCount = if ($AdminProps['badpwdcount']) { $AdminProps['badpwdcount'][0] } else { 0 }
                    PasswordNeverExpires = $AdminUACAnalysis.PasswordNeverExpires
                    UACFlags = $AdminUACAnalysis.FlagsString
                    SecurityRecommendation = if (!$AdminUACAnalysis.IsDisabled) { "Consider disabling or renaming built-in Administrator account" } else { "Good - Built-in Administrator is disabled" }
                    RiskLevel = if (!$AdminUACAnalysis.IsDisabled) { "High" } else { "Low" }
                }
            }
            
            $AdminResults.Dispose()
            $AdminSearcher.Dispose()
            
            if ($BuiltinAdminAnalysis.Count -gt 0) {
                $BuiltinAdminAnalysis | Export-Csv "$Global:OutputPath\Security_Builtin_Administrator.csv" -NoTypeInformation
            }
            
        } catch {
            Write-Log "Error analyzing built-in Administrator account: $($_.Exception.Message)"
        }
        
        # 6. Service Account Security Analysis
        Write-Host "Analyzing Service Account Security..." -ForegroundColor Yellow
        
        $ServiceAccountSecurityAnalysis = @()
        
        # Find service accounts using naming patterns
        foreach ($Pattern in $Global:Config.SecuritySettings.ServiceAccountIdentifiers) {
            $ServiceSearcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(|(samAccountName=*$Pattern*)(description=*$Pattern*)))"
            $ServiceSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
            $ServiceSearcher.PageSize = 1000
            $ServiceSearcher.PropertiesToLoad.AddRange(@(
                'name', 'samaccountname', 'useraccountcontrol', 'serviceprincipalname',
                'lastlogontimestamp', 'pwdlastset', 'description', 'memberof'
            ))
            
            $ServiceResults = $ServiceSearcher.FindAll()
            
            foreach ($ServiceResult in $ServiceResults) {
                $ServiceProps = $ServiceResult.Properties
                $ServiceUAC = if ($ServiceProps['useraccountcontrol']) { [int]$ServiceProps['useraccountcontrol'][0] } else { 0 }
                $ServiceUACAnalysis = Get-UACSummary -UACValue $ServiceUAC
                
                # Check if it's in privileged groups
                $IsPrivileged = $false
                $PrivilegedGroupsList = @()
                if ($ServiceProps['memberof']) {
                    foreach ($GroupDN in $ServiceProps['memberof']) {
                        foreach ($PrivGroupName in $PrivilegedGroups) {
                            if ($GroupDN -like "*CN=$PrivGroupName,*") {
                                $IsPrivileged = $true
                                $PrivilegedGroupsList += $PrivGroupName
                            }
                        }
                    }
                }
                
                $SecurityIssues = @()
                $RiskLevel = "Low"
                
                # Security analysis
                if ($ServiceUACAnalysis.PasswordNeverExpires -and $ServiceUACAnalysis.TrustedForDelegation) {
                    $SecurityIssues += "Password never expires with delegation"
                    $RiskLevel = "High"
                }
                
                if ($IsPrivileged) {
                    $SecurityIssues += "Has privileged group membership"
                    if ($RiskLevel -eq "Low") { $RiskLevel = "Medium" }
                }
                
                if ($ServiceUACAnalysis.TrustedForDelegation) {
                    $SecurityIssues += "Unconstrained delegation enabled"
                    $RiskLevel = "High"
                }
                
                if ($ServiceUACAnalysis.DontRequirePreauth) {
                    $SecurityIssues += "Kerberos preauth not required"
                    $RiskLevel = "High"
                }
                
                $ServiceAccountSecurityAnalysis += [PSCustomObject]@{
                    ServiceAccountName = if ($ServiceProps['samaccountname']) { $ServiceProps['samaccountname'][0] } else { "" }
                    DisplayName = if ($ServiceProps['name']) { $ServiceProps['name'][0] } else { "" }
                    Description = if ($ServiceProps['description']) { $ServiceProps['description'][0] } else { "" }
                    Enabled = !$ServiceUACAnalysis.IsDisabled
                    HasSPN = if ($ServiceProps['serviceprincipalname']) { $ServiceProps['serviceprincipalname'].Count -gt 0 } else { $false }
                    SPNCount = if ($ServiceProps['serviceprincipalname']) { $ServiceProps['serviceprincipalname'].Count } else { 0 }
                    IsPrivileged = $IsPrivileged
                    PrivilegedGroups = $PrivilegedGroupsList -join '; '
                    PasswordNeverExpires = $ServiceUACAnalysis.PasswordNeverExpires
                    TrustedForDelegation = $ServiceUACAnalysis.TrustedForDelegation
                    DontRequirePreauth = $ServiceUACAnalysis.DontRequirePreauth
                    SecurityIssues = $SecurityIssues -join '; '
                    RiskLevel = $RiskLevel
                    LastLogonDate = ConvertTo-DateTime -Value $ServiceProps['lastlogontimestamp'][0] -Format "FileTime"
                    PasswordLastSet = ConvertTo-DateTime -Value $ServiceProps['pwdlastset'][0] -Format "FileTime"
                    UACFlags = $ServiceUACAnalysis.FlagsString
                }
            }
            
            $ServiceResults.Dispose()
            $ServiceSearcher.Dispose()
        }
        
        # Remove duplicates and export
        $ServiceAccountSecurityAnalysis = $ServiceAccountSecurityAnalysis | Sort-Object ServiceAccountName -Unique
        if ($ServiceAccountSecurityAnalysis.Count -gt 0) {
            $ServiceAccountSecurityAnalysis | Export-Csv "$Global:OutputPath\Security_Service_Accounts_Analysis.csv" -NoTypeInformation
        }
        
        # 7. Enhanced Security Summary with configurable thresholds
        $SecurityStats = [PSCustomObject]@{
            # Password Policy
            PasswordMinLength = if ($PasswordPolicy) { $PasswordPolicy.MinPasswordLength } else { "Unknown" }
            PasswordMaxAgeDays = if ($PasswordPolicy) { $PasswordPolicy.MaxPasswordAge } else { "Unknown" }
            LockoutThreshold = if ($PasswordPolicy) { $PasswordPolicy.LockoutThreshold } else { "Unknown" }
            
            # Configuration
            ConfiguredInactiveThreshold = $Global:Config.InactiveUserDays
            ConfiguredStalePasswordThreshold = $Global:Config.StalePasswordDays
            
            # Fine-Grained Policies
            FineGrainedPolicies = $FGPPDetails.Count
            
            # Privileged Groups Analysis
            PrivilegedGroupsAnalyzed = $PrivilegedGroups.Count
            PrivilegedGroupsFound = $GroupAnalysis.Count
            TotalPrivilegedUsers = ($PrivilegedGroupMembers | Where-Object {$_.MemberType -eq "user"} | Select-Object -ExpandProperty MemberSamAccountName -Unique).Count
            StalePrivilegedAccounts = $StalePrivAccounts.Count
            HighRiskPrivilegedAccounts = ($PrivilegedGroupMembers | Where-Object {$_.RiskLevel -eq "High"}).Count
            
            # Service Accounts
            ServiceAccountsAnalyzed = $ServiceAccountSecurityAnalysis.Count
            HighRiskServiceAccounts = ($ServiceAccountSecurityAnalysis | Where-Object {$_.RiskLevel -eq "High"}).Count
            PrivilegedServiceAccounts = ($ServiceAccountSecurityAnalysis | Where-Object {$_.IsPrivileged -eq $true}).Count
            
            # Built-in Administrator
            BuiltinAdminEnabled = if ($BuiltinAdminAnalysis.Count -gt 0) { ($BuiltinAdminAnalysis | Where-Object {$_.Enabled -eq $true}).Count -gt 0 } else { "Unknown" }
            
            # Summary Risk Assessment
            OverallSecurityRisk = if ($StalePrivAccounts.Count -gt 0 -or ($PrivilegedGroupMembers | Where-Object {$_.RiskLevel -eq "High"}).Count -gt 0) { "High" }
                                 elseif (($PrivilegedGroupMembers | Where-Object {$_.RiskLevel -eq "Medium"}).Count -gt 5) { "Medium" }
                                 else { "Low" }
            
            ProcessingTime = ((Get-Date) - $ScriptStartTime).TotalMinutes
            AssessmentMethod = "ADSI"
            RequiredWinRM = $false
        }
        
        $SecurityStats | Export-Csv "$Global:OutputPath\Security_Summary_Stats.csv" -NoTypeInformation
        
        Write-Log "Security assessment completed in $([math]::Round($SecurityStats.ProcessingTime, 2)) minutes"
        
    } catch {
        Write-Log "Critical error in security assessment: $($_.Exception.Message)"
        throw
    } finally {
        [GC]::Collect()
    }
}

# Execute the assessment if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Get-ADSecurityAssessment
    Write-Host "AD Security Assessment completed. Results in: $Global:OutputPath" -ForegroundColor Green
}
