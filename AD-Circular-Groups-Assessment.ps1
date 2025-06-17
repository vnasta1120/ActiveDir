# Circular Group Membership Detection with ADSI Implementation
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
        . $CoreScript -OutputPath $OutputPath -ConfigFile $ConfigFile
    } else {
        Write-Error "Core infrastructure script not found: $CoreScript"
        exit 1
    }
}

function Get-CircularGroupMembershipAssessment {
    Write-Log "=== Starting Circular Group Membership Detection (ADSI) ==="
    
    $ScriptStartTime = Get-Date
    
    # Get domain info
    $DomainInfo = Get-ADSIDomainInfo
    if (!$DomainInfo) {
        Write-Error "Failed to get domain information"
        return
    }
    
    Write-Host "Analyzing group membership for circular references via ADSI..." -ForegroundColor Yellow
    
    # Get all groups with their members using ADSI
    $GroupProperties = @('name', 'distinguishedname', 'member', 'samaccountname', 'description')
    
    $GroupSearcher = [adsisearcher]"(&(objectCategory=group))"
    $GroupSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
    $GroupSearcher.PageSize = 1000
    $GroupSearcher.PropertiesToLoad.AddRange($GroupProperties)
    
    try {
        $GroupResults = $GroupSearcher.FindAll()
        $AllGroups = @()
        
        # Build group collection
        foreach ($GroupResult in $GroupResults) {
            $GroupProps = $GroupResult.Properties
            
            $GroupObject = [PSCustomObject]@{
                Name = if ($GroupProps['name']) { $GroupProps['name'][0] } else { "" }
                DistinguishedName = if ($GroupProps['distinguishedname']) { $GroupProps['distinguishedname'][0] } else { "" }
                SamAccountName = if ($GroupProps['samaccountname']) { $GroupProps['samaccountname'][0] } else { "" }
                Description = if ($GroupProps['description']) { $GroupProps['description'][0] } else { "" }
                Members = if ($GroupProps['member']) { $GroupProps['member'] } else { @() }
                MemberCount = if ($GroupProps['member']) { $GroupProps['member'].Count } else { 0 }
            }
            
            $AllGroups += $GroupObject
        }
        
        $GroupResults.Dispose()
        $GroupSearcher.Dispose()
        
        Write-Log "Found $($AllGroups.Count) groups to analyze for circular membership"
        
        $CircularGroups = @()
        $ProcessedCount = 0
        
        function Test-CircularMembership {
            param(
                [string]$GroupDN,
                [string]$OriginalGroupDN,
                [hashtable]$VisitedGroups,
                [int]$Depth = 0,
                [hashtable]$GroupLookup
            )
            
            if ($Depth -gt $Global:Config.CircularGroupDepthLimit) { return $false }  # Configurable depth limit
            if ($GroupDN -eq $OriginalGroupDN -and $Depth -gt 0) { return $true }
            if ($VisitedGroups.ContainsKey($GroupDN)) { return $false }
            
            $VisitedGroups[$GroupDN] = $true
            
            try {
                # Find the group in our lookup
                $Group = $GroupLookup[$GroupDN]
                if (!$Group) {
                    $VisitedGroups.Remove($GroupDN)
                    return $false
                }
                
                foreach ($MemberDN in $Group.Members) {
                    # Check if this member is a group (simple check - groups typically have CN=groupname format)
                    if ($GroupLookup.ContainsKey($MemberDN)) {
                        if (Test-CircularMembership -GroupDN $MemberDN -OriginalGroupDN $OriginalGroupDN -VisitedGroups $VisitedGroups -Depth ($Depth + 1) -GroupLookup $GroupLookup) {
                            return $true
                        }
                    }
                }
            } catch {
                Write-Log "Error checking circular membership for group DN $GroupDN : $($_.Exception.Message)"
            }
            
            $VisitedGroups.Remove($GroupDN)
            return $false
        }
        
        # Create a hashtable lookup for performance
        $GroupLookup = @{}
        foreach ($Group in $AllGroups) {
            $GroupLookup[$Group.DistinguishedName] = $Group
        }
        
        foreach ($Group in $AllGroups) {
            $ProcessedCount++
            
            if ($ProcessedCount % 50 -eq 0) {
                $PercentComplete = ($ProcessedCount / $AllGroups.Count) * 100
                Write-Progress -Activity "Checking for Circular Group Memberships (ADSI)" `
                    -Status "Processing group $ProcessedCount of $($AllGroups.Count)" `
                    -PercentComplete $PercentComplete `
                    -CurrentOperation "Group: $($Group.Name)"
            }
            
            try {
                $VisitedGroups = @{}
                if (Test-CircularMembership -GroupDN $Group.DistinguishedName -OriginalGroupDN $Group.DistinguishedName -VisitedGroups $VisitedGroups -GroupLookup $GroupLookup) {
                    $CircularGroups += [PSCustomObject]@{
                        GroupName = $Group.Name
                        GroupSamAccountName = $Group.SamAccountName
                        DistinguishedName = $Group.DistinguishedName
                        Description = $Group.Description
                        IssueType = "Circular Group Membership"
                        Severity = "High"
                        IssueDescription = "Group is member of itself through nested membership"
                        MemberCount = $Group.MemberCount
                        DetectionDepthLimit = $Global:Config.CircularGroupDepthLimit
                    }
                    
                    Write-Log "Circular membership detected: $($Group.Name)"
                }
            } catch {
                Write-Log "Error checking circular membership for group $($Group.Name): $($_.Exception.Message)"
            }
        }
        
        Write-Progress -Activity "Checking for Circular Group Memberships" -Completed
        
        # Export results
        if ($CircularGroups.Count -gt 0) {
            $CircularGroups | Export-Csv "$Global:OutputPath\Groups_Circular_Memberships.csv" -NoTypeInformation
            Write-Log "Found $($CircularGroups.Count) groups with circular membership"
            
            # Create a detailed report with the circular paths
            $DetailedReport = @()
            foreach ($CircularGroup in $CircularGroups) {
                # Try to trace the circular path
                $CircularPath = Get-CircularPath -GroupDN $CircularGroup.DistinguishedName -GroupLookup $GroupLookup
                
                $DetailedReport += [PSCustomObject]@{
                    GroupName = $CircularGroup.GroupName
                    GroupSamAccountName = $CircularGroup.GroupSamAccountName
                    DistinguishedName = $CircularGroup.DistinguishedName
                    CircularPath = $CircularPath
                    Severity = $CircularGroup.Severity
                    RecommendedAction = "Remove circular membership to prevent authentication issues"
                    Impact = "May cause authentication delays, group expansion failures, or infinite loops"
                }
            }
            
            $DetailedReport | Export-Csv "$Global:OutputPath\Groups_Circular_Details.csv" -NoTypeInformation
            
        } else {
            Write-Log "No circular group memberships detected"
            
            # Create empty file to indicate assessment was run
            @() | Export-Csv "$Global:OutputPath\Groups_Circular_Memberships.csv" -NoTypeInformation
        }
        
        # Generate group membership statistics
        $GroupStats = @()
        foreach ($Group in $AllGroups) {
            $GroupStats += [PSCustomObject]@{
                GroupName = $Group.Name
                GroupSamAccountName = $Group.SamAccountName
                MemberCount = $Group.MemberCount
                HasMembers = $Group.MemberCount -gt 0
                IsNested = ($Group.Members | Where-Object {$GroupLookup.ContainsKey($_)}).Count -gt 0
                NestedGroupCount = ($Group.Members | Where-Object {$GroupLookup.ContainsKey($_)}).Count
                DirectMemberCount = $Group.MemberCount - ($Group.Members | Where-Object {$GroupLookup.ContainsKey($_)}).Count
            }
        }
        
        $GroupStats | Export-Csv "$Global:OutputPath\Groups_Membership_Statistics.csv" -NoTypeInformation
        
        # Summary statistics
        $SummaryStats = [PSCustomObject]@{
            TotalGroups = $AllGroups.Count
            GroupsWithMembers = ($GroupStats | Where-Object {$_.HasMembers}).Count
            GroupsWithNestedGroups = ($GroupStats | Where-Object {$_.IsNested}).Count
            CircularGroups = $CircularGroups.Count
            MaxDepthAnalyzed = $Global:Config.CircularGroupDepthLimit
            ProcessingTime = ((Get-Date) - $ScriptStartTime).TotalMinutes
            UsedADSI = $true
            RequiredWinRM = $false
        }
        
        $SummaryStats | Export-Csv "$Global:OutputPath\Groups_Summary_Stats.csv" -NoTypeInformation
        
        Write-Log "Circular group membership assessment completed in $([math]::Round($SummaryStats.ProcessingTime, 2)) minutes"
        
    } catch {
        Write-Log "Critical error in circular group membership assessment: $($_.Exception.Message)"
        throw
    } finally {
        [GC]::Collect()
    }
}

function Get-CircularPath {
    param(
        [string]$GroupDN,
        [hashtable]$GroupLookup,
        [array]$Path = @(),
        [int]$MaxDepth = 10
    )
    
    if ($Path.Count -gt $MaxDepth) {
        return "Path too deep (truncated)"
    }
    
    if ($GroupDN -in $Path) {
        # Found the circle, return the path
        $CircleStart = $Path.IndexOf($GroupDN)
        $CirclePath = $Path[$CircleStart..($Path.Count-1)]
        $CirclePath += $GroupDN  # Close the circle
        
        $PathNames = @()
        foreach ($DN in $CirclePath) {
            $Group = $GroupLookup[$DN]
            if ($Group) {
                $PathNames += $Group.Name
            } else {
                $PathNames += "Unknown"
            }
        }
        
        return $PathNames -join " -> "
    }
    
    $Group = $GroupLookup[$GroupDN]
    if (!$Group) {
        return "Group not found"
    }
    
    $NewPath = $Path + @($GroupDN)
    
    foreach ($MemberDN in $Group.Members) {
        if ($GroupLookup.ContainsKey($MemberDN)) {
            $Result = Get-CircularPath -GroupDN $MemberDN -GroupLookup $GroupLookup -Path $NewPath -MaxDepth $MaxDepth
            if ($Result -ne $null -and $Result -ne "Group not found" -and $Result -ne "Path too deep (truncated)") {
                return $Result
            }
        }
    }
    
    return $null
}

# Execute the assessment if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Get-CircularGroupMembershipAssessment
    Write-Host "Circular Group Membership Assessment completed. Results in: $Global:OutputPath" -ForegroundColor Green
}
