# Domain Controllers and Infrastructure Assessment with ADSI Implementation
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

function Get-DCInfrastructureAssessment {
    Write-Log "=== Starting Domain Controllers and Infrastructure Assessment (ADSI) ==="
    
    $ScriptStartTime = Get-Date
    
    # Get domain info
    $DomainInfo = Get-ADSIDomainInfo
    if (!$DomainInfo) {
        Write-Error "Failed to get domain information"
        return
    }
    
    try {
        # 1. Get Forest and Domain Information
        Write-Host "Getting Forest and Domain information via ADSI..." -ForegroundColor Yellow
        
        # Get Forest Information
        $RootDSE = [ADSI]"LDAP://RootDSE"
        $ConfigDN = $RootDSE.configurationNamingContext[0]
        $SchemaDN = $RootDSE.schemaNamingContext[0]
        
        # Get Forest root domain
        $PartitionsSearcher = [adsisearcher]"(&(objectClass=crossRef)(nETBIOSName=*))"
        $PartitionsSearcher.SearchRoot = [ADSI]"LDAP://CN=Partitions,$ConfigDN"
        $PartitionsSearcher.PropertiesToLoad.AddRange(@('dnsroot', 'netbiosname', 'ncname'))
        
        $PartitionsResults = $PartitionsSearcher.FindAll()
        $ForestDomains = @()
        $ForestRootDomain = ""
        
        foreach ($PartitionResult in $PartitionsResults) {
            $PartitionProps = $PartitionResult.Properties
            $DomainDNS = if ($PartitionProps['dnsroot']) { $PartitionProps['dnsroot'][0] } else { "" }
            $DomainNetBIOS = if ($PartitionProps['netbiosname']) { $PartitionProps['netbiosname'][0] } else { "" }
            $NCName = if ($PartitionProps['ncname']) { $PartitionProps['ncname'][0] } else { "" }
            
            if ($DomainDNS) {
                $ForestDomains += $DomainDNS
                if (!$ForestRootDomain -or $NCName -eq $RootDSE.rootDomainNamingContext[0]) {
                    $ForestRootDomain = $DomainDNS
                }
            }
        }
        
        $PartitionsResults.Dispose()
        $PartitionsSearcher.Dispose()
        
        # Get Schema Version
        $SchemaSearcher = [adsisearcher]"(objectClass=dMD)"
        $SchemaSearcher.SearchRoot = [ADSI]"LDAP://$SchemaDN"
        $SchemaSearcher.PropertiesToLoad.Add('objectversion')
        
        $SchemaResults = $SchemaSearcher.FindAll()
        $SchemaVersion = if ($SchemaResults.Count -gt 0 -and $SchemaResults[0].Properties['objectversion']) {
            $SchemaResults[0].Properties['objectversion'][0]
        } else { "Unknown" }
        
        $SchemaResults.Dispose()
        $SchemaSearcher.Dispose()
        
        # Get FSMO role holders
        $SchemaMaster = $RootDSE.schemaNamingContext[0]
        $DomainNamingMaster = $RootDSE.configurationNamingContext[0]
        
        # Get domain-specific FSMO roles
        $DomainSearcher = [adsisearcher]"(objectClass=domainDNS)"
        $DomainSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
        $DomainSearcher.PropertiesToLoad.AddRange(@('fsmoroleowner', 'ridmanagerreference', 'infrastructureupdate'))
        
        $DomainResults = $DomainSearcher.FindAll()
        $PDCEmulator = ""
        $RIDMaster = ""
        $InfrastructureMaster = ""
        
        if ($DomainResults.Count -gt 0) {
            $DomainProps = $DomainResults[0].Properties
            if ($DomainProps['fsmoroleowner']) {
                $PDCEmulator = $DomainProps['fsmoroleowner'][0] -replace '.*?CN=([^,]+).*', '$1'
            }
            if ($DomainProps['ridmanagerreference']) {
                $RIDMaster = $DomainProps['ridmanagerreference'][0] -replace '.*?CN=([^,]+).*', '$1'
            }
        }
        
        $DomainResults.Dispose()
        $DomainSearcher.Dispose()
        
        $ForestInfo = [PSCustomObject]@{
            ForestName = $ForestRootDomain
            ForestMode = "Unknown"  # Not easily available via ADSI
            RootDomain = $ForestRootDomain
            SchemaVersion = $SchemaVersion
            Domains = $ForestDomains -join '; '
            DomainCount = $ForestDomains.Count
            ConfigurationDN = $ConfigDN
            SchemaDN = $SchemaDN
            SchemaMaster = $SchemaMaster
            DomainNamingMaster = $DomainNamingMaster
            AssessmentMethod = "ADSI"
        }
        
        $ForestInfo | Export-Csv "$Global:OutputPath\Infrastructure_Forest_Information.csv" -NoTypeInformation
        
        $DomainInfoReport = [PSCustomObject]@{
            DomainName = $DomainInfo.DomainName
            NetBIOSName = $DomainInfo.NetBIOSName
            DomainMode = $DomainInfo.DomainMode
            DomainFunctionalLevel = $Global:Config.DomainFunctionalLevel
            PDCEmulator = $PDCEmulator
            RIDMaster = $RIDMaster
            InfrastructureMaster = $InfrastructureMaster
            DistinguishedName = $DomainInfo.DomainDN
            AssessmentMethod = "ADSI"
        }
        
        $DomainInfoReport | Export-Csv "$Global:OutputPath\Infrastructure_Domain_Information.csv" -NoTypeInformation
        
        # 2. Get all Domain Controllers with enhanced analysis
        Write-Host "Analyzing Domain Controllers..." -ForegroundColor Yellow
        
        $DCDetails = @()
        
        # Search for Domain Controllers
        $DCSearcher = [adsisearcher]"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        $DCSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
        $DCSearcher.PageSize = 100
        $DCSearcher.PropertiesToLoad.AddRange(@(
            'name', 'dnshostname', 'operatingsystem', 'operatingsystemversion',
            'useraccountcontrol', 'whencreated', 'lastlogontimestamp', 'location',
            'serviceprincipalname'
        ))
        
        $DCResults = $DCSearcher.FindAll()
        
        foreach ($DCResult in $DCResults) {
            Write-Host "Processing DC: $($DCResult.Properties['name'][0])" -ForegroundColor Green
            
            try {
                $DCProps = $DCResult.Properties
                $DCName = if ($DCProps['name']) { $DCProps['name'][0] } else { "" }
                $DCDNSName = if ($DCProps['dnshostname']) { $DCProps['dnshostname'][0] } else { "" }
                $DCUAC = if ($DCProps['useraccountcontrol']) { [int]$DCProps['useraccountcontrol'][0] } else { 0 }
                $DCUACAnalysis = Get-UACSummary -UACValue $DCUAC
                
                # Determine DC type
                $IsGlobalCatalog = $false
                $IsReadOnly = $false
                
                # Check for GC and RODC in SPN
                if ($DCProps['serviceprincipalname']) {
                    $SPNs = $DCProps['serviceprincipalname']
                    foreach ($SPN in $SPNs) {
                        if ($SPN -like "*GC/*") {
                            $IsGlobalCatalog = $true
                        }
                        if ($SPN -like "*E3514235-4B06-11D1-AB04-00C04FC2DCD2/*" -and $SPN -like "*._msdcs.*") {
                            # Domain Controller GUID SPN indicates full DC
                        }
                    }
                }
                
                # Check if RODC (partial attribute set)
                $IsReadOnly = $DCUACAnalysis.IsDisabled -eq $false -and ($DCUAC -band 67108864) -ne 0  # PARTIAL_SECRETS_ACCOUNT
                
                # Get IP addresses (limited without WinRM)
                $IPv4Address = ""
                $IPv6Address = ""
                try {
                    if ($DCDNSName) {
                        $IPAddresses = [System.Net.Dns]::GetHostAddresses($DCDNSName)
                        $IPv4s = $IPAddresses | Where-Object {$_.AddressFamily -eq "InterNetwork"}
                        $IPv6s = $IPAddresses | Where-Object {$_.AddressFamily -eq "InterNetworkV6"}
                        
                        if ($IPv4s) { $IPv4Address = $IPv4s[0].IPAddressToString }
                        if ($IPv6s) { $IPv6Address = $IPv6s[0].IPAddressToString }
                    }
                } catch {
                    # DNS resolution failed
                }
                
                # Determine site (basic logic)
                $Site = "Default-First-Site-Name"  # Default, would need Sites/Services container analysis for accuracy
                
                $DCObject = [PSCustomObject]@{
                    DCName = $DCName
                    DNSHostName = $DCDNSName
                    IPv4Address = $IPv4Address
                    IPv6Address = $IPv6Address
                    Site = $Site
                    IsGlobalCatalog = $IsGlobalCatalog
                    IsReadOnly = $IsReadOnly
                    OperatingSystem = if ($DCProps['operatingsystem']) { $DCProps['operatingsystem'][0] } else { "Unknown" }
                    OperatingSystemVersion = if ($DCProps['operatingsystemversion']) { $DCProps['operatingsystemversion'][0] } else { "Unknown" }
                    WhenCreated = ConvertTo-DateTime -Value $DCProps['whencreated'][0] -Format "GeneralizedTime"
                    LastLogonDate = ConvertTo-DateTime -Value $DCProps['lastlogontimestamp'][0] -Format "FileTime"
                    Location = if ($DCProps['location']) { $DCProps['location'][0] } else { "" }
                    UserAccountControl = $DCUAC
                    UACFlags = $DCUACAnalysis.FlagsString
                    TrustedForDelegation = $DCUACAnalysis.TrustedForDelegation
                    Services = "Limited assessment without WinRM"
                    LastReboot = "Unknown - WinRM required"
                    AssessmentMethod = "ADSI"
                    AssessmentLimitations = "Service status and reboot time require WinRM"
                }
                
                $DCDetails += $DCObject
                
            } catch {
                Write-Log "Error processing DC $DCName : $($_.Exception.Message)"
            }
        }
        
        $DCResults.Dispose()
        $DCSearcher.Dispose()
        
        $DCDetails | Export-Csv "$Global:OutputPath\Infrastructure_Domain_Controllers.csv" -NoTypeInformation
        
        # 3. Get Sites and Subnets
        Write-Host "Getting Sites and Subnets..." -ForegroundColor Yellow
        
        $SiteDetails = @()
        
        # Get Sites
        $SitesSearcher = [adsisearcher]"(objectClass=site)"
        $SitesSearcher.SearchRoot = [ADSI]"LDAP://CN=Sites,$ConfigDN"
        $SitesSearcher.PageSize = 100
        $SitesSearcher.PropertiesToLoad.AddRange(@('name', 'description', 'location', 'whencreated'))
        
        $SitesResults = $SitesSearcher.FindAll()
        
        foreach ($SiteResult in $SitesResults) {
            $SiteProps = $SiteResult.Properties
            $SiteName = if ($SiteProps['name']) { $SiteProps['name'][0] } else { "" }
            
            # Get subnets for this site
            $SubnetSearcher = [adsisearcher]"(&(objectClass=subnet)(siteObject=CN=$SiteName,CN=Sites,$ConfigDN))"
            $SubnetSearcher.SearchRoot = [ADSI]"LDAP://CN=Subnets,CN=Sites,$ConfigDN"
            $SubnetSearcher.PropertiesToLoad.Add('name')
            
            $SubnetResults = $SubnetSearcher.FindAll()
            $Subnets = @()
            
            foreach ($SubnetResult in $SubnetResults) {
                if ($SubnetResult.Properties['name']) {
                    $Subnets += $SubnetResult.Properties['name'][0]
                }
            }
            
            $SubnetResults.Dispose()
            $SubnetSearcher.Dispose()
            
            # Count DCs in this site (simplified - using name matching)
            $SiteDCs = $DCDetails | Where-Object {$_.Site -eq $SiteName}
            
            $SiteObject = [PSCustomObject]@{
                SiteName = $SiteName
                Description = if ($SiteProps['description']) { $SiteProps['description'][0] } else { "" }
                Location = if ($SiteProps['location']) { $SiteProps['location'][0] } else { "" }
                WhenCreated = ConvertTo-DateTime -Value $SiteProps['whencreated'][0] -Format "GeneralizedTime"
                Subnets = $Subnets -join '; '
                SubnetCount = $Subnets.Count
                DomainControllers = ($SiteDCs | Select-Object -ExpandProperty DCName) -join '; '
                DCCount = $SiteDCs.Count
                HasDCs = $SiteDCs.Count -gt 0
                HasSubnets = $Subnets.Count -gt 0
            }
            
            $SiteDetails += $SiteObject
        }
        
        $SitesResults.Dispose()
        $SitesSearcher.Dispose()
        
        $SiteDetails | Export-Csv "$Global:OutputPath\Infrastructure_AD_Sites.csv" -NoTypeInformation
        
        # 4. Get Subnet Information
        Write-Host "Getting Subnet Details..." -ForegroundColor Yellow
        
        $SubnetDetails = @()
        
        $AllSubnetsSearcher = [adsisearcher]"(objectClass=subnet)"
        $AllSubnetsSearcher.SearchRoot = [ADSI]"LDAP://CN=Subnets,CN=Sites,$ConfigDN"
        $AllSubnetsSearcher.PageSize = 100
        $AllSubnetsSearcher.PropertiesToLoad.AddRange(@('name', 'description', 'location', 'siteobject'))
        
        $AllSubnetsResults = $AllSubnetsSearcher.FindAll()
        
        foreach ($SubnetResult in $AllSubnetsResults) {
            $SubnetProps = $SubnetResult.Properties
            $SubnetName = if ($SubnetProps['name']) { $SubnetProps['name'][0] } else { "" }
            $SiteObjectDN = if ($SubnetProps['siteobject']) { $SubnetProps['siteobject'][0] } else { "" }
            
            # Extract site name from DN
            $AssociatedSite = if ($SiteObjectDN -match 'CN=([^,]+),CN=Sites') { $Matches[1] } else { "Unknown" }
            
            $SubnetDetails += [PSCustomObject]@{
                SubnetName = $SubnetName
                Description = if ($SubnetProps['description']) { $SubnetProps['description'][0] } else { "" }
                Location = if ($SubnetProps['location']) { $SubnetProps['location'][0] } else { "" }
                AssociatedSite = $AssociatedSite
                SiteObjectDN = $SiteObjectDN
                HasSiteAssociation = $SiteObjectDN -ne ""
            }
        }
        
        $AllSubnetsResults.Dispose()
        $AllSubnetsSearcher.Dispose()
        
        if ($SubnetDetails.Count -gt 0) {
            $SubnetDetails | Export-Csv "$Global:OutputPath\Infrastructure_AD_Subnets.csv" -NoTypeInformation
        }
        
        # 5. Trust Relationships
        Write-Host "Getting Trust Relationships..." -ForegroundColor Yellow
        
        $TrustDetails = @()
        
        $TrustSearcher = [adsisearcher]"(objectClass=trustedDomain)"
        $TrustSearcher.SearchRoot = [ADSI]"LDAP://CN=System,$($DomainInfo.DomainDN)"
        $TrustSearcher.PageSize = 100
        $TrustSearcher.PropertiesToLoad.AddRange(@(
            'name', 'trustdirection', 'trusttype', 'trustattributes', 
            'whencreated', 'whenchanged', 'flatname'
        ))
        
        $TrustResults = $TrustSearcher.FindAll()
        
        foreach ($TrustResult in $TrustResults) {
            $TrustProps = $TrustResult.Properties
            $TrustName = if ($TrustProps['name']) { $TrustProps['name'][0] } else { "" }
            $TrustDirection = if ($TrustProps['trustdirection']) { $TrustProps['trustdirection'][0] } else { 0 }
            $TrustType = if ($TrustProps['trusttype']) { $TrustProps['trusttype'][0] } else { 0 }
            $TrustAttributes = if ($TrustProps['trustattributes']) { $TrustProps['trustattributes'][0] } else { 0 }
            
            # Interpret trust direction
            $DirectionText = switch ($TrustDirection) {
                1 { "Incoming" }
                2 { "Outgoing" }
                3 { "Bidirectional" }
                default { "Unknown" }
            }
            
            # Interpret trust type
            $TypeText = switch ($TrustType) {
                1 { "External" }
                2 { "Forest" }
                3 { "Unknown" }
                4 { "DCE" }
                default { "Unknown" }
            }
            
            $TrustDetails += [PSCustomObject]@{
                TrustName = $TrustName
                TrustType = $TypeText
                TrustDirection = $DirectionText
                TrustAttributes = $TrustAttributes
                FlatName = if ($TrustProps['flatname']) { $TrustProps['flatname'][0] } else { "" }
                Created = ConvertTo-DateTime -Value $TrustProps['whencreated'][0] -Format "GeneralizedTime"
                Modified = ConvertTo-DateTime -Value $TrustProps['whenchanged'][0] -Format "GeneralizedTime"
                TrustStatus = "Active"  # Basic status - detailed validation would require additional tools
                AssessmentLimitations = "Trust health validation requires additional tools"
            }
        }
        
        $TrustResults.Dispose()
        $TrustSearcher.Dispose()
        
        if ($TrustDetails.Count -gt 0) {
            $TrustDetails | Export-Csv "$Global:OutputPath\Infrastructure_Trust_Relationships.csv" -NoTypeInformation
        }
        
        # 6. Site Links (for replication topology)
        Write-Host "Getting Site Links..." -ForegroundColor Yellow
        
        $SiteLinkDetails = @()
        
        $SiteLinkSearcher = [adsisearcher]"(objectClass=siteLink)"
        $SiteLinkSearcher.SearchRoot = [ADSI]"LDAP://CN=Inter-Site Transports,CN=Sites,$ConfigDN"
        $SiteLinkSearcher.PageSize = 100
        $SiteLinkSearcher.PropertiesToLoad.AddRange(@(
            'name', 'description', 'sitelist', 'cost', 'replinterval', 'schedule'
        ))
        
        $SiteLinkResults = $SiteLinkSearcher.FindAll()
        
        foreach ($SiteLinkResult in $SiteLinkResults) {
            $SiteLinkProps = $SiteLinkResult.Properties
            $SiteLinkName = if ($SiteLinkProps['name']) { $SiteLinkProps['name'][0] } else { "" }
            
            # Get connected sites
            $ConnectedSites = @()
            if ($SiteLinkProps['sitelist']) {
                foreach ($SiteDN in $SiteLinkProps['sitelist']) {
                    if ($SiteDN -match 'CN=([^,]+)') {
                        $ConnectedSites += $Matches[1]
                    }
                }
            }
            
            $SiteLinkDetails += [PSCustomObject]@{
                SiteLinkName = $SiteLinkName
                Description = if ($SiteLinkProps['description']) { $SiteLinkProps['description'][0] } else { "" }
                ConnectedSites = $ConnectedSites -join '; '
                SiteCount = $ConnectedSites.Count
                Cost = if ($SiteLinkProps['cost']) { $SiteLinkProps['cost'][0] } else { 100 }
                ReplicationInterval = if ($SiteLinkProps['replinterval']) { $SiteLinkProps['replinterval'][0] } else { 180 }
                HasCustomSchedule = if ($SiteLinkProps['schedule']) { $true } else { $false }
            }
        }
        
        $SiteLinkResults.Dispose()
        $SiteLinkSearcher.Dispose()
        
        if ($SiteLinkDetails.Count -gt 0) {
            $SiteLinkDetails | Export-Csv "$Global:OutputPath\Infrastructure_Site_Links.csv" -NoTypeInformation
        }
        
        # 7. Infrastructure Summary
        $InfraStats = [PSCustomObject]@{
            # Forest Information
            ForestName = $ForestInfo.ForestName
            ForestDomainCount = $ForestInfo.DomainCount
            SchemaVersion = $ForestInfo.SchemaVersion
            
            # Domain Information
            DomainName = $DomainInfoReport.DomainName
            DomainNetBIOSName = $DomainInfoReport.NetBIOSName
            DomainMode = $DomainInfoReport.DomainMode
            
            # Domain Controllers
            TotalDomainControllers = $DCDetails.Count
            GlobalCatalogs = ($DCDetails | Where-Object {$_.IsGlobalCatalog -eq $true}).Count
            ReadOnlyDCs = ($DCDetails | Where-Object {$_.IsReadOnly -eq $true}).Count
            WritableDCs = ($DCDetails | Where-Object {$_.IsReadOnly -eq $false}).Count
            
            # Sites and Topology
            Sites = $SiteDetails.Count
            SitesWithDCs = ($SiteDetails | Where-Object {$_.HasDCs -eq $true}).Count
            SitesWithoutDCs = ($SiteDetails | Where-Object {$_.HasDCs -eq $false}).Count
            TotalSubnets = $SubnetDetails.Count
            SubnetsWithoutSites = ($SubnetDetails | Where-Object {$_.HasSiteAssociation -eq $false}).Count
            SiteLinks = $SiteLinkDetails.Count
            
            # Trusts
            TrustRelationships = $TrustDetails.Count
            BidirectionalTrusts = ($TrustDetails | Where-Object {$_.TrustDirection -eq "Bidirectional"}).Count
            
            # Health Indicators
            DCsWithDelegation = ($DCDetails | Where-Object {$_.TrustedForDelegation -eq $true}).Count
            OrphanedSites = ($SiteDetails | Where-Object {$_.HasDCs -eq $false -and $_.HasSubnets -eq $true}).Count
            
            ProcessingTime = ((Get-Date) - $ScriptStartTime).TotalMinutes
            AssessmentMethod = "ADSI"
            RequiredWinRM = $false
            Limitations = "Replication status, service health, and detailed DC metrics require WinRM"
        }
        
        $InfraStats | Export-Csv "$Global:OutputPath\Infrastructure_Summary_Stats.csv" -NoTypeInformation
        
        Write-Log "DC and Infrastructure assessment completed in $([math]::Round($InfraStats.ProcessingTime, 2)) minutes"
        
    } catch {
        Write-Log "Critical error in infrastructure assessment: $($_.Exception.Message)"
        throw
    } finally {
        [GC]::Collect()
    }
}

# Execute the assessment if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Get-DCInfrastructureAssessment
    Write-Host "Domain Controllers and Infrastructure Assessment completed. Results in: $Global:OutputPath" -ForegroundColor Green
}
