# Domain Controllers and Infrastructure Assessment - Forest-Aware Version
# Version 5.2 - Handles multi-domain forests correctly

#Requires -Version 5.1

param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\AD_Assessment",
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile
)

# Dot source the core infrastructure (always reload for fresh variables)
if ($true) {
    $CoreScript = Join-Path (Split-Path $MyInvocation.MyCommand.Path) "00-AD-Assessment-Core.ps1"
    if (Test-Path $CoreScript) {
        $CoreParams = @{
            OutputPath = $OutputPath
        }
        if (![string]::IsNullOrEmpty($ConfigFile)) {
            $CoreParams['ConfigFile'] = $ConfigFile
        }
        . $CoreScript @CoreParams
    } else {
        Write-Error "Core infrastructure script not found: $CoreScript"
        exit 1
    }
}

function Get-DCInfrastructureAssessment {
    Write-Log "=== Starting Forest-Aware DC and Infrastructure Assessment ==="
    
    $ScriptStartTime = Get-Date
    
    # Get domain info
    $DomainInfo = Get-ADSIDomainInfo
    if (!$DomainInfo) {
        Write-Error "Failed to get domain information"
        return
    }
    
    try {
        # 1. Get Forest and Domain Information
        Write-Host "Getting Forest and Domain information..." -ForegroundColor Yellow
        
        # Get FOREST configuration from RootDSE (this is the key fix)
        $RootDSE = [ADSI]"LDAP://RootDSE"
        $ConfigDN = $RootDSE.configurationNamingContext[0]
        $SchemaDN = $RootDSE.schemaNamingContext[0]
        $ForestDN = $RootDSE.rootDomainNamingContext[0]
        
        Write-Host "Domain: $($DomainInfo.DomainName) (DN: $($DomainInfo.DomainDN))" -ForegroundColor Green
        Write-Host "Forest Root: $ForestDN" -ForegroundColor Green
        Write-Host "Configuration: $ConfigDN" -ForegroundColor Green
        
        # Get Forest domains
        $PartitionsSearcher = [adsisearcher]"(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=3))"
        $PartitionsSearcher.SearchRoot = [ADSI]"LDAP://CN=Partitions,$ConfigDN"
        $PartitionsSearcher.PropertiesToLoad.AddRange(@('dnsroot', 'netbiosname', 'ncname'))
        
        $PartitionsResults = $PartitionsSearcher.FindAll()
        $ForestDomains = @()
        
        foreach ($PartitionResult in $PartitionsResults) {
            $PartitionProps = $PartitionResult.Properties
            $DomainDNS = if ($PartitionProps['dnsroot']) { $PartitionProps['dnsroot'][0] } else { "" }
            if ($DomainDNS) {
                $ForestDomains += $DomainDNS
            }
        }
        
        Write-Host "Forest contains $($ForestDomains.Count) domain(s): $($ForestDomains -join ', ')" -ForegroundColor Green
        
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
        
        Write-Host "Schema Version: $SchemaVersion" -ForegroundColor Green
        
        $SchemaResults.Dispose()
        $SchemaSearcher.Dispose()
        
        $ForestInfo = [PSCustomObject]@{
            CurrentDomain = $DomainInfo.DomainName
            CurrentDomainDN = $DomainInfo.DomainDN
            ForestRootDN = $ForestDN
            ConfigurationDN = $ConfigDN
            SchemaDN = $SchemaDN
            SchemaVersion = $SchemaVersion
            ForestDomains = $ForestDomains -join '; '
            DomainCount = $ForestDomains.Count
            IsMultiDomainForest = $ForestDomains.Count -gt 1
            AssessmentMethod = "ADSI"
        }
        
        $ForestInfo | Export-Csv "$Global:OutputPath\Infrastructure_Forest_Information.csv" -NoTypeInformation
        
        # 2. Get Domain Controllers
        Write-Host "`nAnalyzing Domain Controllers..." -ForegroundColor Yellow
        
        $DCDetails = @()
        
        $DCSearcher = [adsisearcher]"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        $DCSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
        $DCSearcher.PageSize = 100
        $DCSearcher.PropertiesToLoad.AddRange(@(
            'name', 'dnshostname', 'operatingsystem', 'operatingsystemversion',
            'useraccountcontrol', 'whencreated', 'lastlogontimestamp', 'location',
            'serviceprincipalname', 'distinguishedname', 'description'
        ))
        
        $DCResults = $DCSearcher.FindAll()
        Write-Host "Found $($DCResults.Count) Domain Controllers" -ForegroundColor Green
        
        foreach ($DCResult in $DCResults) {
            $DCProps = $DCResult.Properties
            $DCName = if ($DCProps['name']) { $DCProps['name'][0] } else { "" }
            Write-Host "  Processing DC: $DCName" -ForegroundColor Gray
            
            try {
                $DCDNSName = if ($DCProps['dnshostname']) { $DCProps['dnshostname'][0] } else { "" }
                $DCUAC = if ($DCProps['useraccountcontrol']) { [int]$DCProps['useraccountcontrol'][0] } else { 0 }
                $DCUACAnalysis = Get-UACSummary -UACValue $DCUAC
                
                # Determine DC type from SPNs
                $IsGlobalCatalog = $false
                if ($DCProps['serviceprincipalname']) {
                    foreach ($SPN in $DCProps['serviceprincipalname']) {
                        if ($SPN -like "*GC/*") {
                            $IsGlobalCatalog = $true
                            break
                        }
                    }
                }
                
                $IsReadOnly = ($DCUAC -band 67108864) -ne 0  # PARTIAL_SECRETS_ACCOUNT
                
                # Get IP addresses
                $IPv4Address = ""
                try {
                    if ($DCDNSName) {
                        $IPAddresses = [System.Net.Dns]::GetHostAddresses($DCDNSName)
                        $IPv4s = $IPAddresses | Where-Object {$_.AddressFamily -eq "InterNetwork"}
                        if ($IPv4s) { $IPv4Address = $IPv4s[0].IPAddressToString }
                    }
                } catch { }
                
                # Extract site from DN
                $Site = "Unknown"
                $DCDN = if ($DCProps['distinguishedname']) { $DCProps['distinguishedname'][0] } else { "" }
                if ($DCDN -match 'CN=Servers,CN=([^,]+),CN=Sites') {
                    $Site = $Matches[1]
                }
                
                $DCDetails += [PSCustomObject]@{
                    DCName = $DCName
                    DNSHostName = $DCDNSName
                    IPv4Address = $IPv4Address
                    Site = $Site
                    IsGlobalCatalog = $IsGlobalCatalog
                    IsReadOnly = $IsReadOnly
                    DCType = if ($IsReadOnly) { "RODC" } elseif ($IsGlobalCatalog) { "GC" } else { "DC" }
                    OperatingSystem = if ($DCProps['operatingsystem']) { $DCProps['operatingsystem'][0] } else { "Unknown" }
                    OperatingSystemVersion = if ($DCProps['operatingsystemversion']) { $DCProps['operatingsystemversion'][0] } else { "Unknown" }
                    Description = if ($DCProps['description']) { $DCProps['description'][0] } else { "" }
                    WhenCreated = ConvertTo-DateTime -Value $DCProps['whencreated'][0] -Format "GeneralizedTime"
                    LastLogonDate = ConvertTo-DateTime -Value $DCProps['lastlogontimestamp'][0] -Format "FileTime"
                    Location = if ($DCProps['location']) { $DCProps['location'][0] } else { "" }
                    Enabled = !$DCUACAnalysis.IsDisabled
                }
            } catch {
                Write-Warning "Error processing DC $DCName : $_"
            }
        }
        
        $DCResults.Dispose()
        $DCSearcher.Dispose()
        
        $DCDetails | Export-Csv "$Global:OutputPath\Infrastructure_Domain_Controllers.csv" -NoTypeInformation
        
        # 3. Get Sites and Subnets (from FOREST configuration)
        Write-Host "`nGetting Sites and Subnets from forest configuration..." -ForegroundColor Yellow
        
        $SiteDetails = @()
        
        $SitesSearcher = [adsisearcher]"(objectClass=site)"
        $SitesSearcher.SearchRoot = [ADSI]"LDAP://CN=Sites,$ConfigDN"
        $SitesSearcher.PageSize = 100
        $SitesSearcher.PropertiesToLoad.AddRange(@('name', 'description', 'location', 'whencreated'))
        
        $SitesResults = $SitesSearcher.FindAll()
        Write-Host "Found $($SitesResults.Count) sites in forest" -ForegroundColor Green
        
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
            
            # Count DCs in this site
            $SiteDCs = $DCDetails | Where-Object {$_.Site -eq $SiteName}
            
            $SiteDetails += [PSCustomObject]@{
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
        }
        
        $SitesResults.Dispose()
        $SitesSearcher.Dispose()
        
        $SiteDetails | Export-Csv "$Global:OutputPath\Infrastructure_AD_Sites.csv" -NoTypeInformation
        
        # 4. Get all Subnets
        Write-Host "`nGetting Subnet Details..." -ForegroundColor Yellow
        
        $SubnetDetails = @()
        
        $AllSubnetsSearcher = [adsisearcher]"(objectClass=subnet)"
        $AllSubnetsSearcher.SearchRoot = [ADSI]"LDAP://CN=Subnets,CN=Sites,$ConfigDN"
        $AllSubnetsSearcher.PageSize = 100
        $AllSubnetsSearcher.PropertiesToLoad.AddRange(@('name', 'description', 'location', 'siteobject'))
        
        $AllSubnetsResults = $AllSubnetsSearcher.FindAll()
        Write-Host "Found $($AllSubnetsResults.Count) subnets in forest" -ForegroundColor Green
        
        foreach ($SubnetResult in $AllSubnetsResults) {
            $SubnetProps = $SubnetResult.Properties
            $SubnetName = if ($SubnetProps['name']) { $SubnetProps['name'][0] } else { "" }
            $SiteObjectDN = if ($SubnetProps['siteobject']) { $SubnetProps['siteobject'][0] } else { "" }
            
            $AssociatedSite = if ($SiteObjectDN -match 'CN=([^,]+),CN=Sites') { $Matches[1] } else { "Unknown" }
            
            $SubnetDetails += [PSCustomObject]@{
                SubnetName = $SubnetName
                Description = if ($SubnetProps['description']) { $SubnetProps['description'][0] } else { "" }
                Location = if ($SubnetProps['location']) { $SubnetProps['location'][0] } else { "" }
                AssociatedSite = $AssociatedSite
                HasSiteAssociation = $SiteObjectDN -ne ""
            }
        }
        
        $AllSubnetsResults.Dispose()
        $AllSubnetsSearcher.Dispose()
        
        $SubnetDetails | Export-Csv "$Global:OutputPath\Infrastructure_AD_Subnets.csv" -NoTypeInformation
        
        # 5. Trust Relationships
        Write-Host "`nGetting Trust Relationships..." -ForegroundColor Yellow
        
        $TrustDetails = @()
        
        $TrustSearcher = [adsisearcher]"(objectClass=trustedDomain)"
        $TrustSearcher.SearchRoot = [ADSI]"LDAP://CN=System,$($DomainInfo.DomainDN)"
        $TrustSearcher.PageSize = 100
        $TrustSearcher.PropertiesToLoad.AddRange(@(
            'name', 'trustdirection', 'trusttype', 'trustattributes', 
            'whencreated', 'whenchanged', 'flatname'
        ))
        
        $TrustResults = $TrustSearcher.FindAll()
        Write-Host "Found $($TrustResults.Count) trust relationships" -ForegroundColor Green
        
        foreach ($TrustResult in $TrustResults) {
            $TrustProps = $TrustResult.Properties
            $TrustName = if ($TrustProps['name']) { $TrustProps['name'][0] } else { "" }
            $TrustDirection = if ($TrustProps['trustdirection']) { $TrustProps['trustdirection'][0] } else { 0 }
            $TrustType = if ($TrustProps['trusttype']) { $TrustProps['trusttype'][0] } else { 0 }
            
            $DirectionText = switch ($TrustDirection) {
                1 { "Incoming" }
                2 { "Outgoing" }
                3 { "Bidirectional" }
                default { "Unknown" }
            }
            
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
                FlatName = if ($TrustProps['flatname']) { $TrustProps['flatname'][0] } else { "" }
                Created = ConvertTo-DateTime -Value $TrustProps['whencreated'][0] -Format "GeneralizedTime"
                Modified = ConvertTo-DateTime -Value $TrustProps['whenchanged'][0] -Format "GeneralizedTime"
            }
        }
        
        $TrustResults.Dispose()
        $TrustSearcher.Dispose()
        
        $TrustDetails | Export-Csv "$Global:OutputPath\Infrastructure_Trust_Relationships.csv" -NoTypeInformation
        
        # 6. Site Links
        Write-Host "`nGetting Site Links..." -ForegroundColor Yellow
        
        $SiteLinkDetails = @()
        
        $SiteLinkSearcher = [adsisearcher]"(objectClass=siteLink)"
        $SiteLinkSearcher.SearchRoot = [ADSI]"LDAP://CN=IP,CN=Inter-Site Transports,CN=Sites,$ConfigDN"
        $SiteLinkSearcher.PageSize = 100
        $SiteLinkSearcher.PropertiesToLoad.AddRange(@(
            'name', 'description', 'sitelist', 'cost', 'replinterval'
        ))
        
        $SiteLinkResults = $SiteLinkSearcher.FindAll()
        Write-Host "Found $($SiteLinkResults.Count) site links" -ForegroundColor Green
        
        foreach ($SiteLinkResult in $SiteLinkResults) {
            $SiteLinkProps = $SiteLinkResult.Properties
            $SiteLinkName = if ($SiteLinkProps['name']) { $SiteLinkProps['name'][0] } else { "" }
            
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
            }
        }
        
        $SiteLinkResults.Dispose()
        $SiteLinkSearcher.Dispose()
        
        $SiteLinkDetails | Export-Csv "$Global:OutputPath\Infrastructure_Site_Links.csv" -NoTypeInformation
        
        # 7. Generate Summary
        $InfraStats = [PSCustomObject]@{
            # Forest Info
            ForestRootDN = $ForestDN
            CurrentDomain = $DomainInfo.DomainName
            ForestDomainCount = $ForestInfo.DomainCount
            SchemaVersion = $ForestInfo.SchemaVersion
            IsMultiDomainForest = $ForestInfo.IsMultiDomainForest
            
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
            
            ProcessingTime = ((Get-Date) - $ScriptStartTime).TotalMinutes
            AssessmentMethod = "ADSI"
        }
        
        $InfraStats | Export-Csv "$Global:OutputPath\Infrastructure_Summary_Stats.csv" -NoTypeInformation
        
        Write-Host "`n=== Assessment Complete ===" -ForegroundColor Green
        Write-Host "Forest contains $($ForestInfo.DomainCount) domain(s)" -ForegroundColor White
        Write-Host "Found $($DCDetails.Count) DCs, $($SiteDetails.Count) sites, $($SubnetDetails.Count) subnets" -ForegroundColor White
        Write-Host "Found $($TrustDetails.Count) trusts, $($SiteLinkDetails.Count) site links" -ForegroundColor White
        
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
    Write-Host "`nResults saved to: $Global:OutputPath" -ForegroundColor Yellow
}
