# Domain Controllers and Infrastructure Assessment - Fixed Version
# Version 5.3 - Optimized for som.ucsf.edu domain assessment

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
    Write-Log "=== Starting DC and Infrastructure Assessment for som.ucsf.edu ==="
    
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
        
        $RootDSE = [ADSI]"LDAP://RootDSE"
        $ConfigDN = $RootDSE.configurationNamingContext[0]
        $SchemaDN = $RootDSE.schemaNamingContext[0]
        $ForestDN = $RootDSE.rootDomainNamingContext[0]
        
        Write-Host "  Assessing Domain: $($DomainInfo.DomainName)" -ForegroundColor Green
        Write-Host "  Domain DN: $($DomainInfo.DomainDN)" -ForegroundColor Gray
        Write-Host "  Forest Root: $ForestDN" -ForegroundColor Gray
        
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
        
        $ForestInfo = [PSCustomObject]@{
            AssessedDomain = $DomainInfo.DomainName
            AssessedDomainDN = $DomainInfo.DomainDN
            AssessedDomainNetBIOS = $DomainInfo.NetBIOSName
            ForestRootDN = $ForestDN
            ConfigurationDN = $ConfigDN
            SchemaDN = $SchemaDN
            SchemaVersion = $SchemaVersion
            ForestDomains = $ForestDomains -join '; '
            DomainCount = $ForestDomains.Count
            IsMultiDomainForest = $ForestDomains.Count -gt 1
            AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        $ForestInfo | Export-Csv "$Global:OutputPath\Infrastructure_Forest_Information.csv" -NoTypeInformation
        Write-Host "  Forest information exported" -ForegroundColor Green
        
        # 2. Get som.ucsf.edu Domain Controllers
        Write-Host "`nAnalyzing som.ucsf.edu Domain Controllers..." -ForegroundColor Yellow
        
        $DCDetails = @()
        
        $DCSearcher = [adsisearcher]"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        $DCSearcher.SearchRoot = [ADSI]"LDAP://$($DomainInfo.DomainDN)"
        $DCSearcher.PageSize = 100
        $DCSearcher.PropertiesToLoad.AddRange(@(
            'name', 'dnshostname', 'operatingsystem', 'operatingsystemversion',
            'useraccountcontrol', 'whencreated', 'lastlogontimestamp', 'location',
            'serviceprincipalname', 'distinguishedname', 'description', 'serverreferenceBL'
        ))
        
        $DCResults = $DCSearcher.FindAll()
        Write-Host "  Found $($DCResults.Count) Domain Controllers in som.ucsf.edu" -ForegroundColor Green
        
        foreach ($DCResult in $DCResults) {
            $DCProps = $DCResult.Properties
            $DCName = if ($DCProps['name']) { $DCProps['name'][0] } else { "" }
            
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
                
                # Extract site from DN or serverReferenceBL
                $Site = "Unknown"
                $DCDN = if ($DCProps['distinguishedname']) { $DCProps['distinguishedname'][0] } else { "" }
                
                # Try serverReferenceBL first (more reliable)
                if ($DCProps['serverreferenceBL']) {
                    $ServerRef = $DCProps['serverreferenceBL'][0]
                    if ($ServerRef -match 'CN=([^,]+),CN=Servers,CN=([^,]+),CN=Sites') {
                        $Site = $Matches[2]
                    }
                }
                # Fallback to DN parsing
                elseif ($DCDN -match 'CN=Servers,CN=([^,]+),CN=Sites') {
                    $Site = $Matches[1]
                }
                
                $DCType = if ($IsReadOnly) { "RODC" } elseif ($IsGlobalCatalog) { "GC" } else { "DC" }
                Write-Host "    - $DCName (Site: $Site, Type: $DCType)" -ForegroundColor Gray
                
                $DCDetails += [PSCustomObject]@{
                    DCName = $DCName
                    DNSHostName = $DCDNSName
                    IPv4Address = $IPv4Address
                    Site = $Site
                    IsGlobalCatalog = $IsGlobalCatalog
                    IsReadOnly = $IsReadOnly
                    DCType = $DCType
                    OperatingSystem = if ($DCProps['operatingsystem']) { $DCProps['operatingsystem'][0] } else { "Unknown" }
                    OperatingSystemVersion = if ($DCProps['operatingsystemversion']) { $DCProps['operatingsystemversion'][0] } else { "Unknown" }
                    Description = if ($DCProps['description']) { $DCProps['description'][0] } else { "" }
                    WhenCreated = ConvertTo-DateTime -Value $DCProps['whencreated'][0] -Format "GeneralizedTime"
                    LastLogonDate = ConvertTo-DateTime -Value $DCProps['lastlogontimestamp'][0] -Format "FileTime"
                    Location = if ($DCProps['location']) { $DCProps['location'][0] } else { "" }
                    Enabled = !$DCUACAnalysis.IsDisabled
                    Domain = $DomainInfo.DomainName
                }
            } catch {
                Write-Warning "Error processing DC $DCName : $_"
            }
        }
        
        $DCResults.Dispose()
        $DCSearcher.Dispose()
        
        $DCDetails | Export-Csv "$Global:OutputPath\Infrastructure_Domain_Controllers.csv" -NoTypeInformation
        Write-Host "  Domain Controllers exported" -ForegroundColor Green
        
        # 3. Get Forest-wide Sites
        Write-Host "`nGetting Active Directory Sites (Forest-wide)..." -ForegroundColor Yellow
        
        $SiteDetails = @()
        
        $SitesSearcher = [adsisearcher]"(objectClass=site)"
        $SitesSearcher.SearchRoot = [ADSI]"LDAP://CN=Sites,$ConfigDN"
        $SitesSearcher.PageSize = 100
        $SitesSearcher.PropertiesToLoad.AddRange(@('name', 'description', 'location', 'whencreated', 'distinguishedname'))
        
        $SitesResults = $SitesSearcher.FindAll()
        Write-Host "  Found $($SitesResults.Count) sites in forest" -ForegroundColor Green
        
        foreach ($SiteResult in $SitesResults) {
            $SiteProps = $SiteResult.Properties
            $SiteName = if ($SiteProps['name']) { $SiteProps['name'][0] } else { "" }
            $SiteDN = if ($SiteProps['distinguishedname']) { $SiteProps['distinguishedname'][0] } else { "" }
            
            # Get subnet count for this site
            $SubnetCount = 0
            try {
                $SubnetSearcher = [adsisearcher]"(&(objectClass=subnet)(siteObject=$SiteDN))"
                $SubnetSearcher.SearchRoot = [ADSI]"LDAP://CN=Subnets,CN=Sites,$ConfigDN"
                $SubnetSearcher.PageSize = 100
                
                $SubnetResults = $SubnetSearcher.FindAll()
                $SubnetCount = $SubnetResults.Count
                
                $SubnetResults.Dispose()
                $SubnetSearcher.Dispose()
            } catch { }
            
            # Count DCs from som.ucsf.edu in this site
            $SiteDCs = $DCDetails | Where-Object {$_.Site -eq $SiteName}
            
            $SiteDetails += [PSCustomObject]@{
                SiteName = $SiteName
                Description = if ($SiteProps['description']) { $SiteProps['description'][0] } else { "" }
                Location = if ($SiteProps['location']) { $SiteProps['location'][0] } else { "" }
                WhenCreated = ConvertTo-DateTime -Value $SiteProps['whencreated'][0] -Format "GeneralizedTime"
                SubnetCount = $SubnetCount
                SOMDomainDCs = ($SiteDCs | Select-Object -ExpandProperty DCName) -join '; '
                SOMDomainDCCount = $SiteDCs.Count
                HasSOMDomainDCs = $SiteDCs.Count -gt 0
            }
        }
        
        $SitesResults.Dispose()
        $SitesSearcher.Dispose()
        
        $SiteDetails | Export-Csv "$Global:OutputPath\Infrastructure_AD_Sites.csv" -NoTypeInformation
        Write-Host "  Sites information exported" -ForegroundColor Green
        
        # 4. Trust Relationships for som.ucsf.edu
        Write-Host "`nGetting Trust Relationships for som.ucsf.edu..." -ForegroundColor Yellow
        
        $TrustDetails = @()
        
        $TrustSearcher = [adsisearcher]"(objectClass=trustedDomain)"
        $TrustSearcher.SearchRoot = [ADSI]"LDAP://CN=System,$($DomainInfo.DomainDN)"
        $TrustSearcher.PageSize = 100
        $TrustSearcher.PropertiesToLoad.AddRange(@(
            'name', 'trustdirection', 'trusttype', 'trustattributes', 
            'whencreated', 'whenchanged', 'flatname', 'trustpartner'
        ))
        
        $TrustResults = $TrustSearcher.FindAll()
        Write-Host "  Found $($TrustResults.Count) trust relationships" -ForegroundColor Green
        
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
                3 { "Kerberos" }
                4 { "DCE" }
                default { "Unknown" }
            }
            
            Write-Host "    - $TrustName ($TypeText, $DirectionText)" -ForegroundColor Gray
            
            $TrustDetails += [PSCustomObject]@{
                TrustName = $TrustName
                TrustPartner = if ($TrustProps['trustpartner']) { $TrustProps['trustpartner'][0] } else { $TrustName }
                TrustType = $TypeText
                TrustDirection = $DirectionText
                FlatName = if ($TrustProps['flatname']) { $TrustProps['flatname'][0] } else { "" }
                Created = ConvertTo-DateTime -Value $TrustProps['whencreated'][0] -Format "GeneralizedTime"
                Modified = ConvertTo-DateTime -Value $TrustProps['whenchanged'][0] -Format "GeneralizedTime"
                SourceDomain = $DomainInfo.DomainName
            }
        }
        
        $TrustResults.Dispose()
        $TrustSearcher.Dispose()
        
        $TrustDetails | Export-Csv "$Global:OutputPath\Infrastructure_Trust_Relationships.csv" -NoTypeInformation
        Write-Host "  Trust relationships exported" -ForegroundColor Green
        
        # 5. Generate Summary specifically for som.ucsf.edu
        $InfraStats = [PSCustomObject]@{
            # Domain Being Assessed
            AssessedDomain = $DomainInfo.DomainName
            AssessedDomainNetBIOS = $DomainInfo.NetBIOSName
            
            # Forest Info
            ForestRoot = if ($ForestDN -match 'DC=([^,]+),DC=([^,]+)') { "$($Matches[1]).$($Matches[2])" } else { $ForestDN }
            TotalForestDomains = $ForestInfo.DomainCount
            SchemaVersion = $ForestInfo.SchemaVersion
            IsMultiDomainForest = $ForestInfo.IsMultiDomainForest
            
            # som.ucsf.edu Domain Controllers
            TotalDomainControllers = $DCDetails.Count
            GlobalCatalogs = ($DCDetails | Where-Object {$_.IsGlobalCatalog -eq $true}).Count
            ReadOnlyDCs = ($DCDetails | Where-Object {$_.IsReadOnly -eq $true}).Count
            WritableDCs = ($DCDetails | Where-Object {$_.IsReadOnly -eq $false}).Count
            EnabledDCs = ($DCDetails | Where-Object {$_.Enabled -eq $true}).Count
            
            # Sites (Forest-wide with som.ucsf.edu DC presence)
            TotalForestSites = $SiteDetails.Count
            SitesWithSOMDCs = ($SiteDetails | Where-Object {$_.HasSOMDomainDCs -eq $true}).Count
            
            # Trusts for som.ucsf.edu
            TrustRelationships = $TrustDetails.Count
            
            # Assessment Details
            AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ProcessingTime = ((Get-Date) - $ScriptStartTime).TotalMinutes
            AssessmentMethod = "ADSI"
        }
        
        $InfraStats | Export-Csv "$Global:OutputPath\Infrastructure_Summary_Stats.csv" -NoTypeInformation
        Write-Host "  Summary statistics exported" -ForegroundColor Green
        
        Write-Host "`n=== Assessment Summary for som.ucsf.edu ===" -ForegroundColor Cyan
        Write-Host "Domain Controllers: $($DCDetails.Count) (GCs: $($InfraStats.GlobalCatalogs), RODCs: $($InfraStats.ReadOnlyDCs))" -ForegroundColor White
        Write-Host "Sites with som.ucsf.edu DCs: $($InfraStats.SitesWithSOMDCs) out of $($InfraStats.TotalForestSites) forest sites" -ForegroundColor White
        Write-Host "Trust Relationships: $($TrustDetails.Count)" -ForegroundColor White
        Write-Host "Forest Domains: $($InfraStats.TotalForestDomains)" -ForegroundColor White
        Write-Host "Schema Version: $($InfraStats.SchemaVersion)" -ForegroundColor White
        
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
