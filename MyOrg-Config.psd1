@{
    # =============================================================================
    # Enhanced AD Assessment - Organization Configuration File
    # =============================================================================
    # This file allows you to customize the AD assessment for your organization.
    # Save this file and use: .\Enhanced-AD-Assessment.ps1 -ConfigFile "YourOrg-Config.psd1"
    #
    # If a setting is not specified, the script will auto-detect or use secure defaults.
    # All thresholds are in days unless otherwise specified.
    # =============================================================================

    # =============================================================================
    # ORGANIZATIONAL THRESHOLDS
    # =============================================================================
    # Customize these values based on your organization's policies and requirements
    
    # Days to consider user account inactive (auto-detected from domain password policy if not specified)
    InactiveUserDays = 90
    
    # Days to consider computer account inactive 
    InactiveComputerDays = 90
    
    # Days to consider password stale (typically 2x password max age)
    StalePasswordDays = 180
    
    # Days for computer password age concern (default: 60)
    OldComputerPasswordDays = 60
    
    # =============================================================================
    # CORRUPTION DETECTION THRESHOLDS
    # =============================================================================
    # Adjust these values to match your organization's tolerance levels
    
    # Bad password count threshold before flagging as excessive
    ExcessiveBadPasswordCount = 100
    
    # Maximum deny ACEs before flagging as suspicious
    MaxDenyACEs = 10
    
    # Maximum depth for circular group membership detection (prevents infinite loops)
    CircularGroupDepthLimit = 20
    
    # Threshold for duplicate SPN detection (1 = flag any duplicates)
    SPNDuplicateThreshold = 1
    
    # =============================================================================
    # PERFORMANCE SETTINGS
    # =============================================================================
    # Adjust these based on your environment size and performance requirements
    
    # Objects processed per batch (larger = faster but more memory)
    BatchSize = 100
    
    # Maximum parallel processing jobs
    MaxParallelJobs = 8
    
    # How often to update progress display (every N items for users)
    ProgressUpdateInterval = 10
    
    # Progress updates for computer processing (more frequent due to complexity)
    ComputerProgressInterval = 5
    
    # =============================================================================
    # ASSESSMENT FEATURES
    # =============================================================================
    # Enable or disable specific assessment modules for your needs
    
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
    
    # =============================================================================
    # SECURITY SETTINGS
    # =============================================================================
    # Customize these for your organization's specific security structure
    
    SecuritySettings = @{
        # Groups considered privileged in your organization
        # Add your organization-specific privileged groups here
        PrivilegedGroups = @(
            # Standard Windows privileged groups
            "Domain Admins"
            "Enterprise Admins" 
            "Schema Admins"
            "Administrators"
            "Account Operators"
            "Backup Operators"
            "Server Operators"
            "Domain Controllers"
            "Read-only Domain Controllers"
            "Group Policy Creator Owners"
            "Cryptographic Operators"
            
            # Add your organization-specific privileged groups below
            # Examples (uncomment and modify as needed):
            # "YourOrg Domain Admins"
            # "YourOrg SQL Admins"
            # "YourOrg Exchange Admins"
            # "YourOrg Helpdesk Tier 2"
            # "Privileged Access Workstation Users"
        )
        
        # Patterns to identify service accounts (case-insensitive regex patterns)
        # Customize these based on your organization's naming conventions
        ServiceAccountIdentifiers = @(
            "svc"           # Common: svc-sql, svc-web, etc.
            "service"       # Common: service-app, service-db
            "app"           # Common: app-sharepoint, app-exchange
            "sql"           # SQL Server service accounts
            "system"        # System accounts
            "iis"           # IIS application pool accounts
            "web"           # Web service accounts
            
            # Add your organization-specific patterns below
            # Examples (uncomment and modify as needed):
            # "yourorg-svc"   # YourOrg-svc-sql, YourOrg-svc-web
            # "sa-"           # sa-application, sa-database
            # "srvc"          # Alternative service naming
        )
        
        # Patterns to identify admin accounts (case-insensitive regex patterns)
        # Customize these based on your organization's naming conventions
        AdminAccountIdentifiers = @(
            "admin"         # Common: john.admin, admin-server
            "adm"           # Common: john.adm, adm-db
            "_a$"           # Suffix: john_a, jane_a
            "-admin"        # Suffix: john-admin, server-admin
            ".admin"        # Suffix: john.admin, server.admin
            "administrator" # Full word: administrator, db-administrator
            
            # Add your organization-specific patterns below
            # Examples (uncomment and modify as needed):
            # "yourorg-admin" # YourOrg-admin-sql, YourOrg-admin-ex
            # "_adm$"         # Suffix: john_adm, jane_adm
            # "privuser"      # Privileged user accounts
        )
    }
    
    # =============================================================================
    # CORRUPTION DETECTION SEVERITY THRESHOLDS
    # =============================================================================
    # Define what constitutes each severity level for your organization
    
    CriticalThresholds = @{
        # Issues that require immediate attention
        MissingCoreAttributes = $true      # Missing SamAccountName, SID, etc.
        TombstonedObjects = $true          # Objects marked as deleted but still accessible
        UnreadableACLs = $true             # Cannot read security descriptor
    }
    
    HighRiskThresholds = @{
        # Issues that should be addressed within 30 days
        UnconstrainedDelegation = $true                # Accounts with unconstrained delegation
        PasswordNeverExpiresWithDelegation = $true     # Dangerous combination
        ExcessiveDenyACEs = 10                         # Too many explicit deny permissions
        EndOfLifeOS = $true                            # Operating systems past support
        DuplicateSPNs = $true                          # Duplicate service principal names
    }
    
    MediumRiskThresholds = @{
        # Issues that should be addressed within 90 days
        OrphanedSIDHistory = $true         # SIDHistory entries that can't be resolved
        ExcessiveBadPasswordCount = 100    # High bad password attempts
        StaleActiveAccounts = 90           # Enabled but unused accounts (days)
        OldComputerPasswords = 60          # Computer passwords not changed (days)
    }
    
    # =============================================================================
    # OUTPUT CUSTOMIZATION
    # =============================================================================
    # Configure how the assessment results are exported
    
    OutputSettings = @{
        # Records per CSV export batch (larger = fewer file writes but more memory)
        ExportBatchSize = 1000
        
        # Use UTF-8 encoding for international characters
        UseUTF8Encoding = $true
        
        # Generate PowerBI-friendly column names and data types
        PowerBIOptimized = $true
        
        # Create executive summary report automatically
        GenerateExecutiveSummary = $true
    }
    
    # =============================================================================
    # ADVANCED SETTINGS
    # =============================================================================
    # Advanced configuration options for specific environments
    
    AdvancedSettings = @{
        # Skip auto-detection and use only explicit configuration
        SkipAutoDetection = $false
        
        # Custom LDAP search base (leave empty for auto-detection)
        CustomSearchBase = ""
        
        # Custom domain controller to query (leave empty for auto-detection)
        PreferredDomainController = ""
        
        # Enable verbose logging for troubleshooting
        EnableVerboseLogging = $false
        
        # Custom output path (leave empty to use script default)
        CustomOutputPath = ""
    }
    
    # =============================================================================
    # COMPLIANCE SETTINGS
    # =============================================================================
    # Configure compliance and regulatory requirements
    
    ComplianceSettings = @{
        # Require specific minimum password length
        RequiredMinPasswordLength = 14
        
        # Require password complexity
        RequirePasswordComplexity = $true
        
        # Maximum allowed password age (days)
        MaxAllowedPasswordAge = 90
        
        # Require smart cards for privileged accounts
        RequireSmartCardsForPrivileged = $false
        
        # Flag accounts without recent logon
        FlagInactivePrivilegedAccountDays = 30
    }
    
    # =============================================================================
    # ORGANIZATION INFORMATION
    # =============================================================================
    # Optional: Add your organization details for reporting
    
    OrganizationInfo = @{
        # Organization name for reports
        Name = "Your Organization Name"
        
        # Assessment contact information
        Contact = "IT Security Team"
        
        # Assessment purpose/project
        Purpose = "AD Health Assessment and Migration Planning"
        
        # Assessment date/version
        Version = "1.0"
        
        # Notes about this configuration
        Notes = "Customized configuration for production environment assessment"
    }
}

# =============================================================================
# CONFIGURATION EXAMPLES
# =============================================================================
<#
Example 1: Small Organization Configuration
@{
    InactiveUserDays = 60
    InactiveComputerDays = 60
    SecuritySettings = @{
        PrivilegedGroups = @("Domain Admins", "Administrators")
        ServiceAccountIdentifiers = @("svc", "service")
        AdminAccountIdentifiers = @("admin", "_a$")
    }
}

Example 2: Large Enterprise Configuration
@{
    InactiveUserDays = 120
    InactiveComputerDays = 90
    BatchSize = 200
    SecuritySettings = @{
        PrivilegedGroups = @(
            "Domain Admins", "Enterprise Admins", "Schema Admins",
            "ACME-SQL-Admins", "ACME-Exchange-Admins", "ACME-Tier1-Admins"
        )
        ServiceAccountIdentifiers = @("svc", "acme-svc", "sa-", "app-")
        AdminAccountIdentifiers = @("admin", "acme-admin", "_adm$")
    }
}

Example 3: Security-Focused Configuration
@{
    InactiveUserDays = 30
    InactiveComputerDays = 45
    ExcessiveBadPasswordCount = 50
    HighRiskThresholds = @{
        UnconstrainedDelegation = $true
        PasswordNeverExpiresWithDelegation = $true
        ExcessiveDenyACEs = 5
        EndOfLifeOS = $true
        DuplicateSPNs = $true
    }
    ComplianceSettings = @{
        RequiredMinPasswordLength = 16
        RequirePasswordComplexity = $true
        MaxAllowedPasswordAge = 60
        RequireSmartCardsForPrivileged = $true
        FlagInactivePrivilegedAccountDays = 14
    }
}
#>

# =============================================================================
# USAGE INSTRUCTIONS
# =============================================================================
<#
1. Save this file with a descriptive name like "YourOrg-AD-Config.psd1"
2. Customize the settings above for your organization
3. Run the assessment with your configuration:
   .\Enhanced-AD-Assessment.ps1 -ConfigFile "YourOrg-AD-Config.psd1"

4. To test your configuration:
   .\Enhanced-AD-Assessment.ps1 -ConfigFile "YourOrg-AD-Config.psd1"
   # Select option 18 to view your configuration

5. For a complete assessment with your custom settings:
   .\Enhanced-AD-Assessment.ps1 -ConfigFile "YourOrg-AD-Config.psd1"
   # Select option 21 for Complete Universal Assessment

Note: Any setting not specified will use auto-detection or secure defaults.
#>
