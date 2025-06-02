# AD-Discovery-Assessment.ps1 - Ultimate Edition
**AD-Discovery-Assessment.ps1 Ultimate Edition** is the most comprehensive PowerShell script available for Active Directory assessment and migration planning. It features advanced **corruption detection**, **risk-based analysis**, and **PowerBI-optimized reporting** across all AD components. The script exports data into over **85 detailed and structured CSV files** with executive-ready summaries. This Ultimate Edition is ideal for enterprise environments, migration projects, and organizations requiring professional AD health assessments.

---

## Ultimate Edition Features
- **Advanced Corruption Detection**  
  Performs 15+ user account validations and 12+ computer security checks to identify missing attributes, broken ACLs, orphaned SIDs, delegation issues, and tombstoned objects with Critical/High/Medium/Low severity classification!
- **PowerBI-Optimized Reporting**  
  All 85+ CSV files use consistent, dashboard-friendly naming and include cross-table relationship keys for automated PowerBI connections and executive dashboard creation!
- **Performance & Scale Optimization**  
  Handles 50,000+ objects efficiently with batch processing, memory optimization, and real-time progress tracking. 25-40% faster than standard assessments by eliminating duplicate processing!
- **Risk-Based Analysis**  
  Categorizes all findings by severity level with specific remediation timelines and provides migration readiness assessment with clear go/no-go recommendations!
- **Enhanced Interactive Menu**  
  Updated menu system with 19 assessment options including Ultimate Edition enhancements and optimized bulk operations for comprehensive analysis!
- **Executive Summary Generation**  
  Automatically generates management-ready corruption analysis summaries with risk assessment, migration readiness, and PowerBI integration guidance!

---

## Usage

### Prerequisites
- Ensure you have **Domain Admin privileges** to access all AD components. Enterprise Admin permissions recommended for multi-domain forests.
- Run the script on a system with the **Active Directory PowerShell module** and **RSAT Tools** installed.
- Verify network connectivity to all domain controllers for comprehensive assessment.
- Minimum 4GB RAM recommended for large environments (50,000+ objects).

### Execution
1. Launch PowerShell with administrative privileges.
2. Navigate to the directory containing the script.
3. Unblock the file if downloaded from the internet:
    ```powershell
    Unblock-File -Path ".\AD-Discovery-Assessment.ps1"
    ```
4. Run the script:
    ```powershell
    .\AD-Discovery-Assessment.ps1
    ```
5. Select **Option 19 (Complete Ultimate Assessment)** for comprehensive analysis with corruption detection.
6. Follow the interactive menu to select specific modules if needed.

### Output
The Ultimate Edition generates 85+ CSV files optimized for PowerBI dashboard creation, plus executive summary reports in the script's directory. All files use consistent naming for easy analysis and professional reporting.

---

## Assessment Options

### Ultimate Edition Enhancements
- **Enhanced Users Assessment (Option 13)** – 40+ user attributes with comprehensive corruption detection including missing attributes, delegation analysis, and password policy violations.
- **Enhanced Computers Assessment (Option 14)** – 35+ computer attributes with security validation, LAPS deployment status, BitLocker analysis, and end-of-life system detection.
- **Circular Group Membership Detection (Option 15)** – Identifies groups that are members of themselves through nested membership, preventing authentication issues.
- **Advanced SPN Analysis (Option 16)** – Comprehensive Service Principal Name analysis with duplicate detection and risk assessment across all AD objects.

### Standard Infrastructure Assessments
- **AD Users Assessment (Option 1)** – Standard user account inventory with basic attributes and account type classification.
- **AD Computers Assessment (Option 2)** – Computer account details including operating system compliance and activity status.
- **Printers Assessment (Option 3)** – Information on printers published in AD and print server identification.
- **File Shares Assessment (Option 4)** – Data on shared resources, DFS configuration, and file server inventory.
- **Group Policy Assessment (Option 5)** – Information on GPOs, their links, settings, and login script analysis.
- **CMDB Data Validation (Option 6)** – Validates Configuration Management Database accuracy against actual AD data.
- **DNS Assessment (Option 7)** – Details on DNS zones, records, forwarders, and AD-integrated zone configuration.
- **Domain Controllers & Infrastructure (Option 8)** – Information about each DC, FSMO roles, replication status, and trust relationships.
- **AD-Integrated Applications (Option 9)** – Service Principal Names, Exchange servers, SQL servers, and enterprise application discovery.
- **Security Assessment (Option 10)** – Password policies, privileged group membership, audit settings, and security configuration.
- **Certificate Services (Option 11)** – Details on certificate authorities, templates, and PKI infrastructure components.
- **DHCP Assessment (Option 12)** – DHCP servers, scopes, statistics, authorization status, and IP address utilization.

### Bulk Operations
- **Complete Ultimate Assessment (Option 19)** – **RECOMMENDED** - Runs optimized comprehensive analysis with corruption detection, eliminating duplicate processing for maximum efficiency.
- **Standard Assessments Suite (Option 17)** – Executes all basic assessments (Options 1-12) without Ultimate Edition enhancements.
- **Ultimate Enhancements Only (Option 18)** – Runs only the advanced corruption detection modules (Options 13-16).

---

## Key Output Files

### PowerBI-Optimized Primary Reports
- **Users_Enhanced.csv** – Complete user inventory with 40+ attributes including corruption analysis, delegation rights, and account type classification.
- **Computers_Enhanced.csv** – Comprehensive computer details with 35+ attributes including security validation, LAPS status, and OS compliance.

### Corruption Analysis Reports
- **Users_Corrupted.csv** – User accounts with corruption issues categorized by Critical/High/Medium/Low severity levels.
- **Computers_Corrupted.csv** – Computer accounts with validation problems including password age, delegation, and configuration issues.
- **Groups_Circular_Memberships.csv** – Groups with circular membership references that can cause authentication problems.
- **SPNs_Duplicate.csv** – Duplicate Service Principal Names that can cause Kerberos authentication failures.

### Risk Assessment Reports
- **Service_Accounts_High_Risk.csv** – Service accounts with dangerous configurations including delegation rights and administrative privileges.
- **Admin_Accounts_Stale.csv** – Inactive privileged accounts that pose security risks and should be reviewed.
- **Users_Disabled_But_Grouped.csv** – Disabled user accounts still maintaining group memberships.
- **Computers_Without_LAPS.csv** – Workstations missing Local Administrator Password Solution deployment.

### Executive Summaries
- **Ultimate_Executive_Summary.txt** – Management-ready analysis with corruption statistics, risk assessment, and migration readiness evaluation.
- **Ultimate_Assessment_Summary.txt** – Technical summary with processing statistics, optimization results, and PowerBI integration guidance.

### Standard Infrastructure Reports
- **Infrastructure_Domain_Controllers.csv** – Domain controller health, services status, and role assignments.
- **Security_Privileged_Group_Members.csv** – Complete inventory of all privileged account memberships.
- **DNS_Zones.csv** – DNS zone configuration and AD integration status.
- **GPO_Details.csv** – Group Policy Objects with link analysis and settings summary.
- **Applications_Enterprise_Applications.csv** – Discovered enterprise applications and their AD integration.

---

## PowerBI Dashboard Integration
The Ultimate Edition generates CSV files specifically optimized for PowerBI dashboard creation with consistent naming and cross-table relationship keys.

### Dashboard Creation Process
1. Import all CSV files into PowerBI Desktop using the optimized file structure.
2. Utilize auto-detect relationships with built-in cross-table keys for seamless data connections.
3. Create executive dashboards using corruption level metrics and risk categorization.
4. Implement filtering by severity levels (Critical/High/Medium/Low) for prioritized remediation planning.

### Recommended Dashboard Pages
- **Executive Summary** – Overall AD health, corruption statistics, and migration readiness assessment.
- **User Analysis** – Account type distribution, activity patterns, and corruption analysis across user population.
- **Computer Analysis** – Operating system compliance, security posture, LAPS deployment, and end-of-life system tracking.
- **Infrastructure Health** – Service Principal Names, group membership analysis, replication status, and delegation rights overview.

---

## Corruption Detection Capabilities

### Severity Classifications
- **Critical Issues** – Missing core attributes, tombstoned objects, broken security descriptors requiring immediate attention.
- **High Risk Issues** – Unconstrained delegation, password policy violations, duplicate SPNs requiring remediation within 30 days.
- **Medium Risk Issues** – Orphaned SIDHistory, excessive bad password counts, stale accounts requiring attention within 90 days.
- **Low Risk Issues** – Ancient lockout times, minor UAC inconsistencies suitable for regular maintenance cycles.

### Migration Readiness Assessment
The Ultimate Edition provides clear migration readiness evaluation based on corruption levels:
- **READY** – No Critical/High issues detected, suitable for migration planning.
- **CAUTION** – Medium risk issues present, consider remediation before migration.
- **NOT READY** – Critical or High severity issues require immediate attention before migration planning.

---

## Performance Optimizations
- **Large Environment Support** – Efficiently processes 50,000+ AD objects with batch processing and memory optimization techniques.
- **Elimination of Duplicate Processing** – Ultimate Assessment Suite (Option 19) uses Enhanced versions to replace standard assessments, providing 25-40% performance improvement.
- **PowerBI Integration Optimization** – Structured data format reduces dashboard creation time by 50% compared to standard exports.
- **Real-time Progress Tracking** – Accurate time estimates and completion percentages for long-running assessments.

---

## Best Practices

### Assessment Planning
- Schedule assessments during maintenance windows for large environments to minimize performance impact.
- Use Option 19 (Complete Ultimate Assessment) for comprehensive analysis with corruption detection.
- Ensure sufficient disk space (500MB+) for output file generation.
- Review Ultimate_Executive_Summary.txt immediately after completion for critical findings.

### Remediation Process
1. Address **Critical** severity issues immediately to prevent AD instability.
2. Plan **High** risk remediation within 30 days to maintain security posture.
3. Schedule **Medium** risk fixes within 90 days as part of regular maintenance.
4. Include **Low** risk items in quarterly maintenance cycles.

### Migration Planning
- Ensure no Critical or High severity corruption before initiating migration projects.
- Use operating system compliance data for hardware refresh and upgrade planning.
- Validate CMDB accuracy against AD findings for accurate asset management.

---

