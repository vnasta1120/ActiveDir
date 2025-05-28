# AD-Discovery-Assessment.ps1

**AD-Discovery-Assessment.ps1** is a comprehensive PowerShell script designed to perform an extensive assessment of Active Directory (AD) environments. It collects a wide range of information across nearly all AD components and then exports the data into over **75 detailed and structured CSV files**. This script is ideal for anyone who is looking to obtain highly detailed insights into their AD infrastructure.

---

## Features

- **Modular Design**  
  Each function targets a specific aspect of AD, such as domain controllers, users, groups, organizational units (OUs), group policies, DNS zones, replication status, and more!

- **Interactive Menu**  
  Upon execution, the script presents an interactive menu, allowing users to select specific modules for data collection (Who doesn't love a nice menu!)

- **Comprehensive Data Collection**  
  When all modules are executed, the script gathers extensive information, exporting each dataset into their very own personalized CSV files for easy analysis!

---

## Usage

### Prerequisites

- Ensure you have the necessary permissions to query AD components. Highly recommend using Domain Admin permissions to use the entire script to it's full potential.
- Run the script on a system with the **Active Directory PowerShell module** installed.

### Execution

1. Launch PowerShell with administrative privileges.
2. Navigate to the directory containing the script.
3. Run the script:

    ```powershell
    .\AD-Discovery-Assessment.ps1
    ```

4. Follow the interactive menu to select desired modules.

### Output

Each selected module will generate a corresponding CSV file in the script's directory.

---

## Modules Included

- **Domain Controllers (DCs)** – Information about each DC, including roles and replication status.
- **Organizational Units (OUs)** – Structure and hierarchy of OUs.
- **Users** – Details on user accounts, including statuses like disabled, locked out, or password expired.
- **Groups** – Data on security and distribution groups, including membership and nesting.
- **Group Policy Objects (GPOs)** – Information on GPOs, their links, and settings.
- **DNS Zones** – Details on DNS zones and records.
- **Sites and Subnets** – Configuration of AD sites and associated subnets.
- **Trusts** – Information on trust relationships with other domains.
- **Replication** – Status and configuration of AD replication.
- **FSMO Roles** – Assignment of Flexible Single Master Operations roles.
- **Service Accounts** – Details on managed service accounts.
- **Computers** – Information on computer accounts within the domain.
- **Printers** – Data on printers published in AD.
- **Shares** – Information on shared resources.
- **Certificates** – Details on certificate templates and issued certificates.
- **Fine-Grained Password Policies** – Information on password policies applied to users and groups.
- **Delegation** – Details on accounts with delegation rights.
- **SID History** – Information on security identifier history for accounts.
- **Kerberos Delegation** – Details on accounts configured for Kerberos delegation.
- **AD Recycle Bin** – Status and configuration of the AD Recycle Bin feature.
- **Schema** – Information on the AD schema version and extensions.
- **AD Sites** – Details on site links and configurations.

---
