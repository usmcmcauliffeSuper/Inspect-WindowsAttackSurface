# Inspect-WindowsAttackSurface

A PowerShell script that inventories running processes, network connections, ports, and basic attack surface on Windows 10/11, then generates:

- CSV and JSON inventory of processes and ports  
- A deep-dive text report for interesting/high-risk processes  
- An HTML visual report (risk bars, counts by category, etc.)

## Quick Start

1. Download `Inspect-WindowsAttackSurface.ps1`.
2. Save it to `C:\Tools\SecurityScripts\` on your Windows machine.
3. Run **PowerShell as Administrator**.
4. Set execution policy temporarily (only once per machine):

   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Run the script:

powershell
Copy code
cd C:\Tools\SecurityScripts
.\Inspect-WindowsAttackSurface.ps1
Open the generated HTML report in your browser from:

text
Copy code
C:\Tools\SecurityScripts\SecurityReports\
For full details, see: HOWTO-Inspect-WindowsAttackSurface.md.
