

# 🛡️ Inspect-WindowsAttackSurface.ps1

A **read-only Windows attack surface inventory tool**.

This script takes a snapshot of a Windows machine and builds a detailed view of:

- What processes are running  
- Which ports and remote IPs they use  
- How “exposed” they are (attack surface, data exfil potential, risk score)

It **does not** kill processes, change firewall rules, or edit the registry.  
It only *reads* system state and writes reports to disk.

---

## 📦 What this script gives you

Each run produces **five** files in a `SecurityReports` folder:

1. **CSV** – `Inventory-YYYYMMDD-HHMMSS.csv`  
   Spreadsheet view of all processes and their risk metrics.

2. **JSON** – `Inventory-YYYYMMDD-HHMMSS.json`  
   Same data in JSON (for scripts, automation, or feeding to AI tools).

3. **Deep Dive TXT** – `DeepDive-YYYYMMDD-HHMMSS.txt`  
   Human-readable breakdown of “interesting” processes (High/Medium risk or network-active).

4. **HTML dashboard** – `Report-YYYYMMDD-HHMMSS.html`  
   A visual report with bars & tables for:
   - Risk summary (High / Medium / Low)
   - Top 10 by risk score
   - Top outbound “talkers”
   - Top listening processes
   - Script configuration summary

5. **Run log** – `RunLog-YYYYMMDD-HHMMSS.txt`  
   What the script did, with timestamps and any warnings/errors.

---

## 🧩 Requirements

- Windows 10 or 11 (Home or Pro)
- Built-in **Windows PowerShell**
- Local account with permission to run PowerShell **as Administrator** (recommended)

You do **not** need:

- Any extra PowerShell modules
- Internet access
- Domain admin privileges

---

## 🛠️ Step 1 – Create the script folder

We’ll keep everything in one place: `C:\Tools\SecurityScripts`.

1. Open **File Explorer**.
2. Browse to `C:\`.
3. Right-click → **New → Folder** → name it:

   ```text
   Tools


Open C:\Tools.

Right-click → New → Folder → name it:

SecurityScripts


You should now have:

C:\Tools\SecurityScripts

✍️ Step 2 – Save the script file

Press Start, type notepad, press Enter.

Paste the full script code for Inspect-WindowsAttackSurface.ps1 (v1.7) into Notepad.

In Notepad, go to File → Save As…

In the File name box, enter:

C:\Tools\SecurityScripts\Inspect-WindowsAttackSurface.ps1


In Save as type, choose All Files (.).

Click Save.

You should now see this file in Explorer:

C:\Tools\SecurityScripts\Inspect-WindowsAttackSurface.ps1

🔐 Step 3 – Allow local scripts to run (Execution Policy)

By default, Windows blocks all PowerShell scripts.
We’ll set a safer per-user policy that allows scripts you create or trust to run.

⚠️ This does not fully disable protection.
It only allows scripts for the current user and requires downloaded scripts to be “unblocked” or trusted.

Press Start, type:

powershell


In the results, right-click Windows PowerShell → choose Run as administrator.

In the blue/black window, run:

Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned


You’ll see a warning with:

[Y] Yes  [A] Yes to All  [N] No  ...


Type:

A


and press Enter.

You only need to do this once per user account on that machine.

🧭 Step 4 – Open PowerShell as Administrator & navigate

To get full visibility (especially system processes & services), run the script as admin.

Press Start, type:

powershell


Right-click Windows PowerShell → Run as administrator → click Yes.

In the PowerShell window, go to the script folder:

cd C:\Tools\SecurityScripts


(Optional) Confirm the script is there:

Get-ChildItem


You should see:

Inspect-WindowsAttackSurface.ps1

🚀 Step 5 – Run the script

From the admin PowerShell window in C:\Tools\SecurityScripts, run:

.\Inspect-WindowsAttackSurface.ps1


The first run may take 20–60 seconds depending on:

Number of processes

Current system load

You’ll see output similar to:

[2025-11-23 05:52:43] [SUCCESS] PowerShell session is running with administrative privileges.
[2025-11-23 05:52:43] [INFO] Machine: DESKTOP-XYZ | OS: Microsoft Windows 11 Pro | Version: ...
[2025-11-23 05:52:43] [INFO] === Inspect-WindowsAttackSurface.ps1 starting (version 1.7) ===
[2025-11-23 05:52:43] [INFO] Collecting process inventory...
...
[2025-11-23 05:53:06] [SUCCESS] CSV inventory exported to: C:\Tools\SecurityScripts\SecurityReports\Inventory-2025...
[2025-11-23 05:53:06] [SUCCESS] HTML visual report exported to: C:\Tools\SecurityScripts\SecurityReports\Report-2025...
[2025-11-23 05:53:06] [INFO] Summary: High=1, Medium=24, Low=168
[2025-11-23 05:53:06] [SUCCESS] === Inspect-WindowsAttackSurface.ps1 completed ===
[2025-11-23 05:53:06] [SUCCESS] Log file saved to: C:\Tools\SecurityScripts\SecurityReports\RunLog-2025...


If you don’t see any red [ERROR] lines, the run completed successfully.

📁 Step 6 – Find your reports

The script automatically creates a SecurityReports folder inside your script directory.

Path:

C:\Tools\SecurityScripts\SecurityReports


Each run adds files with a unique timestamp, for example:

Inventory-20251123-055243.csv
Inventory-20251123-055243.json
DeepDive-20251123-055243.txt
Report-20251123-055243.html
RunLog-20251123-055243.txt

🌈 Step 7 – Use the HTML dashboard

The HTML report is the fastest way to see what’s happening on the machine.

Open File Explorer.

Go to:

C:\Tools\SecurityScripts\SecurityReports


Find the latest:

Report-YYYYMMDD-HHMMSS.html


Double-click it to open in your default browser.

What you’ll see

Risk Summary card

Total number of High / Medium / Low risk processes

Bar graph showing the relative counts

Top 10 by Risk Score

Which processes are most “interesting” from an attack-surface perspective

Risk category + numeric score (0–100) + likely role (browser, remote desktop, system service, etc.)

Top 10 Outbound “Talkers”

Processes with the most unique remote IPs

Good for spotting noisy apps or unexpected network activity

Top 10 Listening Processes

Processes with the most listening ports

Good for seeing which apps are waiting for inbound connections

Script Configuration Summary

A list of process names the script treats as:

Trusted but high-surface tools (e.g. remote desktop clients)

Browsers

Remote access tools

Cloud sync clients

Chat/collab apps

Core Windows system processes

This reflects the configuration at the top of the script (you can edit those lists later if you like).

🔍 Step 8 – Read the Deep Dive report

Open the matching deep-dive text file:

C:\Tools\SecurityScripts\SecurityReports\DeepDive-YYYYMMDD-HHMMSS.txt


This file focuses on “interesting” processes only:

Any process with High or Medium risk

Any process with network activity (connections or listening ports)

Each entry includes:

PID & process name

UserName (which account it runs under)

LikelyRole (e.g., Web browser, RustDesk remote desktop client/agent, Windows service host, etc.)

AttackSurface (Low / Medium / High)

DataExfiltrationPotential (Yes / No / Unknown)

RiskScore and RiskCategory

IsWindowsComponent (true/false, with special handling for core Windows processes)

Path, Company, Description

StartTime

Network details:

LocalPorts

RemoteIPs

OutboundConnectionCount

InboundListeningCount

For svchost.exe, a list of Windows services hosted inside that instance

RiskReasons: short explanation of why the score is what it is

This is the “manual triage” view: you can scroll process by process and decide:

“Is this something I expect?”

“Do I trust this vendor & path?”

“Do I really want this listening on the network?”

🔁 Step 9 – Running it again later

You can run the script as often as you like.
Each run creates new timestamped output so you can compare:

Before vs after installing/removing software

Before vs after tuning services

Different machines (e.g., clean workstation vs. “mystery” family laptop)

To re-run:

# Run PowerShell as Administrator first, then:
cd C:\Tools\SecurityScripts
.\Inspect-WindowsAttackSurface.ps1

🧯 Step 10 – Common errors & fixes
❌ Error: “Running scripts is disabled on this system”

You might see:

File C:\Tools\SecurityScripts\Inspect-WindowsAttackSurface.ps1 cannot be loaded
because running scripts is disabled on this system.


Fix (once per user), in admin PowerShell:

Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned


Choose:

A


for “Yes to All”.

❌ Script runs, but no network data appears

If the machine is idle and nothing has connected to the network recently, you may see very few network entries.

Try this:

Open a browser and visit a website.

Open any remote-access tool (e.g. RustDesk).

Wait a few seconds.

Run the script again.

You should now see more populated RemoteIPs, OutboundConnectionCount, and ListeningPorts data.

⚙️ (Optional) Tweaking behavior via config

At the top of the script there is a configuration block:

$Config = @{
    TrustedHighSurfaceProcesses = @('rustdesk','wireguard','wg','tailscale')
    BrowserProcesses            = @('chrome','firefox','msedge', ...)
    RemoteAccessProcesses       = @('rustdesk','teamviewer', ...)
    CloudSyncProcesses          = @('onedrive','dropbox', ...)
    ChatCollabProcesses         = @('discord','slack','teams', ...)
    CoreSystemProcesses         = @('system','wininit','lsass','svchost', ...)
}


You can:

Add your own tools to TrustedHighSurfaceProcesses
→ they will still be treated as high-surface but with slightly less harsh scoring and a note explaining they are intentionally trusted.

Add/remove process names in the browser / remote / chat lists
→ this changes the “LikelyRole” and risk heuristics.

If you’re new to PowerShell, you can ignore this at first and use the defaults.
The script will still work fine.

✅ Summary

Put the script in C:\Tools\SecurityScripts\Inspect-WindowsAttackSurface.ps1

Run PowerShell as Administrator

Allow local scripts with:

Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned


Run the script:

cd C:\Tools\SecurityScripts
.\Inspect-WindowsAttackSurface.ps1


Open the latest Report-*.html for a visual dashboard

Open DeepDive-*.txt for detailed triage

This gives you a repeatable, read-only “X-ray” of any Windows machine’s attack surface in just a couple of minutes.


---
