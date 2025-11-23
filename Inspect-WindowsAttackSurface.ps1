<#
.SYNOPSIS
    Inspect-WindowsAttackSurface.ps1 - Read-Only Windows Attack Surface Inventory Tool (v1.7)

.DESCRIPTION
    Takes a snapshot of the current Windows system and builds a detailed, READ-ONLY
    inventory of the attack surface.

    It produces FIVE artifacts per run:
      1) CSV  - Inventory-<timestamp>.csv   (spreadsheet view)
      2) JSON - Inventory-<timestamp>.json  (script / automation / AI view)
      3) LOG  - RunLog-<timestamp>.txt      (what the script did and any errors)
      4) TXT  - DeepDive-<timestamp>.txt    (human-readable triage on interesting processes)
      5) HTML - Report-<timestamp>.html     (visual "dashboard" for quick review / show & tell)

    High-level behavior:
      - Enumerates running processes (+ company, product, hashes, signer, architecture, user, etc.)
      - Correlates processes with network activity (TCP/UDP connections and listeners).
      - Assigns:
            * AttackSurface (Low / Medium / High)
            * DataExfiltrationPotential (Yes / No / Unknown)
            * RiskScore (0-100) and RiskCategory (Low / Medium / High)
            * RiskReasons (string explaining why)
            * LikelyRole (best-effort guess at "what this is for")
      - Builds an extended Deep Dive report for any process that is:
            * High or Medium risk, OR
            * Has any network activity
      - Builds a lightweight HTML report with:
            * Risk summary
            * Counts per risk category
            * Top processes by risk score
            * Top "network talkers" (most outbound / most listening)
            * A summary of script configuration (trusted apps, role mappings)

    SAFETY:
      - NEVER kills processes.
      - NEVER touches firewall rules.
      - NEVER edits the registry.
      - DOES NOT require internet access.
      - Entirely read-only.

.PARAMETER OutputDirectory
    Where to write reports. Default = "SecurityReports" subfolder of the current directory.

.NOTES
    Version: 1.7
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = "$(Join-Path -Path (Get-Location) -ChildPath 'SecurityReports')"
)

# =========================
#  CONFIGURATION
# =========================
# Central place where you can tweak how the script interprets certain processes.
# Names are normalized to lowercase before matching.

$Config = @{
    # Tools you trust but know are high-attack-surface (remote access / VPN).
    TrustedHighSurfaceProcesses = @(
        'rustdesk',
        'wireguard',
        'wg',
        'tailscale'
    )

    # Browsers (used for LikelyRole + High attack surface heuristic).
    BrowserProcesses = @(
        'chrome',
        'firefox',
        'msedge',
        'iexplore',
        'brave',
        'opera',
        'vivaldi'
    )

    # Remote desktop or remote control.
    RemoteAccessProcesses = @(
        'rustdesk',
        'teamviewer',
        'anydesk',
        'logmein',
        'mstsc',
        'vnc',
        'rdp'
    )

    # Cloud file sync clients.
    CloudSyncProcesses = @(
        'onedrive',
        'dropbox',
        'googledrive',
        'gdrive',
        'megasync',
        'nextcloud'
    )

    # Chat / collaboration / calling tools.
    ChatCollabProcesses = @(
        'discord',
        'slack',
        'teams',
        'zoom',
        'skype',
        'webex',
        'telegram',
        'signal'
    )

    # Core Windows system processes (treated as IsWindowsComponent even if path is weird).
    CoreSystemProcesses = @(
        'system',
        'smss',
        'csrss',
        'wininit',
        'services',
        'lsass',
        'svchost'
    )
}

# =========================
#  GLOBAL STATE & BASICS
# =========================

$Script:RunTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$Script:LogFile      = Join-Path -Path $OutputDirectory -ChildPath "RunLog-$($Script:RunTimestamp).txt"
$Script:DeepDiveFile = Join-Path -Path $OutputDirectory -ChildPath "DeepDive-$($Script:RunTimestamp).txt"
$Script:HtmlReport   = Join-Path -Path $OutputDirectory -ChildPath "Report-$($Script:RunTimestamp).html"

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','DEBUG')]
        [string]$Level = 'INFO'
    )

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'WARN'    { Write-Host $line -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
        'DEBUG'   { Write-Host $line -ForegroundColor DarkGray }
        default   { Write-Host $line }
    }

    try {
        Add-Content -Path $Script:LogFile -Value $line
    }
    catch {
        Write-Host "[LOG-FAIL] $line" -ForegroundColor Red
    }
}

function Save-Log {
    Write-Log "Log file saved to: $Script:LogFile" -Level SUCCESS
}

# =========================
#  ENVIRONMENT & SAFETY
# =========================

function Test-Elevation {
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal       = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    }
    catch {
        Write-Log "Failed to determine elevation status: $($_.Exception.Message)" -Level WARN
        return $false
    }
}

$Script:IsElevated = Test-Elevation

if ($Script:IsElevated) {
    Write-Log "PowerShell session is running with administrative privileges." -Level SUCCESS
}
else {
    Write-Log "PowerShell session is NOT elevated. Some data (system processes, services, connections) may be incomplete." -Level WARN
}

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    Write-Log "Machine: $($cs.Name) | OS: $($os.Caption) | Version: $($os.Version) | Build: $($os.BuildNumber)" -Level INFO
}
catch {
    Write-Log "Failed to collect OS/computer details: $($_.Exception.Message)" -Level WARN
}

# =========================
#  FILE & SIGNATURE HELPERS
# =========================

function Get-FileHashSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )
    try {
        if (-not [string]::IsNullOrWhiteSpace($Path) -and (Test-Path -LiteralPath $Path)) {
            return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash
        }
        else {
            return $null
        }
    }
    catch {
        return $null
    }
}

function Get-SignerInfo {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    $result = [PSCustomObject]@{
        IsSigned = $false
        Subject  = $null
        Issuer   = $null
        Status   = "Unknown"
    }

    try {
        if (-not [string]::IsNullOrWhiteSpace($Path) -and (Test-Path -LiteralPath $Path)) {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop

            $result.IsSigned = ($sig.Status -ne 'NotSigned')

            if ($sig.SignerCertificate) {
                $result.Subject = $sig.SignerCertificate.Subject
                $result.Issuer  = $sig.SignerCertificate.Issuer
            }

            $result.Status = $sig.Status.ToString()
        }
        else {
            $result.Status = "PathNotFound"
        }
    }
    catch {
        $result.Status = "Error: $($_.Exception.Message)"
    }

    return $result
}

function Test-IsWindowsComponent {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    $normalized = $Path.ToLower()

    $windowsRoots = @(
        "$env:SystemRoot".ToLower(),
        (Join-Path $env:SystemRoot "System32").ToLower(),
        (Join-Path $env:SystemRoot "SysWOW64").ToLower(),
        (Join-Path $env:SystemRoot "WinSxS").ToLower()
    )

    foreach ($root in $windowsRoots) {
        if ($normalized.StartsWith($root)) {
            return $true
        }
    }

    return $false
}

# =========================
#  ARCHITECTURE HELPER
# =========================

function Get-ProcessArchitecture {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process
    )

    if (-not [Environment]::Is64BitOperatingSystem) {
        return "32-bit"
    }

    try {
        $isWow64 = $false

        $signature = @"
using System;
using System.Runtime.InteropServices;
public class Wow64Helper {
    [DllImport("kernel32.dll", SetLastError=true, CallingConvention=CallingConvention.Winapi)]
    public static extern bool IsWow64Process(IntPtr processHandle, out bool wow64Process);
}
"@
        if (-not ("Wow64Helper" -as [type])) {
            Add-Type $signature -ErrorAction Stop
        }

        $handle = $Process.Handle
        $null   = [Wow64Helper]::IsWow64Process($handle, [ref]$isWow64)

        if ($isWow64) { return "32-bit (WOW64)" }
        else          { return "64-bit" }
    }
    catch {
        return "Unknown"
    }
}

# =========================
#  IP HELPER
# =========================

function Test-IsPrivateIP {
    param(
        [Parameter(Mandatory = $true)][string]$IPAddress
    )

    try {
        if ([string]::IsNullOrWhiteSpace($IPAddress)) {
            return $false
        }

        $ip = [System.Net.IPAddress]::Parse($IPAddress)
        $bytes = $ip.GetAddressBytes()

        if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            if ($bytes[0] -eq 10) { return $true }
            if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $true }
            if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $true }
            if ($bytes[0] -eq 127) { return $true }
            return $false
        }

        if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            $b0 = $bytes[0]
            $b1 = $bytes[1]

            if (($b0 -band 0xFE) -eq 0xFC) { return $true } # fc00::/7
            if ($b0 -eq 0xFE -and ($b1 -band 0xC0) -eq 0x80) { return $true } # fe80::/10

            return $false
        }

        return $false
    }
    catch {
        return $false
    }
}

# =========================
#  PROCESS INVENTORY
# =========================

function Get-ProcessInventory {
    Write-Log "Collecting process inventory..." -Level INFO

    $processInventory = @()

    try {
        $processes = Get-Process -ErrorAction Stop | Sort-Object -Property Id
    }
    catch {
        Write-Log "Failed to enumerate processes: $($_.Exception.Message)" -Level ERROR
        return @()
    }

    foreach ($p in $processes) {
        try {
            $path        = $null
            $description = $null
            $company     = $null
            $product     = $null
            $startTime   = $null
            $userName    = $null

            try {
                $path = $p.Path
            }
            catch {
                $path = $null
            }

            if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path)) {
                try {
                    $fileVersionInfo = (Get-Item -LiteralPath $path).VersionInfo
                    $description     = $fileVersionInfo.FileDescription
                    $company         = $fileVersionInfo.CompanyName
                    $product         = $fileVersionInfo.ProductName
                }
                catch {
                    $description = $null
                    $company     = $null
                    $product     = $null
                }
            }

            try {
                $startTime = $p.StartTime
            }
            catch {
                $startTime = $null
            }

            try {
                $procCim = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction Stop
                $owner   = $procCim | Invoke-CimMethod -MethodName GetOwner
                if ($owner -and $owner.User) {
                    $userName = "$($owner.Domain)\$($owner.User)"
                }
            }
            catch {
                $userName = $null
            }

            $hash       = if ($path) { Get-FileHashSafe -Path $path } else { $null }
            $signerInfo = if ($path) { Get-SignerInfo    -Path $path } else { $null }

            $isWindowsComponent = $false
            if ($path) {
                $isWindowsComponent = Test-IsWindowsComponent -Path $path
            }

            $arch = Get-ProcessArchitecture -Process $p

            $processInventory += [PSCustomObject]@{
                ProcessName               = $p.ProcessName
                PID                       = $p.Id
                Path                      = $path
                Product                   = $product
                Description               = $description
                Company                   = $company
                FileHashSHA256            = $hash
                IsSigned                  = $signerInfo.IsSigned
                SignatureStatus           = $signerInfo.Status
                SignerSubject             = $signerInfo.Subject
                SignerIssuer              = $signerInfo.Issuer
                IsWindowsComponent        = $isWindowsComponent
                Architecture              = $arch
                StartTime                 = $startTime
                UserName                  = $userName

                HasNetworkConnections     = $false
                LocalPorts                = $null
                RemoteIPs                 = $null
                OutboundConnectionCount   = 0
                InboundListeningCount     = 0

                AttackSurface             = "Unknown"
                DataExfiltrationPotential = "Unknown"
                RiskScore                 = 0
                RiskCategory              = "Unknown"
                RiskReasons               = "Not yet assessed"
                LikelyRole                = "Unknown - manual review required."
            }
        }
        catch {
            Write-Log "Failed to inspect process ID $($p.Id) ($($p.ProcessName)): $($_.Exception.Message)" -Level WARN
        }
    }

    Write-Log "Collected $($processInventory.Count) processes." -Level SUCCESS
    return $processInventory
}

# =========================
#  NETWORK CORRELATION
# =========================

function Get-NetworkMap {
    Write-Log "Building network activity map (PID -> ports/IPs)..." -Level INFO

    $networkData = @{}

    function Get-OrCreate-NetworkInfo([int]$procId) {
        if (-not $networkData.ContainsKey($procId)) {
            $networkData[$procId] = @{
                LocalPorts  = New-Object System.Collections.Generic.List[int]
                RemoteIPs   = New-Object System.Collections.Generic.List[string]
                ListenPorts = New-Object System.Collections.Generic.List[int]
            }
        }
        return $networkData[$procId]
    }

    $usedFallback = $false

    try {
        $tcpConnections = $null
        $udpEndpoints   = $null

        if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            $tcpConnections = Get-NetTCPConnection -ErrorAction Stop
        }

        if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
            $udpEndpoints = Get-NetUDPEndpoint -ErrorAction Stop
        }

        $tcpCount = @($tcpConnections).Count
        $udpCount = @($udpEndpoints).Count

        Write-Log "NetTCPIP cmdlets returned TCP=$tcpCount rows, UDP=$udpCount rows." -Level INFO

        if ($tcpCount -gt 0 -or $udpCount -gt 0) {
            Write-Log "Using Get-NetTCPConnection / Get-NetUDPEndpoint for network correlation." -Level SUCCESS

            foreach ($conn in $tcpConnections) {
                $procId = $conn.OwningProcess
                if (-not $procId -or $procId -eq 0) { continue }

                $info = Get-OrCreate-NetworkInfo -procId $procId

                if ($conn.LocalPort -gt 0) {
                    [void]$info.LocalPorts.Add([int]$conn.LocalPort)
                }

                if ($conn.State -eq 'Listen' -and $conn.LocalPort -gt 0) {
                    [void]$info.ListenPorts.Add([int]$conn.LocalPort)
                }

                if ($conn.RemoteAddress -and
                    $conn.RemoteAddress -ne '0.0.0.0' -and
                    $conn.RemoteAddress -ne '::') {

                    [void]$info.RemoteIPs.Add($conn.RemoteAddress)
                }
            }

            foreach ($udp in $udpEndpoints) {
                $procId = $udp.OwningProcess
                if (-not $procId -or $procId -eq 0) { continue }

                $info = Get-OrCreate-NetworkInfo -procId $procId

                if ($udp.LocalPort -gt 0) {
                    [void]$info.LocalPorts.Add([int]$udp.LocalPort)
                    [void]$info.ListenPorts.Add([int]$udp.LocalPort)
                }
            }
        }
        else {
            Write-Log "NetTCPIP cmdlets returned zero rows; preparing to fall back to netstat." -Level WARN
            $usedFallback = $true
            throw "Empty NetTCPIP results"
        }
    }
    catch {
        if (-not $usedFallback) {
            Write-Log "Error using NetTCPIP cmdlets: $($_.Exception.Message). Falling back to netstat." -Level WARN
        }
        $usedFallback = $true

        try {
            $netstatOutput = netstat -ano

            foreach ($line in $netstatOutput) {
                if ($line -match '^\s*(TCP|UDP)\s+(\S+):(\d+)\s+(\S+):(\d+|\*)\s+\S*\s+(\d+)$') {
                    $protocol   = $matches[1]
                    $localAddr  = $matches[2]
                    $localPort  = [int]$matches[3]
                    $remoteAddr = $matches[4]
                    $procId     = [int]$matches[6]

                    if ($procId -eq 0) { continue }

                    $info = Get-OrCreate-NetworkInfo -procId $procId

                    if ($localPort -gt 0) {
                        [void]$info.LocalPorts.Add($localPort)
                    }

                    if ($remoteAddr -and
                        $remoteAddr -ne '0.0.0.0' -and
                        $remoteAddr -ne '::'       -and
                        $remoteAddr -ne '*') {

                        [void]$info.RemoteIPs.Add($remoteAddr)
                    }
                }
            }

            Write-Log "Parsed netstat output for network correlation." -Level SUCCESS
        }
        catch {
            Write-Log "Failed to parse netstat output: $($_.Exception.Message)" -Level ERROR
        }
    }

    $pidCount = $networkData.Keys.Count
    Write-Log "Network map built for $pidCount PIDs." -Level INFO

    return $networkData
}

function Merge-NetworkMapIntoInventory {
    param(
        [Parameter(Mandatory = $true)][array]$ProcessInventory,
        [Parameter(Mandatory = $true)][hashtable]$NetworkMap
    )

    Write-Log "Merging network map into process inventory..." -Level INFO

    $matched = 0

    foreach ($process in $ProcessInventory) {
        $procId = $process.PID

        if ($NetworkMap.ContainsKey($procId)) {
            $info = $NetworkMap[$procId]

            $uniqueLocalPorts  = $info.LocalPorts  | Select-Object -Unique | Sort-Object
            $uniqueRemoteIPs   = $info.RemoteIPs   | Select-Object -Unique | Sort-Object
            $uniqueListenPorts = $info.ListenPorts | Select-Object -Unique | Sort-Object

            $process.HasNetworkConnections   = $true
            $process.LocalPorts              = ($uniqueLocalPorts  -join ", ")
            $process.RemoteIPs               = ($uniqueRemoteIPs   -join ", ")
            $process.OutboundConnectionCount = $uniqueRemoteIPs.Count
            $process.InboundListeningCount   = $uniqueListenPorts.Count

            $matched++
        }
    }

    Write-Log "Network correlation complete: $matched processes have active connections/listening sockets." -Level SUCCESS
}

# =========================
#  ROLE HINT HELPER
# =========================

function Get-LikelyRole {
    param(
        [Parameter(Mandatory = $true)][string]$ProcessName,
        [string]$Company,
        [string]$Description
    )

    $name = ($ProcessName | Out-String).Trim().ToLower()
    $comp = ($Company     | Out-String).Trim().ToLower()
    $desc = ($Description | Out-String).Trim().ToLower()

    if ($Config.BrowserProcesses -contains $name) {
        return "Web browser"
    }
    if ($Config.RemoteAccessProcesses -contains $name) {
        return "Remote desktop / remote control client/agent"
    }
    if ($Config.CloudSyncProcesses -contains $name) {
        return "Cloud file sync client"
    }
    if ($Config.ChatCollabProcesses -contains $name) {
        return "Chat / collaboration / calling client"
    }

    if ($name -eq 'explorer') {
        return "Windows shell / file explorer"
    }
    if ($name -eq 'rustdesk') {
        return "RustDesk remote desktop client/agent"
    }
    if ($name -eq 'mstsc') {
        return "RDP client (mstsc.exe)"
    }
    if ($name -eq 'msmpeng') {
        return "Windows Defender antimalware engine"
    }
    if ($name -eq 'svchost') {
        return "Windows service host (multiple system services)"
    }
    if ($name -eq 'lockapp') {
        return "Windows lock screen UI"
    }
    if ($name -eq 'searchapp') {
        return "Windows search / Start menu search UI"
    }
    if ($desc -like '*windows audio*') {
        return "Windows audio service / sound subsystem"
    }
    if ($desc -like '*print spooler*') {
        return "Windows print spooler service"
    }
    if ($desc -like '*time service*') {
        return "Windows time synchronization service"
    }
    if ($desc -like '*push notification*') {
        return "Windows push notification service"
    }

    return "Unknown - manual review required."
}

# =========================
#  RISK ASSESSMENT
# =========================

function Add-RiskAssessment {
    param([Parameter(Mandatory = $true)][array]$ProcessInventory)

    Write-Log "Performing risk assessment..." -Level INFO

    foreach ($process in $ProcessInventory) {
        $name    = (($process.ProcessName | Out-String).Trim()).ToLower()
        $path    = (($process.Path        | Out-String).Trim()).ToLower()
        $company = (($process.Company     | Out-String).Trim()).ToLower()
        $desc    = (($process.Description | Out-String).Trim()).ToLower()

        $hasNetwork   = [bool]$process.HasNetworkConnections
        $remoteIPText = [string]$process.RemoteIPs
        $remoteIPs    = @()
        if (-not [string]::IsNullOrWhiteSpace($remoteIPText)) {
            $remoteIPs = $remoteIPText -split '\s*,\s*'
        }

        $isWindowsComponent = [bool]$process.IsWindowsComponent

        $runsAsUser = $false
        if ($process.UserName -and $process.UserName -notmatch '^(NT AUTHORITY|NT SERVICE|SYSTEM|LOCAL SERVICE|NETWORK SERVICE)') {
            $runsAsUser = $true
        }

        # Ensure core system processes are always treated as Windows components
        if ($Config.CoreSystemProcesses -contains $name) {
            $isWindowsComponent = $true
        }
        elseif (-not $isWindowsComponent -and [string]::IsNullOrWhiteSpace($path)) {
            if ($process.UserName -match '^(NT AUTHORITY|NT SERVICE|SYSTEM|LOCAL SERVICE|NETWORK SERVICE)') {
                if ($name -match '^(system|csrss|smss|winlogon|services|lsass|svchost)$') {
                    $isWindowsComponent = $true
                }
            }
        }
        $process.IsWindowsComponent = $isWindowsComponent

        $isBrowser       = $Config.BrowserProcesses       -contains $name
        $isRemoteAccess  = $Config.RemoteAccessProcesses  -contains $name
        $isCloudSync     = $Config.CloudSyncProcesses     -contains $name
        $isChatCollab    = $Config.ChatCollabProcesses    -contains $name
        $isTrustedHigh   = $Config.TrustedHighSurfaceProcesses -contains $name

        # 1) ATTACK SURFACE
        $attackSurface = "Low"

        if ($isBrowser -or $isRemoteAccess -or
            $name -match 'sqlservr|mysqld|postgres|oracle|redis|mongodb'      -or
            $name -match 'bittorrent|utorrent|qbittorrent|transmission'       -or
            (($hasNetwork) -and (-not $isWindowsComponent))) {

            $attackSurface = "High"
        }
        elseif ($isCloudSync -or $isChatCollab -or
                (($hasNetwork) -and $isWindowsComponent)) {

            $attackSurface = "Medium"
        }
        else {
            $attackSurface = "Low"
        }

        # 2) DATA EXFIL FLAG
        $dataExfil = "Unknown"
        $hasInternetRemote = $false

        foreach ($ip in $remoteIPs) {
            if ([string]::IsNullOrWhiteSpace($ip)) { continue }
            if (-not (Test-IsPrivateIP -IPAddress $ip)) {
                $hasInternetRemote = $true
                break
            }
        }

        if ($hasNetwork -and $remoteIPs.Count -gt 0) {
            if ($hasInternetRemote) {
                $dataExfil = "Yes"
            }
            else {
                $dataExfil = "No"
            }
        }
        elseif (-not $hasNetwork) {
            $dataExfil = "No"
        }
        else {
            $dataExfil = "Unknown"
        }

        # 3) NUMERIC RISK SCORE
        $score   = 0
        $reasons = @()

        if (-not $isWindowsComponent) {
            $score += 10
            $reasons += "Non-Windows component (third-party or custom software, based on path and core process list)."
        }

        if (-not $process.IsSigned -or $process.SignatureStatus -notin @('Valid','Trusted')) {
            $score += 15
            $reasons += "Not signed or invalid/untrusted digital signature."
        }

        switch ($attackSurface) {
            'High'   { $score += 25; $reasons += "High attack surface (network-heavy role, browser, or remote access tool)."; }
            'Medium' { $score += 10; $reasons += "Medium attack surface (network-aware or cloud/communication client)."; }
        }

        if ($hasNetwork -and $remoteIPs.Count -gt 0) {
            $score += 10
            $reasons += "Has active remote network connections."
        }
        elseif ($hasNetwork) {
            $score += 5
            $reasons += "Has local network activity (listening sockets)."
        }

        if ($process.OutboundConnectionCount -gt 10) {
            $score += 10
            $reasons += "High number of unique outbound remote IPs."
        }

        if ($process.InboundListeningCount -gt 5) {
            $score += 10
            $reasons += "High number of listening ports."
        }

        if ($dataExfil -eq 'Yes') {
            $score += 15
            $reasons += "Potential to send data to internet endpoints (non-private IPs detected)."
        }

        if ($runsAsUser) {
            $score += 5
            $reasons += "Runs under a regular or domain user account (user-context compromise vector)."
        }

        if ($isWindowsComponent -and $Config.CoreSystemProcesses -contains $name) {
            $score -= 5
            $reasons += "Core Windows process (powerful but expected; see core process list in config)."
        }

        if ($isTrustedHigh) {
            $score -= 5
            $reasons += "Configured as trusted high-surface tool (see TrustedHighSurfaceProcesses in script config)."
        }

        $score = [math]::Max(0, [math]::Min(100, $score))

        $category = if ($score -ge 60) {
            "High"
        }
        elseif ($score -ge 30) {
            "Medium"
        }
        else {
            "Low"
        }

        if ($reasons.Count -eq 0) {
            $reasons = @("Unknown - manual review required.")
        }

        $process.AttackSurface             = $attackSurface
        $process.DataExfiltrationPotential = $dataExfil
        $process.RiskScore                 = $score
        $process.RiskCategory              = $category
        $process.RiskReasons               = ($reasons -join " ")
        $process.LikelyRole                = Get-LikelyRole -ProcessName $process.ProcessName -Company $process.Company -Description $process.Description
    }

    Write-Log "Risk assessment complete." -Level SUCCESS
}

# =========================
#  EXPORT RESULTS (CSV/JSON/DEE DIVE/HTML)
# =========================

function Export-Results {
    param(
        [Parameter(Mandatory = $true)][array]$ProcessInventory,
        [Parameter(Mandatory = $true)][string]$OutputDirectory
    )

    $timestamp     = $Script:RunTimestamp
    $csvPath       = Join-Path -Path $OutputDirectory -ChildPath "Inventory-$timestamp.csv"
    $jsonPath      = Join-Path -Path $OutputDirectory -ChildPath "Inventory-$timestamp.json"
    $deepDivePath  = $Script:DeepDiveFile
    $htmlReport    = $Script:HtmlReport

    # ----- CSV -----
    try {
        $ProcessInventory |
            Sort-Object -Property RiskScore -Descending |
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

        Write-Log "CSV inventory exported to: $csvPath" -Level SUCCESS
    }
    catch {
        Write-Log "Failed to export CSV: $($_.Exception.Message)" -Level ERROR
    }

    # ----- JSON -----
    try {
        $ProcessInventory |
            Sort-Object -Property RiskScore -Descending |
            ConvertTo-Json -Depth 6 |
            Out-File -FilePath $jsonPath -Encoding UTF8

        Write-Log "JSON inventory exported to: $jsonPath" -Level SUCCESS
    }
    catch {
        Write-Log "Failed to export JSON: $($_.Exception.Message)" -Level ERROR
    }

    # ----- Deep Dive TXT -----
    try {
        Write-Log "Building deep dive report for interesting processes..." -Level INFO

        $interesting = $ProcessInventory | Where-Object {
            $_.RiskCategory -in @('High','Medium') -or $_.HasNetworkConnections
        }

        $lines = @()
        $lines += "Deep Dive Report - Inspect-WindowsAttackSurface.ps1 v1.7"
        $lines += "Run timestamp : $timestamp"
        $lines += "Machine       : $env:COMPUTERNAME"
        $lines += "Total processes: $($ProcessInventory.Count)"
        $lines += "Interesting processes (High/Medium risk OR network-active): $($interesting.Count)"
        $lines += ""
        $lines += "Legend:"
        $lines += "  - AttackSurface: High/Medium/Low = how exposed this process is to input from the network / users."
        $lines += "  - DataExfiltrationPotential: Yes = currently talking to non-private IPs; No = only local/private; Unknown = insufficient data."
        $lines += "  - RiskScore: 0-100 numeric score combining signature, role, network behavior, and account."
        $lines += "  - RiskCategory: High (>=60), Medium (30-59), Low (<30)."
        $lines += ""
        $lines += "Config summary (see script header to adjust):"
        $lines += "  - TrustedHighSurfaceProcesses: $($Config.TrustedHighSurfaceProcesses -join ', ')"
        $lines += "  - CoreSystemProcesses: $($Config.CoreSystemProcesses -join ', ')"
        $lines += ""
        $lines += "==============================================================================="

        # Top talkers / top risky
        $topByRisk = $interesting |
            Sort-Object -Property RiskScore -Descending |
            Select-Object -First 10

        $topOutbound = $ProcessInventory |
            Where-Object { $_.OutboundConnectionCount -gt 0 } |
            Sort-Object -Property OutboundConnectionCount -Descending |
            Select-Object -First 10

        $topListening = $ProcessInventory |
            Where-Object { $_.InboundListeningCount -gt 0 } |
            Sort-Object -Property InboundListeningCount -Descending |
            Select-Object -First 10

        $lines += ""
        $lines += "Top 10 by RiskScore:"
        foreach ($p in $topByRisk) {
            $lines += ("  PID {0,-5} Score {1,-3} Category {2,-6} Name {3} ({4})" -f $p.PID, $p.RiskScore, $p.RiskCategory, $p.ProcessName, $p.LikelyRole)
        }

        $lines += ""
        $lines += "Top 10 by OutboundConnectionCount:"
        foreach ($p in $topOutbound) {
            $lines += ("  PID {0,-5} Outbound {1,-3} Name {2} ({3})" -f $p.PID, $p.OutboundConnectionCount, $p.ProcessName, $p.LikelyRole)
        }

        $lines += ""
        $lines += "Top 10 by InboundListeningCount:"
        foreach ($p in $topListening) {
            $lines += ("  PID {0,-5} ListeningPorts {1,-3} Name {2} ({3})" -f $p.PID, $p.InboundListeningCount, $p.ProcessName, $p.LikelyRole)
        }

        $lines += ""
        $lines += "==============================================================================="

        foreach ($p in ($interesting | Sort-Object -Property RiskScore -Descending)) {
            $lines += ""
            $lines += "----------------------------------------"
            $lines += "PID: $($p.PID)"
            $lines += "ProcessName: $($p.ProcessName)"
            $lines += "UserName: $($p.UserName)"
            $lines += "LikelyRole: $($p.LikelyRole)"
            $lines += "AttackSurface: $($p.AttackSurface)"
            $lines += "DataExfiltrationPotential: $($p.DataExfiltrationPotential)"
            $lines += "RiskScore: $($p.RiskScore) ($($p.RiskCategory))"
            $lines += "IsWindowsComponent: $($p.IsWindowsComponent)"
            $lines += "Path: $($p.Path)"
            $lines += "Company: $($p.Company)"
            $lines += "Description: $($p.Description)"
            $lines += "StartTime: $($p.StartTime)"
            $lines += ""
            $lines += "--- Network ---"
            $lines += "HasNetworkConnections: $($p.HasNetworkConnections)"
            $lines += "LocalPorts: $($p.LocalPorts)"
            $lines += "RemoteIPs: $($p.RemoteIPs)"
            $lines += "OutboundConnectionCount: $($p.OutboundConnectionCount)"
            $lines += "InboundListeningCount: $($p.InboundListeningCount)"

            if ($p.ProcessName -eq 'svchost') {
                try {
                    $svc = Get-CimInstance Win32_Service -Filter "ProcessId = $($p.PID)" -ErrorAction Stop
                    if ($svc) {
                        $lines += ""
                        $lines += "--- Services hosted in this svchost ---"
                        foreach ($s in $svc) {
                            $lines += "ServiceName: $($s.Name)"
                            $lines += "  DisplayName: $($s.DisplayName)"
                            $lines += "  State: $($s.State)"
                            $lines += "  StartMode: $($s.StartMode)"
                        }
                    }
                }
                catch {
                    $lines += ""
                    $lines += "--- Services hosted in this svchost ---"
                    $lines += "Unable to enumerate services for PID $($p.PID): $($_.Exception.Message)"
                }
            }

            $lines += ""
            $lines += "--- RiskReasons ---"
            $lines += $p.RiskReasons
            $lines += ""
            $lines += "----------------------------------------"
        }

        $lines | Out-File -FilePath $deepDivePath -Encoding UTF8
        Write-Log "Deep dive report exported to: $deepDivePath" -Level SUCCESS
    }
    catch {
        Write-Log "Failed to build deep dive report: $($_.Exception.Message)" -Level ERROR
    }

    # ----- HTML VISUAL REPORT -----
    try {
        Write-Log "Building HTML visual report..." -Level INFO

        $highRisk   = @($ProcessInventory | Where-Object { $_.RiskCategory -eq 'High' }).Count
        $mediumRisk = @($ProcessInventory | Where-Object { $_.RiskCategory -eq 'Medium' }).Count
        $lowRisk    = @($ProcessInventory | Where-Object { $_.RiskCategory -eq 'Low' }).Count

        $maxCount = ($highRisk, $mediumRisk, $lowRisk | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum)
        $maxCount = [math]::Max($maxCount, 1) # avoid divide-by-zero
        $maxBarWidth = 300

        function Get-BarWidth([int]$count, [int]$max, [int]$maxWidth) {
            if ($max -le 0) { return 0 }
            return [int]([double]$count / [double]$max * [double]$maxWidth)
        }

        $highWidth   = Get-BarWidth -count $highRisk   -max $maxCount -maxWidth $maxBarWidth
        $medWidth    = Get-BarWidth -count $mediumRisk -max $maxCount -maxWidth $maxBarWidth
        $lowWidth    = Get-BarWidth -count $lowRisk    -max $maxCount -maxWidth $maxBarWidth

        $topRiskHtml = ""
        $topByRisk = $ProcessInventory |
            Sort-Object -Property RiskScore -Descending |
            Select-Object -First 10

        foreach ($p in $topByRisk) {
            $barWidth = [int]($p.RiskScore * 3) # 0–100 => up to 300px
            $topRiskHtml += @"
<tr>
  <td>$($p.ProcessName)</td>
  <td>$($p.PID)</td>
  <td>$($p.LikelyRole)</td>
  <td>$($p.RiskCategory)</td>
  <td>
    <div class="bar-container">
      <div class="bar" style="width: ${barWidth}px;"></div>
      <span class="bar-label">$($p.RiskScore)</span>
    </div>
  </td>
</tr>
"@
        }

        $topOutboundHtml = ""
        $topOutbound = $ProcessInventory |
            Where-Object { $_.OutboundConnectionCount -gt 0 } |
            Sort-Object -Property OutboundConnectionCount -Descending |
            Select-Object -First 10

        foreach ($p in $topOutbound) {
            $barWidth = [int]([math]::Min($p.OutboundConnectionCount,50) * 6) # cap visually
            $topOutboundHtml += @"
<tr>
  <td>$($p.ProcessName)</td>
  <td>$($p.PID)</td>
  <td>$($p.LikelyRole)</td>
  <td>
    <div class="bar-container">
      <div class="bar blue" style="width: ${barWidth}px;"></div>
      <span class="bar-label">$($p.OutboundConnectionCount)</span>
    </div>
  </td>
</tr>
"@
        }

        $topListeningHtml = ""
        $topListening = $ProcessInventory |
            Where-Object { $_.InboundListeningCount -gt 0 } |
            Sort-Object -Property InboundListeningCount -Descending |
            Select-Object -First 10

        foreach ($p in $topListening) {
            $barWidth = [int]([math]::Min($p.InboundListeningCount,50) * 6)
            $topListeningHtml += @"
<tr>
  <td>$($p.ProcessName)</td>
  <td>$($p.PID)</td>
  <td>$($p.LikelyRole)</td>
  <td>
    <div class="bar-container">
      <div class="bar green" style="width: ${barWidth}px;"></div>
      <span class="bar-label">$($p.InboundListeningCount)</span>
    </div>
  </td>
</tr>
"@
        }

        # Config summary strings for HTML display
        $trustedList = [string]::Join(", ", $Config.TrustedHighSurfaceProcesses)
        $coreSysList = [string]::Join(", ", $Config.CoreSystemProcesses)
        $browserList = [string]::Join(", ", $Config.BrowserProcesses)
        $remoteList  = [string]::Join(", ", $Config.RemoteAccessProcesses)
        $syncList    = [string]::Join(", ", $Config.CloudSyncProcesses)
        $chatList    = [string]::Join(", ", $Config.ChatCollabProcesses)

        $html = @"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Windows Attack Surface Report - $env:COMPUTERNAME - $timestamp</title>
  <style>
    body {
      font-family: Segoe UI, Tahoma, Arial, sans-serif;
      margin: 20px;
      background-color: #f5f5f5;
      color: #222;
    }
    h1, h2, h3 {
      color: #222;
    }
    .card {
      background-color: #ffffff;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      padding: 16px 20px;
      margin-bottom: 20px;
    }
    .summary-grid {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
    }
    .summary-item {
      flex: 1 1 150px;
      padding: 12px;
      border-radius: 8px;
      background: #fafafa;
      border: 1px solid #e0e0e0;
    }
    .summary-item span.label {
      display: block;
      font-size: 12px;
      color: #666;
    }
    .summary-item span.value {
      display: block;
      font-size: 20px;
      font-weight: bold;
      margin-top: 4px;
    }
    .risk-bar-row {
      display: flex;
      align-items: center;
      margin: 6px 0;
    }
    .risk-bar-row .label {
      width: 70px;
      font-weight: bold;
    }
    .risk-bar-row .bar-container {
      flex: 1;
      background-color: #e0e0e0;
      border-radius: 4px;
      margin: 0 8px;
      height: 14px;
      overflow: hidden;
    }
    .risk-bar-row .bar {
      height: 100%;
      border-radius: 4px;
    }
    .risk-bar-row .bar.high   { background-color: #e53935; }
    .risk-bar-row .bar.medium { background-color: #fb8c00; }
    .risk-bar-row .bar.low    { background-color: #43a047; }
    .risk-bar-row .value {
      width: 40px;
      text-align: right;
      font-size: 12px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      font-size: 13px;
    }
    th, td {
      border: 1px solid #ddd;
      padding: 6px 8px;
      text-align: left;
    }
    th {
      background-color: #f0f0f0;
    }
    .bar-container {
      position: relative;
      background-color: #e0e0e0;
      border-radius: 4px;
      height: 14px;
      overflow: hidden;
    }
    .bar {
      height: 100%;
      border-radius: 4px;
      background-color: #e53935;
    }
    .bar.blue {
      background-color: #1e88e5;
    }
    .bar.green {
      background-color: #43a047;
    }
    .bar-label {
      position: absolute;
      top: -2px;
      left: 6px;
      font-size: 11px;
      color: #fff;
      text-shadow: 0 0 2px rgba(0,0,0,0.7);
    }
    .note {
      font-size: 12px;
      color: #555;
    }
    ul.config-list {
      font-size: 12px;
      color: #333;
      padding-left: 18px;
    }
  </style>
</head>
<body>
  <h1>Windows Attack Surface Report</h1>
  <div class="card">
    <p><strong>Machine:</strong> $env:COMPUTERNAME<br/>
       <strong>Generated:</strong> $((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))<br/>
       <strong>Run ID:</strong> $timestamp</p>
    <p class="note">
      This report is generated by Inspect-WindowsAttackSurface.ps1 (v1.7).<br/>
      It is read-only: no processes were killed, no firewall rules changed, no registry edits performed.
    </p>
  </div>

  <div class="card">
    <h2>Risk Summary</h2>
    <div class="summary-grid">
      <div class="summary-item">
        <span class="label">High Risk</span>
        <span class="value">$highRisk</span>
      </div>
      <div class="summary-item">
        <span class="label">Medium Risk</span>
        <span class="value">$mediumRisk</span>
      </div>
      <div class="summary-item">
        <span class="label">Low Risk</span>
        <span class="value">$lowRisk</span>
      </div>
      <div class="summary-item">
        <span class="label">Total Processes</span>
        <span class="value">$($ProcessInventory.Count)</span>
      </div>
    </div>

    <h3>Processes by Risk Category</h3>
    <div class="risk-bar-row">
      <span class="label">High</span>
      <div class="bar-container">
        <div class="bar high" style="width:${highWidth}px;"></div>
      </div>
      <span class="value">$highRisk</span>
    </div>
    <div class="risk-bar-row">
      <span class="label">Medium</span>
      <div class="bar-container">
        <div class="bar medium" style="width:${medWidth}px;"></div>
      </div>
      <span class="value">$mediumRisk</span>
    </div>
    <div class="risk-bar-row">
      <span class="label">Low</span>
      <div class="bar-container">
        <div class="bar low" style="width:${lowWidth}px;"></div>
      </div>
      <span class="value">$lowRisk</span>
    </div>
  </div>

  <div class="card">
    <h2>Top 10 Processes by Risk Score</h2>
    <p class="note">
      These are the most “interesting” processes from an attack-surface perspective.
      High score does NOT mean malicious; it means “worth understanding first.”
    </p>
    <table>
      <thead>
        <tr>
          <th>Process</th>
          <th>PID</th>
          <th>Likely Role</th>
          <th>Risk Category</th>
          <th>Risk Score (0–100)</th>
        </tr>
      </thead>
      <tbody>
        $topRiskHtml
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Top 10 Outbound “Talkers”</h2>
    <p class="note">
      OutboundConnectionCount = number of unique remote IPs currently associated with the process.
    </p>
    <table>
      <thead>
        <tr>
          <th>Process</th>
          <th>PID</th>
          <th>Likely Role</th>
          <th>Outbound Connections (unique IPs)</th>
        </tr>
      </thead>
      <tbody>
        $topOutboundHtml
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Top 10 Listening Processes</h2>
    <p class="note">
      InboundListeningCount = number of listening ports. These processes are waiting for inbound connections.
    </p>
    <table>
      <thead>
        <tr>
          <th>Process</th>
          <th>PID</th>
          <th>Likely Role</th>
          <th>Listening Ports</th>
        </tr>
      </thead>
      <tbody>
        $topListeningHtml
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Script Configuration Summary</h2>
    <p class="note">
      These lists come from the configuration block near the top of the PowerShell script.
      You can edit them to adjust how processes are classified (trusted tools, browsers, remote access, etc.).
    </p>
    <ul class="config-list">
      <li><strong>TrustedHighSurfaceProcesses:</strong> $trustedList</li>
      <li><strong>CoreSystemProcesses:</strong> $coreSysList</li>
      <li><strong>BrowserProcesses:</strong> $browserList</li>
      <li><strong>RemoteAccessProcesses:</strong> $remoteList</li>
      <li><strong>CloudSyncProcesses:</strong> $syncList</li>
      <li><strong>ChatCollabProcesses:</strong> $chatList</li>
    </ul>
  </div>

</body>
</html>
"@

        $html | Out-File -FilePath $htmlReport -Encoding UTF8
        Write-Log "HTML visual report exported to: $htmlReport" -Level SUCCESS
    }
    catch {
        Write-Log "Failed to build HTML report: $($_.Exception.Message)" -Level ERROR
    }
}

# =========================
#  MAIN
# =========================

function Main {
    Write-Log "=== Inspect-WindowsAttackSurface.ps1 starting (version 1.7) ===" -Level INFO

    $processInventory = Get-ProcessInventory

    if (-not $processInventory -or $processInventory.Count -eq 0) {
        Write-Log "No processes collected; aborting further analysis." -Level ERROR
        Save-Log
        return
    }

    $networkMap = Get-NetworkMap
    if ($networkMap.Count -gt 0) {
        Merge-NetworkMapIntoInventory -ProcessInventory $processInventory -NetworkMap $networkMap
    }
    else {
        Write-Log "No network map data was built (no active sockets detected or an earlier error occurred)." -Level WARN
    }

    Add-RiskAssessment -ProcessInventory $processInventory

    Export-Results -ProcessInventory $processInventory -OutputDirectory $OutputDirectory

    $highRisk   = @($processInventory | Where-Object { $_.RiskCategory -eq 'High' }).Count
    $mediumRisk = @($processInventory | Where-Object { $_.RiskCategory -eq 'Medium' }).Count
    $lowRisk    = @($processInventory | Where-Object { $_.RiskCategory -eq 'Low' }).Count

    Write-Log "Summary: High=$highRisk, Medium=$mediumRisk, Low=$lowRisk" -Level INFO
    Write-Log "Output directory: $OutputDirectory" -Level INFO
    Write-Log "=== Inspect-WindowsAttackSurface.ps1 completed ===" -Level SUCCESS

    Save-Log
}

try {
    Main
}
catch {
    Write-Log "Unhandled exception in Main: $($_.Exception.Message)" -Level ERROR
    Save-Log
}
