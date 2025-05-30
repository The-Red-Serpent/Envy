#  /$$$$$$$$                               
# | $$_____/                               
# | $$       /$$$$$$$  /$$    /$$ /$$   /$$
# | $$$$$   | $$__  $$|  $$  /$$/| $$  | $$
# | $$__/   | $$  \ $$ \  $$/$$/ | $$  | $$
# | $$      | $$  | $$  \  $$$/  | $$  | $$
# | $$$$$$$$| $$  | $$   \  $/   |  $$$$$$$
# |________/|__/  |__/    \_/     \____  $$
#                                 /$$  | $$
#                                |  $$$$$$/
#                                 \______/
# Envy - Low-Privilege PowerShell Script for System and Domain Enumeration
# Author: The_Red_Serpent


# Initialize timestamp and in-memory log
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$log = @()

# Function to add section to log and display in terminal
function Add-Section {
    param($Title, $Content)
    $log = $script:log
    $log += "`n" + "-" * 50
    $log += "`n$Title"
    $log += "`n" + "-" * 50
    $log += "`n$Content`n"
    Write-Host "`n" -NoNewline
    Write-Host ("-" * 50) -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ("-" * 50) -ForegroundColor Cyan
    Write-Host $Content
    Write-Host ""
    $script:log = $log
}

# Function to check if a command is available
function Test-Command {
    param($CommandName)
    return (Get-Command $CommandName -ErrorAction SilentlyContinue) -ne $null
}

# Function to execute command with fallbacks
function Run-Command {
    param(
        [ScriptBlock]$Command,
        [string]$Title,
        [ScriptBlock]$FallbackCommand = $null,
        [bool]$RequiresAdmin = $false,
        [string]$RequiresModule = $null
    )
    try {
        switch ($true) {
            ($RequiresModule -and -not (Test-Command $RequiresModule)) {
                if ($FallbackCommand) {
                    try {
                        $output = & $FallbackCommand 2>&1 | Out-String
                        if ($output -and $output.Trim()) {
                            Add-Section -Title $Title -Content $output
                        } else {
                            Add-Section -Title $Title -Content "Fallback command returned no output (possibly due to permissions or non-domain environment)."
                        }
                    } catch {
                        Add-Section -Title $Title -Content "Fallback command failed: $($_.Exception.Message)"
                    }
                } else {
                    Add-Section -Title $Title -Content "Command skipped: Required module ($RequiresModule) not available."
                }
                break
            }
            ($RequiresAdmin -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                if ($FallbackCommand) {
                    try {
                        $output = & $FallbackCommand 2>&1 | Out-String
                        if ($output -and $output.Trim()) {
                            Add-Section -Title $Title -Content $output
                        } else {
                            Add-Section -Title $Title -Content "Fallback command returned no output (possibly due to permissions or non-domain environment)."
                        }
                    } catch {
                        Add-Section -Title $Title -Content "Fallback command failed: $($_.Exception.Message)"
                    }
                } else {
                    Add-Section -Title $Title -Content "Command skipped: Requires elevated permissions."
                }
                break
            }
            default {
                $output = & $Command 2>&1 | Out-String
                if ($output -and $output.Trim()) {
                    Add-Section -Title $Title -Content $output
                } else {
                    if ($FallbackCommand) {
                        try {
                            $output = & $FallbackCommand 2>&1 | Out-String
                            if ($output -and $output.Trim()) {
                                Add-Section -Title $Title -Content $output
                            } else {
                                Add-Section -Title $Title -Content "Fallback command returned no output (possibly due to permissions or non-domain environment)."
                            }
                        } catch {
                            Add-Section -Title $Title -Content "Fallback command failed: $($_.Exception.Message)"
                        }
                    } else {
                        Add-Section -Title $Title -Content "No output or command failed (possibly due to permissions or non-domain environment)."
                    }
                }
            }
        }
    } catch {
        if ($FallbackCommand) {
            try {
                $output = & $FallbackCommand 2>&1 | Out-String
                if ($output -and $output.Trim()) {
                    Add-Section -Title $Title -Content $output
                } else {
                    Add-Section -Title $Title -Content "Fallback command returned no output (possibly due to permissions or non-domain environment)."
                }
            } catch {
                Add-Section -Title $Title -Content "Fallback command failed: $($_.Exception.Message)"
            }
        } else {
            Add-Section -Title $Title -Content "Error: $($_.Exception.Message) (May require elevated permissions or module)"
        }
    }
}

# Clear terminal for clean output
Clear-Host

# Display title and author
Write-Host '/$$$$$$$$                               ' -ForegroundColor Green
Write-Host '| $$_____/                               ' -ForegroundColor Green
Write-Host '| $$       /$$$$$$$  /$$    /$$ /$$   /$$' -ForegroundColor Green
Write-Host '| $$$$$   | $$__  $$|  $$  /$$/| $$  | $$' -ForegroundColor Green
Write-Host '| $$__/   | $$  \ $$ \  $$/$$/ | $$  | $$' -ForegroundColor Green
Write-Host '| $$      | $$  | $$  \  $$$/  | $$  | $$' -ForegroundColor Green
Write-Host '| $$$$$$$$| $$  | $$   \  $/   |  $$$$$$$' -ForegroundColor Green
Write-Host '|________/|__/  |__/    \_/     \____  $$' -ForegroundColor Green
Write-Host '                                /$$  | $$' -ForegroundColor Green
Write-Host '                               |  $$$$$$/' -ForegroundColor Green
Write-Host '                                \______/ ' -ForegroundColor Green

Write-Host "Author: The_Red_Serpent" -ForegroundColor Red
Write-Host "Credits: Yokai Whispers" -ForegroundColor Red
Write-Host "Timestamp: $timestamp`n" -ForegroundColor Green

# Start enumeration
Add-Section -Title "Script Started" -Content "Low-Privilege Enumeration started at $timestamp"

# System Information (Enhanced with Kernel Version and Architecture)
Run-Command -Command { 
    $os = Get-CimInstance Win32_OperatingSystem
    [PSCustomObject]@{
        ComputerName = $os.CSName
        OSCaption = $os.Caption
        KernelVersion = $os.BuildNumber
        Architecture = $os.OSArchitecture
        TotalPhysicalMemoryMB = [math]::Round($os.TotalVisibleMemorySize/1KB,0)
    } | Format-Table -AutoSize | Out-String 
} -Title "System Information"

# System Uptime
Run-Command -Command { 
    $os = Get-CimInstance Win32_OperatingSystem
    $uptime = (Get-Date) - $os.LastBootUpTime
    [PSCustomObject]@{
        LastBootTime = $os.LastBootUpTime
        Uptime = "$($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"
    } | Format-Table -AutoSize | Out-String 
} -Title "System Uptime"

# Hotfixes Applied
Run-Command -Command { 
    Get-CimInstance Win32_QuickFixEngineering | Select-Object HotFixID, Description, InstalledOn | Sort-Object InstalledOn -Descending | Format-Table -AutoSize | Out-String 
} -Title "Hotfixes Applied"

# Windows Defender Status
function Get-WinDefenderStatus {
    $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    $defenderStatus = if ($defenderService) { $defenderService.Status } else { "Not Installed or Disabled" }
    $realtimeProtection = Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RealTimeProtectionEnabled
    [PSCustomObject]@{
        DefenderServiceStatus = $defenderStatus
        RealTimeProtection = if ($realtimeProtection -ne $null) { $realtimeProtection } else { "Unknown" }
    } | Format-Table -AutoSize | Out-String
}
Run-Command -Command { Get-WinDefenderStatus } `
            -Title "Windows Defender Status" `
            -FallbackCommand { sc query WinDefend | Out-String }

# Installed Applications
Run-Command -Command { 
    Get-CimInstance Win32_Product | Select-Object Name, Version, InstallDate | Sort-Object Name | Format-Table -AutoSize | Out-String 
} -Title "Installed Applications" `
    -FallbackCommand { Get-WmiObject Win32_Product | Select-Object Name, Version, InstallDate | Sort-Object Name | Format-Table -AutoSize | Out-String }

# Microsoft Office Presence
function Get-OfficePresence {
    try {
        # Check Win32_Product for Office applications
        $officeApps = Get-CimInstance Win32_Product | Where-Object { 
            $_.Name -like "*Microsoft Office*" -or 
            $_.Name -like "*Microsoft 365*" -or 
            $_.Name -like "*Word*" -or 
            $_.Name -like "*Excel*" -or 
            $_.Name -like "*PowerPoint*" -or 
            $_.Name -like "*Outlook*" -or 
            $_.Name -like "*Access*" 
        } | Select-Object Name, Version, InstallDate
        # Check registry for Office installations
        $regPaths = @(
            "HKLM:\Software\Microsoft\Office",
            "HKLM:\Software\WOW6432Node\Microsoft\Office"
        )
        $regOffice = $regPaths | Where-Object { Test-Path $_ } | ForEach-Object { 
            Get-Item $_ | Select-Object @{Name='Path';Expression={$_}}, @{Name='Version';Expression={(Get-ItemProperty $_).Version}}
        }
        if ($officeApps -or $regOffice) {
            $result = "Microsoft Office Components Detected:`n"
            if ($officeApps) {
                $result += ($officeApps | Format-Table -AutoSize | Out-String)
            }
            if ($regOffice) {
                $result += "Registry Entries:`n" + ($regOffice | Format-Table -AutoSize | Out-String)
            }
            return $result
        } else {
            return "Microsoft Office not detected."
        }
    } catch {
        return "Error checking Microsoft Office presence: $($_.Exception.Message).`nFallback registry check:`n" + ($regPaths | Where-Object { Test-Path $_ } | ForEach-Object { Get-Item $_ | Select-Object @{Name='Path';Expression={$_}}, @{Name='Version';Expression={(Get-ItemProperty $_).Version}} } | Format-Table -AutoSize | Out-String)
    }
}
Run-Command -Command { Get-OfficePresence } `
            -Title "Microsoft Office Presence" `
            -FallbackCommand { 
                $regPaths = @("HKLM:\Software\Microsoft\Office", "HKLM:\Software\WOW6432Node\Microsoft\Office")
                $regOffice = $regPaths | Where-Object { Test-Path $_ } | ForEach-Object { 
                    Get-Item $_ | Select-Object @{Name='Path';Expression={$_}}, @{Name='Version';Expression={(Get-ItemProperty $_).Version}}
                }
                if ($regOffice) {
                    $regOffice | Format-Table -AutoSize | Out-String
                } else {
                    "Microsoft Office not detected in registry."
                }
            }

# Sysmon Status
function Get-SysmonStatus {
    try {
        $sysmonProcess = Get-Process -Name "Sysmon*" -ErrorAction SilentlyContinue
        $sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
        $sysmonDriver = Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -like "SysmonDrv*" } | Select-Object Name, State
        $sysmonFile = Test-Path "C:\Windows\Sysmon.exe" -ErrorAction SilentlyContinue
        $regSysmon = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon" -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            SysmonProcessRunning = if ($sysmonProcess) { $true } else { $false }
            SysmonServiceStatus = if ($sysmonService) { $sysmonService.Status } else { "Not Installed" }
            SysmonDriverStatus = if ($sysmonDriver) { $sysmonDriver.State } else { "Not Installed" }
            SysmonFileExists = $sysmonFile
            SysmonRegistryExists = $regSysmon
        } | Format-Table -AutoSize | Out-String
    } catch {
        return "Error checking Sysmon status: $($_.Exception.Message)"
    }
}
Run-Command -Command { Get-SysmonStatus } `
            -Title "Sysmon Status" `
            -FallbackCommand { sc query Sysmon | Out-String }

# IP Configuration
Run-Command -Command { Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' } | Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table | Out-String } -Title "IP Configuration"

# ARP Table
Run-Command -Command { Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress, LinkLayerAddress, State | Format-Table | Out-String } -Title "ARP Table"

# Shared Resources
Run-Command -Command { net share | Out-String } -Title "Shared Resources"

# Antivirus Products
Run-Command -Command { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState | Format-Table | Out-String } `
            -Title "Antivirus Products" `
            -FallbackCommand { wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayName,productState | Out-String } `
            -RequiresAdmin $true

# Network Computers
Run-Command -Command { net view | Out-String } -Title "Network Computers"

# Domain Information
Run-Command -Command { Get-ADDomain | Select-Object Name, DomainSID, PDCEmulator | Format-Table | Out-String } `
            -Title "Domain Information" `
            -FallbackCommand { nltest /dsgetdc:$env:USERDOMAIN | Out-String } `
            -RequiresModule "Get-ADDomain"

# Domain SID and Trusts
Run-Command -Command { nltest /domain_trusts | Out-String } -Title "Domain SID and Trusts"

# Domain Password Policy
Run-Command -Command { Get-ADDefaultDomainPasswordPolicy | Select-Object MinimumPasswordLength, PasswordComplexity, LockoutDuration, LockoutThreshold | Format-Table | Out-String } `
            -Title "Domain Password Policy" `
            -RequiresModule "Get-ADDefaultDomainPasswordPolicy"

# Domain Controllers
Run-Command -Command { nltest /dclist:$env:USERDOMAIN | Out-String } -Title "Domain Controllers"

# Primary Domain Controller
Run-Command -Command { Get-ADDomain | Select-Object PDCEmulator | Format-Table | Out-String } `
            -Title "Primary Domain Controller" `
            -FallbackCommand { nltest /dsgetdc:$env:USERDOMAIN | Out-String } `
            -RequiresModule "Get-ADDomain"

# Domain Trusts
Run-Command -Command { Get-ADTrust -Filter * | Select-Object Name, Target, Direction | Format-Table | Out-String } `
            -Title "Domain Trusts" `
            -FallbackCommand { nltest /domain_trusts | Out-String } `
            -RequiresModule "Get-ADTrust"

# Forest Trusts
Run-Command -Command { nltest /domain_trusts /all_trusts | Out-String } -Title "Forest Trusts"

# Forest Information
Run-Command -Command { Get-ADForest | Select-Object Name, Domains, GlobalCatalogs | Format-Table | Out-String } `
            -Title "Forest Information" `
            -FallbackCommand { nltest /domain_trusts /all_trusts | Out-String } `
            -RequiresModule "Get-ADForest"

# Global Catalogs
Run-Command -Command { nltest /sc_query:$env:USERDOMAIN | Out-String } -Title "Global Catalogs"

# Domain Groups
Run-Command -Command { Get-ADGroup -Filter * | Select-Object Name, SamAccountName | Format-Table | Out-String } `
            -Title "Domain Groups" `
            -FallbackCommand { net group /domain | Out-String } `
            -RequiresModule "Get-ADGroup"

# Domain Admins Members
Run-Command -Command { net group 'Domain Admins' /domain | Out-String } -Title "Domain Admins Members"

# Local Groups
Run-Command -Command { net localgroup | Out-String } -Title "Local Groups"

# Local Administrators
Run-Command -Command { net localgroup administrators | Out-String } -Title "Local Administrators"

# Group Managed Service Accounts
Run-Command -Command { Get-ADServiceAccount -Filter * | Select-Object Name, ServiceAccountType | Format-Table | Out-String } `
            -Title "Group Managed Service Accounts" `
            -RequiresModule "Get-ADServiceAccount"

# Group Policy Objects
Run-Command -Command { Get-GPO -All | Select-Object DisplayName, Id | Format-Table | Out-String } `
            -Title "Group Policy Objects" `
            -FallbackCommand { gpresult /r | Out-String } `
            -RequiresModule "Get-GPO"

# Organizational Units
Run-Command -Command { Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName | Format-Table | Out-String } `
            -Title "Organizational Units" `
            -RequiresModule "Get-ADOrganizationalUnit"

# Domain Users
Run-Command -Command { Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled | Format-Table | Out-String } `
            -Title "Domain Users" `
            -FallbackCommand { net user /domain | Out-String } `
            -RequiresModule "Get-ADUser"

# Current User Info
Run-Command -Command { whoami /all | Out-String } -Title "Current User Info"

# Password Policy (Local Security Policy)
function Get-LocalPasswordPolicy {
    $tempFile = "$env:TEMP\secpol_$([guid]::NewGuid()).cfg"
    try {
        # Verify write access to TEMP directory
        if (-not (Test-Path -Path $env:TEMP -PathType Container)) {
            return "Error: TEMP directory ($env:TEMP) is inaccessible."
        }
        # Run secedit and check for success
        $null = secedit /export /cfg $tempFile 2>&1
        if (Test-Path $tempFile) {
            $policy = Get-Content $tempFile -ErrorAction Stop | Where-Object { $_ -match "^(MinimumPasswordLength|PasswordComplexity|MaximumPasswordAge|LockoutBadCount|ResetLockoutCount)" }
            $result = $policy -join "`n"
            if (-not $result) { $result = "No relevant policy settings found in secpol.cfg." }
        } else {
            $result = "secedit failed to export policy. Using fallback method (net accounts)."
            $result += "`n" + (net accounts | Out-String)
        }
        return $result
    } catch {
        $result = "Error accessing local password policy: $($_.Exception.Message). Using fallback method (net accounts)."
        $result += "`n" + (net accounts | Out-String)
        return $result
    } finally {
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -ErrorAction SilentlyContinue
        }
    }
}
Run-Command -Command { Get-LocalPasswordPolicy } -Title "Local Password Policy"

# Firewall Status
function Get-FirewallStatus {
    if (Get-Module -ListAvailable -Name NetSecurity) {
        $profiles = Get-NetFirewallProfile | Select-Object Name, Enabled
        return $profiles | Format-Table -AutoSize | Out-String
    } else {
        $output = netsh advfirewall show allprofiles | Select-String "State" -Context 0,1
        return $output -join "`n"
    }
}
Run-Command -Command { Get-FirewallStatus } -Title "Firewall Status"

# End of enumeration
Add-Section -Title "Script Finished" -Content "Enumeration finished at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
