# STIG-Remediation-WN11-CC-000025

# Synopsis
    This PowerShell script ensures the system is configured to prevent IPv4 source routing (highest protection level).

# Notes
    Author          : Jason Moore
    LinkedIn        : linkedin.com/in/jasonmoore-infosec
    GitHub          : github.com/jasonmoore.io
    Date Created    : 2026-08-26
    Last Modified   : 2026-08-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : 19506
    STIG-ID         : WN11-CC-000025
    Documentation   : https://stigaview.com/products/win11/v2r8/WN11-CC-000025/

# Tested On
    Date(s) Tested  : 2026-08-29
    Tested By       : Tenable Nessus Vulnerability Management
    Systems Tested  : Windows 11
    PowerShell Ver. : Build 26100; Revision 9168

# Usage
    Run this script in an elevated (Administrator) PowerShell session on the
    target Windows 11 workstation. It creates the DisableIPSourceRouting
    DWORD under Tcpip\Parameters, sets it to 2, then prints the confirmation
    output, a PASS/FAIL check, and a reg.exe query so you can capture
    evidence for the STIG checklist. No parameters are required. 

# Remediation
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
  -Name "DisableIPSourceRouting" `
  -PropertyType DWord `
  -Value 2 `
  -Force | Out-Null

# Confirmation command
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
  -Name "DisableIPSourceRouting"

You want to see:
DisableIPSourceRouting : 2

# Disable
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
  -Name "DisableIPSourceRouting" `
  -ErrorAction SilentlyContinue

# Confirmation command
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
  -Name "DisableIPSourceRouting"
  
# Cleaner pass/fail check
$Value = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
  -Name "DisableIPSourceRouting" `
  -ErrorAction SilentlyContinue).DisableIPSourceRouting

if ($Value -eq 2) {
    "PASS: WN11-CC-000025 is configured. IPv4 source routing is disabled."
} else {
    "FAIL: WN11-CC-000025 is not configured correctly. Current value: $Value"
}

# reg.exe confirmation
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting

Expected result:
DisableIPSourceRouting    REG_DWORD    0x2
