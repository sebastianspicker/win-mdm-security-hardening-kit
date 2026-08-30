<#
.SYNOPSIS
Stable facade for native command execution and Windows tool operations.

.DESCRIPTION
Loads focused platform implementations while preserving External.psm1's
public command contract for existing endpoint scripts.
#>

Set-StrictMode -Version Latest
Microsoft.PowerShell.Core\Import-Module ([System.IO.Path]::Combine($PSScriptRoot, 'Validation.psm1'))
$script:IsWindowsHost = (
  [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
)

$platformRoot = Join-Path $PSScriptRoot 'platform'
. (Join-Path $platformRoot 'Executable.ps1')
. (Join-Path $platformRoot 'NativeProcess.ps1')
. (Join-Path $platformRoot 'NativeTools.ps1')
. (Join-Path $platformRoot 'WindowsOperations.ps1')

Export-ModuleMember -Function @(
  'Resolve-NativeExecutablePath',
  'Resolve-TrustedWindowsSystemFile',
  'Resolve-TrustedWingetPath',
  'Resolve-TrustedGitPath',
  'Test-CommandExists',
  'Ensure-Cmdlet',
  'Ensure-Exe',
  'Invoke-NativeCommand',
  'Invoke-Schtasks',
  'Invoke-Auditpol',
  'Invoke-Wevtutil',
  'Invoke-Wecutil',
  'Invoke-RegExe',
  'Invoke-WinrmCommand',
  'Invoke-Git',
  'Get-AuditPolSubcategories',
  'Get-EventLogInfo',
  'Enable-EventLog',
  'Set-EventLogMaxSize',
  'Export-EventLog',
  'New-MdmScheduledTask',
  'Remove-ScheduledTask',
  'Export-RegistryKey'
)
