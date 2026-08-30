<#
.SYNOPSIS
  Escapes one value for a Windows native command line.
.DESCRIPTION
  Preserves argument boundaries when ProcessStartInfo uses a single string.
#>
function ConvertTo-WindowsCommandLineArgument {
  param([AllowEmptyString()][string]$Argument)

  if ($Argument.Length -eq 0) { return '""' }
  if ($Argument -notmatch '[\s"]') { return $Argument }
  $builder = New-Object System.Text.StringBuilder
  [void]$builder.Append('"')
  $slashes = 0
  foreach ($character in $Argument.ToCharArray()) {
    if ($character -eq '\') { $slashes++; continue }
    if ($character -eq '"') {
      [void]$builder.Append(('\' * (($slashes * 2) + 1)))
      [void]$builder.Append('"')
      $slashes = 0
      continue
    }
    if ($slashes -gt 0) { [void]$builder.Append(('\' * $slashes)); $slashes = 0 }
    [void]$builder.Append($character)
  }
  if ($slashes -gt 0) { [void]$builder.Append(('\' * ($slashes * 2))) }
  [void]$builder.Append('"')
  return $builder.ToString()
}

<#
.SYNOPSIS
  Sets native process arguments using the safest available API.
.DESCRIPTION
  Uses ArgumentList when possible and quotes a legacy command line otherwise.
#>
function Set-NativeProcessArguments {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][System.Diagnostics.ProcessStartInfo]$StartInfo,
    [AllowEmptyCollection()][string[]]$Arguments = @()
  )

  if ($null -ne $StartInfo.PSObject.Properties['ArgumentList']) {
    foreach ($argument in @($Arguments)) {
      [void]$StartInfo.ArgumentList.Add([string]$argument)
    }
    return
  }

  $StartInfo.Arguments = (@(
      $Arguments | ForEach-Object {
        ConvertTo-WindowsCommandLineArgument -Argument ([string]$_)
      }
    ) -join ' ')
}

<#
.SYNOPSIS
  Initializes the native process output capture type.
.DESCRIPTION
  Adds the interop type once for bounded asynchronous stream capture.
#>
function Initialize-NativeProcessCaptureType {
  if ('NativeProcessCapture' -as [type]) { return }
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
public sealed class NativeProcessCapture {
  readonly int max; readonly StringBuilder stdout = new StringBuilder(); readonly StringBuilder stderr = new StringBuilder();
  int stdoutBytes, stderrBytes;
  public bool OutputTruncated, StderrTruncated;
  public NativeProcessCapture(int maxBytes) { max = maxBytes; }
  void Append(StringBuilder target, char[] buffer, int count, bool isError) {
    if (count <= 0 || (isError ? StderrTruncated : OutputTruncated)) return;
    string value = new string(buffer, 0, count);
    int used = isError ? stderrBytes : stdoutBytes; int bytes = Encoding.UTF8.GetByteCount(value);
    if (used + bytes <= max) { target.Append(value); if (isError) stderrBytes += bytes; else stdoutBytes += bytes; return; }
    int remain = Math.Max(0, max - used), low = 0, high = value.Length;
    while (low < high) { int mid = (low + high + 1) / 2; if (Encoding.UTF8.GetByteCount(value.Substring(0, mid)) <= remain) low = mid; else high = mid - 1; }
    if (low > 0 && low < value.Length && char.IsHighSurrogate(value[low - 1]) && char.IsLowSurrogate(value[low])) low--;
    if (low > 0) { string partial = value.Substring(0, low); target.Append(partial); if (isError) stderrBytes += Encoding.UTF8.GetByteCount(partial); else stdoutBytes += Encoding.UTF8.GetByteCount(partial); }
    if (isError) StderrTruncated = true; else OutputTruncated = true;
  }
  async Task Drain(StreamReader reader, bool isError) {
    char[] buffer = new char[4096]; int count;
    while ((count = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0) {
      Append(isError ? stderr : stdout, buffer, count, isError);
    }
  }
  public Task DrainStdoutAsync(StreamReader reader) { return Drain(reader, false); }
  public Task DrainStderrAsync(StreamReader reader) { return Drain(reader, true); }
  public string Output { get { return stdout.ToString(); } }
  public string Error { get { return stderr.ToString(); } }
}

public static class NativeProcessPosix {
  [DllImport("libc", SetLastError = true)]
  static extern int kill(int pid, int signal);
  public static bool KillProcessGroup(int processGroupId) {
    return processGroupId > 0 && kill(-processGroupId, 9) == 0;
  }
}

public sealed class NativeProcessJob : IDisposable {
  const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
  IntPtr handle;

  [StructLayout(LayoutKind.Sequential)]
  struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
    public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
    public uint LimitFlags;
    public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
    public uint ActiveProcessLimit;
    public UIntPtr Affinity;
    public uint PriorityClass, SchedulingClass;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct IO_COUNTERS {
    public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
    public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
    public IO_COUNTERS IoInfo;
    public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
  }
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern IntPtr CreateJobObject(IntPtr attributes, string name);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint length);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool CloseHandle(IntPtr handle);

  public NativeProcessJob() {
    handle = CreateJobObject(IntPtr.Zero, null);
    if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed");
    var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(handle, 9, ref info, (uint)Marshal.SizeOf(info))) {
      int error = Marshal.GetLastWin32Error(); CloseHandle(handle); handle = IntPtr.Zero;
      throw new Win32Exception(error, "SetInformationJobObject failed");
    }
  }
  public void Assign(Process process) {
    if (process == null) throw new ArgumentNullException("process");
    if (handle == IntPtr.Zero) throw new ObjectDisposedException("NativeProcessJob");
    if (!AssignProcessToJobObject(handle, process.Handle))
      throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject failed");
  }
  public void Dispose() {
    IntPtr value = Interlocked.Exchange(ref handle, IntPtr.Zero);
    if (value != IntPtr.Zero) CloseHandle(value);
  }
}
'@ -ErrorAction Stop
}

<#
.SYNOPSIS
  Gets the trusted PowerShell host path for native workers.
.DESCRIPTION
  Fails closed when the current host executable cannot be resolved.
#>
function Get-NativePowerShellHostPath {
  [OutputType([string])]
  param()

  $hostPath = try { (Get-Process -Id $PID -ErrorAction Stop).Path } catch { $null }
  if ([string]::IsNullOrWhiteSpace($hostPath) -or -not (Test-Path -LiteralPath $hostPath -PathType Leaf)) {
    throw 'Unable to resolve the current trusted PowerShell host for native process isolation.'
  }
  return [IO.Path]::GetFullPath($hostPath)
}

<#
.SYNOPSIS
  Builds the isolated native-worker script text.
.DESCRIPTION
  Supplies the child process code used to execute a native command safely.
#>
function Get-NativeWorkerScript {
  [OutputType([string])]
  param()

  return @'
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 can serialize first-use module progress as CLIXML on
# stderr when the worker is redirected. Suppress only the worker's progress;
# native child stdout and stderr are still copied byte-for-byte below.
$ProgressPreference = 'SilentlyContinue'
$gate = $null
$child = $null
$utf8 = New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8
[Console]::InputEncoding = $utf8

<#
.SYNOPSIS
  Escapes one argument for the native worker command line.
.DESCRIPTION
  Keeps worker argument boundaries intact for the fallback launch API.
#>
function ConvertTo-WorkerCommandLineArgument {
  param([AllowEmptyString()][string]$Argument)

  if ($Argument.Length -eq 0) { return '""' }
  if ($Argument -notmatch '[\s"]') { return $Argument }
  $builder = New-Object System.Text.StringBuilder
  [void]$builder.Append('"')
  $slashes = 0
  foreach ($character in $Argument.ToCharArray()) {
    if ($character -eq '\') { $slashes++; continue }
    if ($character -eq '"') {
      [void]$builder.Append(('\' * (($slashes * 2) + 1)))
      [void]$builder.Append('"')
      $slashes = 0
      continue
    }
    if ($slashes -gt 0) { [void]$builder.Append(('\' * $slashes)); $slashes = 0 }
    [void]$builder.Append($character)
  }
  if ($slashes -gt 0) { [void]$builder.Append(('\' * ($slashes * 2))) }
  [void]$builder.Append('"')
  return $builder.ToString()
}

<#
.SYNOPSIS
  Configures command-line arguments for the native worker.
.DESCRIPTION
  Uses the worker-specific quoting rules required by the child process.
#>
function Set-WorkerProcessArguments {
  param(
    [Parameter(Mandatory)][Diagnostics.ProcessStartInfo]$StartInfo,
    [AllowEmptyCollection()][object[]]$Arguments = @()
  )

  if ($null -ne $StartInfo.PSObject.Properties['ArgumentList']) {
    foreach ($argument in @($Arguments)) {
      [void]$StartInfo.ArgumentList.Add([string]$argument)
    }
    return
  }

  $StartInfo.Arguments = (@(
      $Arguments | ForEach-Object {
        ConvertTo-WorkerCommandLineArgument -Argument ([string]$_)
      }
    ) -join ' ')
}

try {
  $encoded = [Environment]::GetEnvironmentVariable('BASELINEOPS_NATIVE_MANIFEST_B64', 'Process')
  if ([string]::IsNullOrWhiteSpace($encoded) -or $encoded.Length -gt 24576) { throw 'Native worker manifest is missing or oversized.' }
  try {
    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
  } finally {
    [Environment]::SetEnvironmentVariable('BASELINEOPS_NATIVE_MANIFEST_B64', $null, [EnvironmentVariableTarget]::Process)
    Remove-Item -LiteralPath 'Env:BASELINEOPS_NATIVE_MANIFEST_B64' -ErrorAction SilentlyContinue
    $encoded = $null
  }
  $manifest = $json | ConvertFrom-Json -ErrorAction Stop
  if ([string]::IsNullOrWhiteSpace([string]$manifest.Command)) { throw 'Native worker manifest is invalid.' }

  if ([bool]$manifest.StartNewSession) {
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class NativeProcessWorkerSession {
  [DllImport("libc", SetLastError = true)] public static extern int setsid();
}
"@ -ErrorAction Stop
    if ([NativeProcessWorkerSession]::setsid() -lt 0) {
      throw [ComponentModel.Win32Exception]::new(
        [Runtime.InteropServices.Marshal]::GetLastWin32Error(),
        'setsid failed'
      )
    }
  }

  if (-not [string]::IsNullOrWhiteSpace([string]$manifest.GateName)) {
    $gate = [Threading.EventWaitHandle]::OpenExisting([string]$manifest.GateName)
    if (-not $gate.WaitOne(30000)) { throw 'Native worker start gate timed out.' }
  }

  $startInfo = New-Object Diagnostics.ProcessStartInfo
  $startInfo.FileName = [string]$manifest.Command
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  # A Windows child launched by a redirected, windowless worker does not
  # reliably inherit the worker's standard handles. Redirect explicitly and
  # stream both pipes through the worker so the parent can apply its existing
  # independent output bounds without buffering the child output here.
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  Set-WorkerProcessArguments -StartInfo $startInfo -Arguments @($manifest.Arguments)
  [void]$startInfo.EnvironmentVariables.Remove('BASELINEOPS_NATIVE_MANIFEST_B64')
  $child = [Diagnostics.Process]::Start($startInfo)
  if ($null -eq $child) { throw 'Native child process did not start.' }
  $stdoutTarget = [Console]::OpenStandardOutput()
  $stderrTarget = [Console]::OpenStandardError()
  $stdoutCopy = $child.StandardOutput.BaseStream.CopyToAsync($stdoutTarget)
  $stderrCopy = $child.StandardError.BaseStream.CopyToAsync($stderrTarget)
  $child.WaitForExit()
  [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdoutCopy, $stderrCopy))
  $stdoutTarget.Flush()
  $stderrTarget.Flush()
  exit $child.ExitCode
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 125
} finally {
  if ($null -ne $child) { $child.Dispose() }
  if ($null -ne $gate) { $gate.Dispose() }
}
'@
}

<#
.SYNOPSIS
  Creates ProcessStartInfo for an isolated native worker.
.DESCRIPTION
  Encodes the validated execution manifest for the child process environment.
#>
function New-NativeWorkerStartInfo {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ResolvedCommand,
    [AllowEmptyCollection()][string[]]$Arguments = @(),
    [AllowEmptyString()][string]$GateName = '',
    [switch]$StartNewSession
  )

  $manifestJson = [ordered]@{
    Command         = $ResolvedCommand
    Arguments       = @($Arguments | ForEach-Object { [string]$_ })
    GateName        = $GateName
    StartNewSession = [bool]$StartNewSession
  } | ConvertTo-Json -Compress -Depth 3
  $manifestBytes = [Text.Encoding]::UTF8.GetBytes($manifestJson)
  if ($manifestBytes.Length -gt 16384) { throw 'Native command manifest exceeds the safe environment bound.' }

  $workerScript = Get-NativeWorkerScript
  $encodedWorker = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($workerScript))
  $startInfo = New-Object Diagnostics.ProcessStartInfo
  $startInfo.FileName = Get-NativePowerShellHostPath
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  Set-NativeProcessArguments -StartInfo $startInfo -Arguments @(
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-OutputFormat',
    'Text',
    '-EncodedCommand',
    $encodedWorker
  )
  $startInfo.EnvironmentVariables['BASELINEOPS_NATIVE_MANIFEST_B64'] = [Convert]::ToBase64String($manifestBytes)
  return $startInfo
}

<#
.SYNOPSIS
  Stops a native process and its descendants.
.DESCRIPTION
  Uses platform-appropriate termination with a safe failure result.
#>
function Stop-NativeProcessTree {
  [OutputType([bool])]
  param(
    [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
    [int]$ProcessGroupId = 0
  )
  if (-not $script:IsWindowsHost -and $ProcessGroupId -gt 0) {
    try {
      [void][NativeProcessPosix]::KillProcessGroup($ProcessGroupId)
      try { if ($Process.HasExited) { return $true } } catch { return $false }
      return $Process.WaitForExit(5000)
    } catch { Write-Verbose "POSIX process-group termination failed: $($_.Exception.Message)" }
  }
  try { if ($Process.HasExited) { return $true } } catch { return $false }
  if ($script:IsWindowsHost) {
    $taskkill = $null
    try {
      $taskkillPath = Resolve-TrustedWindowsSystemFile -LeafName 'taskkill.exe'
      if ([string]::IsNullOrWhiteSpace($taskkillPath)) { throw 'Trusted taskkill executable not found.' }
      $killer = New-Object System.Diagnostics.ProcessStartInfo
      $killer.FileName = $taskkillPath; $killer.Arguments = "/PID $($Process.Id) /T /F"; $killer.UseShellExecute = $false; $killer.CreateNoWindow = $true
      $taskkill = [System.Diagnostics.Process]::Start($killer)
      if ($taskkill -and -not $taskkill.WaitForExit(10000)) {
        try { $taskkill.Kill(); [void]$taskkill.WaitForExit(2000) } catch { Write-Verbose "taskkill timeout cleanup failed: $($_.Exception.Message)" }
      }
      if ($Process.WaitForExit(5000)) { return $true }
    } catch { Write-Verbose "taskkill process-tree termination failed: $($_.Exception.Message)" }
    finally { if ($null -ne $taskkill) { $taskkill.Dispose() } }
  }
  try {
    if (-not $script:IsWindowsHost) {
      try {
        $Process.Kill($true)
        return $Process.WaitForExit(5000)
      } catch { Write-Verbose "Whole process-tree kill is unavailable; falling back to the direct process: $($_.Exception.Message)" }
    }
    $Process.Kill()
    return $Process.WaitForExit(5000)
  } catch {
    Write-Verbose "Process kill fallback failed: $($_.Exception.Message)"
    return $false
  }
}

<#
.SYNOPSIS
  Verifies the resolved WinGet executable identity.
.DESCRIPTION
  Rejects an executable whose signed identity is not the expected binary.
#>
function Assert-NativeExecutableIdentity {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ResolvedCommand)

  if (-not $script:IsWindowsHost -or [IO.Path]::GetFileName($ResolvedCommand) -ine 'winget.exe') {
    return
  }

  $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $ResolvedCommand -ErrorAction Stop
  $subject = if ($null -ne $signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { '' }
  $originalFilename = [string][System.Diagnostics.FileVersionInfo]::GetVersionInfo($ResolvedCommand).OriginalFilename
  if (
    $signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
    $subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)' -or
    $originalFilename -ine 'winget.exe'
  ) {
    throw 'WinGet executable identity validation failed.'
  }
}

<#
.SYNOPSIS
  Creates resources required to launch a native worker.
.DESCRIPTION
  Holds validation locks and process controls through the launch transition.
#>
function New-NativeWorkerLaunchContext {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ResolvedCommand,
    [AllowEmptyCollection()][string[]]$Arguments = @()
  )

  $startGate = $null
  $nativeJob = $null
  $workerLock = $null
  try {
    if ($script:IsWindowsHost) {
      $gateName = 'Local\BaselineOpsNative-' + [Guid]::NewGuid().ToString('N')
      $startGate = New-Object Threading.EventWaitHandle(
        $false,
        [Threading.EventResetMode]::ManualReset,
        $gateName
      )
      $startInfo = New-NativeWorkerStartInfo `
        -ResolvedCommand $ResolvedCommand `
        -Arguments $Arguments `
        -GateName $gateName
      $workerLock = [IO.File]::Open(
        $startInfo.FileName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
      )
      $nativeJob = New-Object NativeProcessJob
    } else {
      $startInfo = New-NativeWorkerStartInfo `
        -ResolvedCommand $ResolvedCommand `
        -Arguments $Arguments `
        -StartNewSession
    }

    return [pscustomobject]@{
      StartInfo  = $startInfo
      StartGate  = $startGate
      NativeJob  = $nativeJob
      WorkerLock = $workerLock
    }
  } catch {
    if ($null -ne $startGate) { $startGate.Dispose() }
    if ($null -ne $nativeJob) { $nativeJob.Dispose() }
    if ($null -ne $workerLock) { $workerLock.Dispose() }
    throw
  }
}

<#
.SYNOPSIS
  Waits for native process completion and captures its output.
.DESCRIPTION
  Returns bounded output, exit state, and timeout information for callers.
#>
function Wait-NativeProcessCompletion {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
    [Parameter(Mandatory)][object]$Capture,
    [Parameter(Mandatory)][ValidateRange(1, 86400)][int]$TimeoutSeconds,
    [AllowNull()][object]$NativeJob,
    [int]$ProcessGroupId = 0
  )

  $stdoutTask = $Capture.DrainStdoutAsync($Process.StandardOutput)
  $stderrTask = $Capture.DrainStderrAsync($Process.StandardError)
  $drainTasks = [System.Threading.Tasks.Task[]]@($stdoutTask, $stderrTask)
  $executionTimedOut = -not $Process.WaitForExit($TimeoutSeconds * 1000)
  $terminated = $true
  if ($executionTimedOut) {
    if ($null -ne $NativeJob) { $NativeJob.Dispose() }
    $terminated = $Process.WaitForExit(5000)
    if (-not $terminated) {
      $terminated = Stop-NativeProcessTree -Process $Process -ProcessGroupId $ProcessGroupId
    }
  }

  $drained = $false
  if ($terminated) {
    try {
      $drained = [System.Threading.Tasks.Task]::WaitAll($drainTasks, 10000)
    } catch {
      $drained = $false
    }
  }
  if (-not $drained) {
    if ($null -ne $NativeJob) { $NativeJob.Dispose() }
    if (-not $script:IsWindowsHost) {
      [void](Stop-NativeProcessTree -Process $Process -ProcessGroupId $ProcessGroupId)
    }
    $Capture.OutputTruncated = $true
    $Capture.StderrTruncated = $true
    try { $Process.StandardOutput.Dispose() } catch { Write-Verbose "Stdout drain cleanup failed: $($_.Exception.Message)" }
    try { $Process.StandardError.Dispose() } catch { Write-Verbose "Stderr drain cleanup failed: $($_.Exception.Message)" }
    try {
      [void][System.Threading.Tasks.Task]::WaitAll($drainTasks, 2000)
    } catch {
      Write-Verbose "Native stream drain did not reach a clean terminal state: $($_.Exception.Message)"
    }
  }

  $timedOut = $executionTimedOut -or -not $drained
  return [pscustomobject]@{
    ExecutionTimedOut = $executionTimedOut
    Drained           = $drained
    TimedOut          = $timedOut
    ExitCode          = if ($timedOut) { -1 } else { $Process.ExitCode }
    Stdout            = $Capture.Output
    Stderr            = $Capture.Error
    OutputTruncated   = [bool]$Capture.OutputTruncated
    StderrTruncated   = [bool]$Capture.StderrTruncated
  }
}

<#
.SYNOPSIS
  Formats a native-command failure message.
.DESCRIPTION
  Includes exit and bounded stderr context without returning unbounded output.
#>
function Get-NativeCommandFailureMessage {
  [OutputType([string])]
  param(
    [Parameter(Mandatory)][string]$Command,
    [Parameter(Mandatory)][object]$Completion,
    [Parameter(Mandatory)][ValidateRange(1, 86400)][int]$TimeoutSeconds
  )

  $message = if ($Completion.ExecutionTimedOut) {
    "$Command timed out after $TimeoutSeconds seconds"
  } elseif (-not $Completion.Drained) {
    "$Command left a process tree or output stream open after exit"
  } else {
    "$Command exited with code $($Completion.ExitCode)"
  }

  if (-not [string]::IsNullOrWhiteSpace([string]$Completion.Stderr)) {
    $stderrExcerpt = ([string]$Completion.Stderr).Trim()
    if ($stderrExcerpt.Length -gt 4096) {
      $stderrExcerpt = $stderrExcerpt.Substring(0, 4096) + ' [truncated]'
    }
    $message = "$message. Stderr: $stderrExcerpt"
  }
  return $message
}

<#
.SYNOPSIS
  Splits captured native output into lines.
.DESCRIPTION
  Preserves meaningful blank lines while removing only a trailing terminator.
#>
function ConvertTo-NativeOutputLines {
  [CmdletBinding()]
  param([AllowNull()][string]$Text)

  if ([string]::IsNullOrEmpty($Text)) { return }
  $lines = @($Text -split '\r\n|\n|\r')
  if ($lines.Count -gt 0 -and $lines[-1] -eq '' -and $Text -match '(?:\r\n|\n|\r)$') {
    $lines = if ($lines.Count -eq 1) { @() } else { @($lines[0..($lines.Count - 2)]) }
  }
  foreach ($line in $lines) { $line }
}

<#
.SYNOPSIS
  Creates the public result object for a native command.
.DESCRIPTION
  Maps worker completion data to the module's stable result contract.
#>
function New-NativeCommandResult {
  param([Parameter(Mandatory)][object]$Completion)

  $success = (-not $Completion.TimedOut -and $Completion.ExitCode -eq 0)
  $outputLines = New-Object System.Collections.Generic.List[object]
  foreach ($line in @(ConvertTo-NativeOutputLines -Text ([string]$Completion.Stdout))) {
    [void]$outputLines.Add($line)
  }
  foreach ($line in @(ConvertTo-NativeOutputLines -Text ([string]$Completion.Stderr))) {
    [void]$outputLines.Add($line)
  }
  $legacyOutput = if ($outputLines.Count -eq 0) {
    $null
  } elseif ($outputLines.Count -eq 1) {
    $outputLines[0]
  } else {
    $outputLines.ToArray()
  }

  return [pscustomobject]@{
    Output          = $legacyOutput
    Stdout          = [string]$Completion.Stdout
    Stderr          = [string]$Completion.Stderr
    ExitCode        = [int]$Completion.ExitCode
    Success         = $success
    TimedOut        = [bool]$Completion.TimedOut
    OutputTruncated = [bool]$Completion.OutputTruncated
    StderrTruncated = [bool]$Completion.StderrTruncated
  }
}

<#
.SYNOPSIS
  Invokes a validated native command with bounded capture.
.DESCRIPTION
  Runs the command through the isolated worker and returns structured status.
#>
function Invoke-NativeCommand {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Command,

    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [AllowEmptyString()]
    [string[]]$Arguments,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput,

    [switch]$Quiet,

    [ValidateRange(1, 86400)][int]$TimeoutSeconds = 300,

    [ValidateRange(1024, 10485760)][int]$MaxOutputBytes = 1048576
  )

  # ProcessStartInfo starts FileName directly with UseShellExecute disabled, so
  # path characters such as spaces and ampersands are data rather than shell
  # syntax. Reject only empty values and control characters that cannot identify
  # a safe executable path.
  if ([string]::IsNullOrWhiteSpace($Command) -or $Command -match '[\x00-\x1F\x7F]') {
    throw "Invoke-NativeCommand: -Command must be a non-empty executable name or path without control characters."
  }

  # Resolve once to an absolute path. The read-share lock prevents replacement
  # on Windows. POSIX launch remains path-based: the open descriptor proves the
  # checked file was readable but cannot prevent a concurrent rename/unlink.
  $resolvedCommand = Resolve-NativeExecutablePath -Name $Command
  if ([string]::IsNullOrWhiteSpace($resolvedCommand)) {
    $msg = "Command not found: $Command"
    if ($ThrowOnError) {
      throw $msg
    }
    Write-Warning $msg
    return $null
  }

  $process = $null
  $processStarted = $false
  $executableLock = $null
  $launchContext = $null
  $processGroupId = 0
  try {
    $executableLock = [System.IO.File]::Open($resolvedCommand, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    Assert-NativeExecutableIdentity -ResolvedCommand $resolvedCommand
    Initialize-NativeProcessCaptureType
    $launchContext = New-NativeWorkerLaunchContext -ResolvedCommand $resolvedCommand -Arguments $Arguments
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $launchContext.StartInfo
    $capture = New-Object NativeProcessCapture($MaxOutputBytes)
    if (-not $process.Start()) { throw "Process did not start: $Command" }
    $processStarted = $true
    if (-not $script:IsWindowsHost) { $processGroupId = $process.Id }
    if ($null -ne $launchContext.NativeJob) {
      $launchContext.NativeJob.Assign($process)
      [void]$launchContext.StartGate.Set()
    }
    $completion = Wait-NativeProcessCompletion `
      -Process $process `
      -Capture $capture `
      -TimeoutSeconds $TimeoutSeconds `
      -NativeJob $launchContext.NativeJob `
      -ProcessGroupId $processGroupId
    $success = (-not $completion.TimedOut -and $completion.ExitCode -eq 0)
    if (-not $success) {
      $msg = Get-NativeCommandFailureMessage `
        -Command $Command `
        -Completion $completion `
        -TimeoutSeconds $TimeoutSeconds
      if ($ThrowOnError) { throw $msg }
      if (-not $Quiet) { Write-Warning $msg }
    }
    if ($CaptureOutput) {
      return New-NativeCommandResult -Completion $completion
    }
    if ($success) { return $true }
    return $false
  } catch {
    if ($processStarted) {
      try { if (-not $process.HasExited) { [void](Stop-NativeProcessTree -Process $process -ProcessGroupId $processGroupId) } } catch { Write-Verbose "Failed native process cleanup: $($_.Exception.Message)" }
    }
    $msg = "Failed to execute $Command : $($_.Exception.Message)"
    if ($ThrowOnError) {
      throw $msg
    }
    Write-Warning $msg
    return $null
  } finally {
    if ($null -ne $launchContext) {
      if ($null -ne $launchContext.StartGate) { $launchContext.StartGate.Dispose() }
      if ($null -ne $launchContext.NativeJob) { $launchContext.NativeJob.Dispose() }
      if ($null -ne $launchContext.WorkerLock) { $launchContext.WorkerLock.Dispose() }
    }
    if ($null -ne $process) { $process.Dispose() }
    if ($null -ne $executableLock) { $executableLock.Dispose() }
  }
}
