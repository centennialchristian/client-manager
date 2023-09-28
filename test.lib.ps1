

$PC_SYSTEM_TYPE = @{
  0 = 'Unspecified';
  1 = 'Desktop';
  2 = 'Mobile';
  3 = 'Workstation';
  4 = 'Enterprise';
  5 = 'SOHO';
  6 = 'Appliance';
  7 = 'Performance';
  8 = 'Maximum';
}

$global:ComputerState = @{
  'ADComputer' = $null;
  'ADSite' = $null;
  'BootMode' = $null;
  'ComputerGroups' = $null;
  'DomainJoined' = $null;
  'SystemType' = $null;
  'Win32_BIOS' = $null;
  'Win32_ComputerSystem' = $null;
  'Win32_OperatingSystem' = $null;
}

if (& $env:SystemRoot\System32\bcdedit.exe | Select-String -Pattern 'path.*efi') {
  $global:ComputerState['BootMode'] = 'Ueif';
} else {
  $global:ComputerState['BootMode'] = 'Legacy';
}

$global:ComputerState['Win32_BIOS'] =  Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExcludeProperty PSComputerName,CimClass,CimInstanceProperties,CimSystemProperties;
$global:ComputerState['Win32_ComputerSystem'] = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExcludeProperty PSComputerName,CimClass,CimInstanceProperties,CimSystemProperties;
$global:ComputerState['Win32_OperatingSystem'] = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExcludeProperty PSComputerName,CimClass,CimInstanceProperties,CimSystemProperties;

$global:ComputerState['DomainJoined'] = $global:ComputerState['Win32_ComputerSystem'].PartOfDomain;
if ($global:ComputerState['DomainJoined']) {
  Add-Type -AssemblyName System.DirectoryServices.AccountManagement;
  # Add-Type -AssemblyName System.DirectoryServices.ActiveDirectory;
  $context = [System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Domain);
  $global:ComputerState['ADComputer'] = [System.DirectoryServices.AccountManagement.ComputerPrincipal]::FindByIdentity($context, $env:COMPUTERNAME);
  $global:ComputerState['ComputerGroups'] = $global:ComputerState['ADComputer'].GetGroups();
  $global:ComputerState['ADSite'] = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite();
  Remove-Variable -Name context -ErrorAction SilentlyContinue;
}

$SessionId = Get-Process -Name explorer -IncludeUserName | Select-Object -ExpandProperty SessionId;
# $WorkingDir = "$env:ProgramData\osd\ClientManager\PrinterManager\AsUserScripts";
$WorkingDir = "C:\Users\trolleman";
# $testCmdString = @"
# `$env:ComputerState = ConvertFrom-Json -InputObject "$(ConvertTo-Json -Compress -InputObject $global:ComputerState)";
# `$env:USERPROFILE;
# (Get-Date).ToString() | Add-Content -Path "`$env:USERPROFILE\test-userscript.txt"
# "@;
$testCmdString = "Write-Output `$env:USERPROFILE";
$testCmdB64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($testCmdString));
$CommandLine = "$env:WINDIR\System32\WindowsPowershell\v1.0\powershell.exe -NoLogo -NonInteractive -ExecutionPolicy ByPass -WindowStyle Hidden -EncodedCommand `"$testCmdB64`"";

Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class AdvApi32Dll {

  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern bool CreateProcessAsUserA(
    IntPtr hToken,
    string lpApplicationName,
    string lpCommandLine,
    IntPtr lpProcessAttributes,
    IntPtr lpThreadAttributes,
    bool bInheritHandles,
    uint dwCreationFlags,
    IntPtr lpEnvironment,
    string lpCurrentDirectory,
    [In] ref STARTUPINFO lpStartupInfo,
    out PROCESS_INFORMATION lpProcessInformation
  );

  [StructLayout(LayoutKind.Sequential)]
  public struct PROCESS_INFORMATION {
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct SECURITY_ATTRIBUTES {
      public int nLength;
      public IntPtr lpSecurityDescriptor;
      public int bInheritHandle;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct STARTUPINFO {
    public Int32 cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public Int32 dwX;
    public Int32 dwY;
    public Int32 dwXSize;
    public Int32 dwYSize;
    public Int32 dwXCountChars;
    public Int32 dwYCountChars;
    public Int32 dwFillAttribute;
    public Int32 dwFlags;
    public Int16 wShowWindow;
    public Int16 cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
  }

  [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
  public static extern bool DuplicateTokenEx(
    IntPtr ExistingTokenHandle,
    uint dwDesiredAccess,
    IntPtr lpThreadAttributes,
    int TokenType,
    int ImpersonationLevel,
    ref IntPtr DuplicateTokenHandle
  );
}

public class Kernel32Dll {
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, IntPtr lpSECURITY_ATTRIBUTES, uint nSize);

  [DllImport("kernel32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool CloseHandle(IntPtr hObject);
}

public class UserEnvDll {
  [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
  public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

  [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
  public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
}

public class WtsApi32Dll {
  [DllImport("Wtsapi32.dll")]
  public static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);
}
"@
$HIDE_WINDOW = 0;
$NO_CREATION_FLAGS = 0;
$IMPERSONATION_LEVEL_IMPERSONATE = 2;
$STARTF_USESTDHANDLES = 0x00000100;
$TOKEN_ACCESS_SAME = 0;
$TOKEN_TYPE_IMPERSONATE = 2;
$TOKEN_TYPE_PRIMARY = 1;
$CREATE_NO_NEW_WINDOW = 0x08000000;
$CREATE_UNICODE_ENVIRONMENT = 0x00000400;

$userToken = [IntPtr]::Zero;
[WtsApi32Dll]::WTSQueryUserToken($SessionId,[ref] $userToken);
$envBlock = [IntPtr]::Zero;
## Create basic environment block
if (-not [UserEnvDll]::CreateEnvironmentBlock([ref] $envBlock,$userToken,$false)) {
  $lastWinError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
  throw "Unable to create Environment block. Error code $lastWinError";
}

$procSecurityAttrs = [AdvApi32Dll+SECURITY_ATTRIBUTES]::new();
$procSecurityAttrs.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($procSecurityAttrs);
$procSecurityAttrs.bInheritHandle = 0; # do not inherit current handle
$procSecurityAttrs.lpSecurityDescriptor = [IntPtr]::Zero;# user default security descriptor

## Access to the stdout and stderr of the new process requires a PIPE.
$stdoutReadHandle = [IntPtr]::Zero;
$stdoutWriteHandle = [IntPtr]::Zero;
$stderrReadHandle = [IntPtr]::Zero;
$stderrWriteHandle = [IntPtr]::Zero;
if (-not ([Kernel32Dll]::CreatePipe([ref] $stdoutReadHandle, [ref] $stdoutWriteHandle, [IntPtr]::Zero, 0))) {
  throw "Error creating the stdout PIPE";
}
if (-not ([Kernel32Dll]::CreatePipe([ref] $stderrReadHandle, [ref] $stderrWriteHandle, [IntPtr]::Zero, 0))) {
  throw "Error creating the stderr PIPE";
}

try {
  $startupInfo = [AdvApi32Dll+STARTUPINFO]::new();
  $startupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($startupInfo);
  $startupInfo.hStdError = $stderrWriteHandle;
  $startupInfo.hStdOutput = $stdoutWriteHandle;
  $startupInfo.dwFlags = $STARTF_USESTDHANDLES;
  $procInfo = [AdvApi32Dll+PROCESS_INFORMATION]::new();
  # $createdProc = [AdvApi32Dll]::CreateProcessAsUserA(
  #   $userToken,
  #   [IntPtr]::Zero,
  #   $CommandLine,
  #   [IntPtr]::Zero,
  #   [IntPtr]::Zero,
  #   $false,
  #   $($CREATE_NO_NEW_WINDOW+$CREATE_UNICODE_ENVIRONMENT),
  #   $envBlock,
  #   $WorkingDir,
  #   [ref] $startupInfo,
  #   [ref] $procInfo
  # );
  $createdProc = [AdvApi32Dll]::CreateProcessAsUserA(
    $userToken,
    [IntPtr]::Zero,
    $CommandLine,
    [IntPtr]::Zero,
    [IntPtr]::Zero,
    $false,
    $($CREATE_NO_NEW_WINDOW+$CREATE_UNICODE_ENVIRONMENT),
    [IntPtr]::Zero,
    $WorkingDir,
    [ref] $startupInfo,
    [ref] $procInfo
  );

  if (-not $createdProc) {
    $lastWinError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
    throw "Unable to create process. Error code $lastWinError .";
  } else {
    Write-Output "Process was created.";
  }

  while (Get-Process -Id $procInfo.dwProcessId -ErrorAction SilentlyContinue) {
    Start-Sleep -Seconds 1;
  }

  $stdoutFSStream = [System.IO.FileStream]::new($stdoutReadHandle, [System.IO.FileAccess]::Read);
  $stdoutReader = [System.IO.StreamReader]::new($stdoutFSStream);
  $stdoutResult = @();
  while ($line = $stdoutReader.ReadLine()) {
    $stdoutResult += $line;
  }
  $stdoutReader.Close();

  $stderrFSStream = [System.IO.FileStream]::new($stderrReadHandle, [System.IO.FileAccess]::Read);
  $stderrReader = [StreamReader]::new($stderrFSStream);
  $stderrResult = @();
  while ($line = $stderrReader.ReadLine()) {
    $stderrResult += $line;
  }
  $stderrReader.Close();

  Write-Output "StdOut = $($stdoutResult -join "`n")";
  Write-Output "StdErr = $($stderrResult -join "`n")";
} finally {
  [Kernel32Dll]::CloseHandle($procInfo.hProcess);
  [Kernel32Dll]::CloseHandle($procInfo.hThread);
  [Kernel32Dll]::CloseHandle($stdoutWriteHandle);
  [Kernel32Dll]::CloseHandle($stderrWriteHandle);
  [void][UserEnvDll]::DestroyEnvironmentBlock($envBlock);
}