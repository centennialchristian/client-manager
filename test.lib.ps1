

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
  Add-Type -AssemblyName System.DirectoryServices.ActiveDirectory;
  $context = [System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Domain);
  $global:ComputerState['ADComputer'] = [System.DirectoryServices.AccountManagement.ComputerPrincipal]::FindByIdentity($context, $env:COMPUTERNAME);
  $global:ComputerState['CompGroups'] = $adComputer.GetGroups();
  $global:ComputerState['ADSite'] = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite();
  Remove-Variable -Name context -ErrorAction SilentlyContinue;
}

$SessionId = Get-Process -Name explorer -IncludeUserName | Select-Object -ExpandProperty SessionId;
$WorkingDir = "$env:ProgramData\osd\ClientManager\PrinterManager\AsUserScripts";
$testCmdString = @"
`$env:ComputerState = ConvertFrom-Json -InputObject "$(ConvertTo-Json -Compress -InputObject $global:ComputerState)";
. "$WorkingDir\test.userscript.ps1"
"@;
$testCmdB64 = [System.Convert]::ToBase64String([System.Convert.UTF8]::GetBytes($testCmdString));
$CommandLine = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy ByPass -WindowStyle Hidden -EncodedCommand `"$testCmdB64`""
return;

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
  public static extern bool CreatePip(out IntPtr hReadPipe, out IntPtr hWritePipe, IntPtr lpSECURITY_ATTRIBUTES, uint nSize);
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
  $lastWinError = [Marshal]::GetLastError();
  throw "Unable to create Environment block. Error code $lastWinError";
}

try {
  $startupInfo = [AdvApi32Dll+STARTUPINFO]::new();
  $startupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($startupInfo);
  $procInfo = [AdvApi32Dll+PROCESS_INFORMATION]::new();
  $createdProc = [AdvApi32Dll]::CreateProcessAsUserA(
    $userToken,
    [IntPtr]::Zero,
    $CommandLine,
    [IntPtr]::Zero,
    [IntPtr]::Zero,
    $false,
    $CREATE_NO_NEW_WINDOW+$CREATE_UNICODE_ENVIRONMENT,
    $envBlock,
    $WorkingDir,
    [ref] $startupInfo,
    [ref] $procInfo
  );

  if (-not $createdProc) {
    $lastWinError = [Marshal]::GetLastError();
    throw "Unable to create process. Error code $lastWinError .";
  }
} finally {
  [void][UserEnvDll]::DestroyEnvironmentBlock($envBlock);
}