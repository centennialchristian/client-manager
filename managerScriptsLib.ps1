
class EventNotFound : System.Exception {};
class EventInvalidLogonType : System.Exception {};
class EventInvalidUserType : System.Exception {};

Function Is-ValidateUserType {
  param(
    [Parameter(Mandatory=$true,Position=0)][String]$DomainName,
    [Parameter(Mandatory=$true,Position=1)][String]$UserName
  );

  $systemDomains = @('NT AUTHORITY','Font Driver Host','Window Manager');
  $sysDomainsRegex = "($($systemDomains | Foreach-Object { [Regex]::Escape($_)}))";

  $DomainName -notmatch "^$sysDomainsRegex\\" -and $UserName -match '.+' -and -not ($UserName -like "Administrator" -and $DomainName -like "$env:COMPUTERNAME")
}
Function Get-UserFromEvent {
  param($EventRecordId,$EventChannel);

  $logonEvent = Get-WinEvent -FilterXPath "*[System[(EventRecordID='$EventRecordId')]]" -LogName $EventChannel -ErrorAction Continue;
  if (-not $logonEvent) {
    throw [EventNotFound]"Unable to find logon event with RecordID of '$EventRecordId' in '$EventChannel'";
  }
  $eventXml = $logonEvent.ToXml();
  $logonUser = $eventXml.Event.EventData.Data.GetEnumerator() |
    Where-Object -FilterScript { $_.Name -eq 'TargetUserName' } |
    Select-Object -ExpandProperty '#text';

  $logonDomain = $eventXml.Event.EventData.Data.GetEnumerator() | 
    Where-Object -FilterScript { $_.Name -eq 'TargetDomainName' } |
    Select-Object -ExpandProperty '#text';

  $logonType = $eventXml.Event.EventData.Data.GetEnumerator() |
    Where-Object -FilterScript { $_.Name -eq 'LogonType' } |
    Select-Object -ExpandProperty '#text';

  ## If the logon type isn't interactive or terminal services then do not run
  if ($logonType -notmatch '^(2|10)$') {
    throw [EventInvalidLogonType]"Logon type is not interactive or terminal services.";
  }

  if (-not (Is-ValidateUserType -DomainName $logonDomain -UserName $logonUser)) {
    throw [EventInvalidUserType]"'$logonDomain\$logonUser' is a system user.";
  }

  return [PSCustomObject]@{
    UserName = $logonUser;
    DomainName = $logonDomain;
  }
}

Function Get-LoggedOnUsers {
  ## users with processes running exploer.exe
  $systemDomains = @('NT AUTHORITY','Font Driver Host','Window Manager');
  $sysDomainsRegex = "($($systemDomains | Foreach-Object { [Regex]::Escape($_)}))";
  # Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" |
  #   Foreach-Object -Process { Invoke-CimMethod -InputObject $_ -MethodName 'GetOwner' } |
  #   Where-Object -FilterScript { $_.Domain -notmatch "($($systemDomains -join '|'))" -and $_.User -match '.+' -and -not ($_.User -like 'Administrator' -and $_.Domain -like $env:COMPUTERNAME)}
  
  # Where-Object -FilterScript { $_.Name -ne 'powershell.exe' -and Name -ne 'cmd.exe' -and Name -ne 'pwsh.exe' -and Name -ne 'conhost.exe' -and Name -ne 'sshd.exe' -and Name -ne 'mmc.exe'" }
  Get-Process -Name explorer -IncludeUserName -ErrorAction SilentlyContinue |
    Where-Object -FilterScript { Is-ValidateUserType -DomainName $($_.UserName -replace '^([^\\]+)\\.*','$1') -UserName $($_.UserName -replace '^[^\\]+\\','') }

  ## get session Ids of typer interactive (2) or interactive over terminal services (10)
  $logonIds = Get-CimInstance -ClassName Win32_LogonSession -Filter "LogonType=2 or LogonType=10" |
    Select-Object -ExpandProperty LogonId;
  
  ## custom properties to create based on the Win32_LoggedOnUser objects
  $propertyParse =
    @{n='LogonId';e={$_.Dependent -replace '.*LogonId = "([0-9]+)".*','$1'}},
    @{n='UserName';e={$_.Antecedent -replace '.*Name = "([^"]+)".*','$1'}},
    @{n='DomainName';e={$_.Antecedent -replace '.*Domain = "([^"]+)".*','$1'}}
  
  ## get list of users from Win32_LoggedOnUser and filter out system accounts and non-interactive logons
  Get-CimInstance -ClassName Win32_LoggedOnUser |
    Select-Object -Property $propertyParse |
    Where-Object -FilterScript { $_.LogonId -match "($($logonIds -join '|'))" } |
    Where-Object -FilterScript { -not (($_.UserName -match '^(DWM-[0-9]+|UMFD-[0-9]+|(LOCAL|NETWORK) SERVICE)$' -and $_.DomainName -like "^($env:COMPUTERNAME|NT AUTHORITY)$") -or ($_.UserName -like 'SYSTEM' -and $_.DomainName -like "^($env:COMPUTERNAME|NT AUTHORITY)$")) }
    Where-Object -FilterScript { Get-CimInstance -ClassName Win32_Process -Filter "" }
    Sort-Object -Property UserName,Domain
    Select-Object -Unique
}

Function Run-ProcessAsUser {
  param([Int]$SessionId,[String]$CommandLine,[String]$WorkingDir,[TimeSpan]$Timeout);
  ## Credit: https://stackoverflow.com/questions/41902301/run-powershell-command-as-currently-logged-in-user
  Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class WinApi
{
  [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
  public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern bool CreatePip(out IntPtr hReadPipe, out IntPtr hWritePipe, IntPtr lpSECURITY_ATTRIBUTES, uint nSize);

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

  [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
  public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

  [DllImport("Wtsapi32.dll")]
  public static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

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
  [WinApi]::WTSQueryUserToken($SessionId,[ref] $userToken);
  $envBlock = [IntPtr]::Zero;
  ## Create environment block with current environment
  if (-not [WinApi]::CreateEnvironmentBlock([ref] $envBlock,$userToken,$true)) {
    $lastWinError = [Marshal]::GetLastError();
    throw "Unable to create Environment block. Error code $lastWinError";
  }

  try {
    $startupInfo = [WinApi+STARTUPINFO]::new();
    $startupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($startupInfo);
    $procInfo = [WinApi+PROCESS_INFORMATION]::new();
    $createdProc = [WinApi]::CreateProcessAsUserA(
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
    [void][WinApi]::DestroyEnvironmentBlock($envBlock);
  }
}

Function Get-LoggedOnUserState {
  param([String]$UserName,[String]$DomainName);


}

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

$env:ComputerState = @{
  'ADComputer' = $null;
  'ADSite' = $null;
  'BootMode' = $null;
  'ComputerGroups' = $null;
  'DomainJoined' = $null;
  'SystemType' = $null;
  'Win32_Bios' = $null;
  'Win32_ComputerSystem' = $null;
  'Win32_OperatingSystem' = $null;
}

if (& $env:SystemRoot\System32\bcdedit.exe | Select-String -Pattern 'path.*efi') {
  $env:ComputerState['BootMode'] = 'Ueif';
} else {
  $env:ComputerState['BootMode'] = 'Legacy';
}

$env:ComputerState['Win32_BIOS'] =  Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExcludeProperty PSComputerName,CimClass,CimInstanceProperties,CimSystemProperties;
$env:ComputerState['Win32_ComputerSystem'] = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExcludeProperty PSComputerName,CimClass,CimInstanceProperties,CimSystemProperties;
$env:ComputerState['Win32_OperatingSystem'] = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExcludeProperty PSComputerName,CimClass,CimInstanceProperties,CimSystemProperties;

$env:ComputerState['DomainJoined'] = $env:ComputerState['Win32_ComputerSystem'].PartOfDomain;
if ($env:ComputerState['DomainJoined']) {
  Add-Type -AssemblyName System.DirectoryServices.AccountManagement;
  Add-Type -AssemblyName System.DirectoryServices.ActiveDirectory;
  $context = [System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Domain);
  $env:ComputerState['ADComputer'] = [System.DirectoryServices.AccountManagement.ComputerPrincipal]::FindByIdentity($context, $env:COMPUTERNAME);
  $env:ComputerState['CompGroups'] = $adComputer.GetGroups();
  $env:ComputerState['ADSite'] = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite();
  Remove-Variable -Name context -ErrorAction SilentlyContinue;
}


$osdDir = "$env:ProgramData\osd";
$osdInstallersDir = "$osdDir\installers";
$osdUserInstallersDir = "$osdDir\user-installers";
$osdScriptsDir = "$osdDir\scripts";
$osdUserScriptsDir = "$osdDir\user-scripts";

$osdDirs = @{
  Root = $osdDir;
  Installers = $osdInstallersDir;
  UserInstallers = $osdUserInstallersDir;
  Scripts = $osdScriptsDir;
  UserScripts = $osdUserScriptsDir
}


foreach ($dir in $osdDirs.Values) {
  if (-not (Test-Path -Path $dir -ErrorAction SilentlyContinue)) {
    mkdir -Path $dir -ErrorAction Stop | Out-Null;
  }
}

$osdAcl = Get-Acl -Path $osdDir;

$adminAccountsToAdd = @(
  'NT AUTHORITY\SYSTEM',
  'Administrators'
);

if ($env:ComputerState['DomainJoined']) {
  $adminAccountsToAdd += "$($env:ComputerState['Win32_ComputerSystem'].Domain)\Domain Admins";
}

# give administrative accounts explicit permission
$adminInheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit + [System.Security.AccessControl.InheritanceFlags]::ObjectInherit;
$adminPropagateFlags = [System.Security.AccessControl.PropagationFlags]::None;
foreach ($account in $adminAccountsToAdd) {
  Write-Output "Adding rule for '$account'";
  $osdAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($account,"FullControl",$adminInheritFlags,$adminPropagateFlags,"Allow"));
}
Remove-Variable -Name adminPropagateFlags,adminInheritFlags,adminAccountsToAdd -ErrorAction SilentlyContinue;

# give users ability to traverse directory to subdirs they have access to
$userTopInheritFlags = [System.Security.AccessControl.InheritanceFlags]::None;
$userTopPropagateFlags = [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit;
$userTopRights = [System.Security.AccessControl.FileSystemRights]::ListDirectory + [System.Security.AccessControl.FileSystemRights]::Synchronize + [System.Security.AccessControl.FileSystemRights]::Traverse ;
$osdAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new('BUILTIN\Users',$userTopRights,$userTopInheritFlags,$userTopPropagateFlags,"Allow"));

Remove-Variable -Name userTopInheritFlags,userTopPropagateFlags,userTopRights -ErrorAction SilentlyContinue;

# remove inheritence
$osdAcl.SetAccessRuleProtection($true,$false);
Set-Acl -Path $osdDir -AclObject $osdAcl;

Remove-Variable -Name osdAcl;

# give users read only access to specific dirs
$userInheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit + [System.Security.AccessControl.InheritanceFlags]::ObjectInherit;
$userPropagteFlags = [System.Security.AccessControl.PropagationFlags]::None;
$userRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute;
Write-Output "Creating 'Users' rule to apply to user dirs";
$newRule = [System.Security.AccessControl.FileSystemAccessRule]::new('BUILTIN\Users',$userRights,$userInheritFlags,$userPropagteFlags,"Allow");
$userReadOnlyDirs = (dir -Path $osdDir -Filter "user-*").FullName;
foreach ($dir in $userReadOnlyDirs) {
  Write-Output "Adding 'Users' to '$dir'";
  $dirAcl = Get-Acl -Path $dir;
  $dirAcl.AddAccessRule($newRule);
  Set-Acl -Path $dir -AclObject $dirAcl;

  Remove-Variable -Name dirAcl -ErrorAction SilentlyContinue;
}

Remove-Variable -Name osdInstallersDir,osdUserInstallersDir,osdScriptsDir,osdUserScriptsDir,userReadOnlyDirs,newRule,userRights,userPropagateFlags,userInheritFlags -ErrorAction SilentlyContinue;