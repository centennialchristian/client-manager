

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

Add-Type -TypeDefinition "$(Get-Content -Path "$PSScriptRoot\CreateProcessAsUser.cs" -Raw)" -Language CSharp;
$ProcAsUser = [ClientManager.ProcessAsUser]::new();
$ProcAsUer.GetTYpe();
$ProcAsUser.Start($SessionId,$CommandLine,$WorkingDir);
$p = Get-Process -Id $ProcAsUser.ProcessId;

while (-not ($p.HasExited) -and $p) {
  Start-Sleep -Seconds 1;
}

$procStdout = $ProcAsUser.GetStdout();
$procStderr = $ProcAsUser.GetStderr();
$ProcAsUser.Dispose();

Write-Output "STDOUT:`n$procStdout`n";
Write-Host "STDERR:`n$procStderr" -ForegroundColor Red;