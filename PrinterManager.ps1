##
##  If this script is passed an EventRecordId, then will assume it is a logon event and 
##    run only on that user. Otherwise will run on all users running explorer.exe .
##
[CmdletBinding()]
param(
  [String]$EventRecordId,
  [String]$EventChannel
);

. "$PSScriptRoot\managerScriptsLib.ps1";

$global:PRINTER_MGR_LOCAL_DIR = "$($osdDirs['Root'])\PrinterManager";
$PRINTER_DRIVER_REMOTE_DIR = "$PSScriptRoot\PrinterDrivers";
$LOG_DIR = "$global:PRINTER_MGR_LOCAL_DIR\Logs";
$LOG_FILE_NAME = "PrinterManager.$((Get-Date).ToString('YYYY-mm-dd_HH.MM.SS.log'))";
$LOG_FILE_PATH = "$LOG_DIR\$LOG_FILE_NAME";

if (-not (Test-Path -Path $LOG_DIR -ErrorAction SilentlyContinue)) {
  mkdir "$LOG_DIR" | Out-Null;
}
Start-Transcript -Path $LOG_FILE_PATH;

try {

  ## Get logged on user based on event of eventId provided
  $explorerProcesses = @();
  if ($EventRecordId) {
    $eventUser = $null;
    try {
      $eventUser = Get-UserFromEvent -EventRecordId $EventRecordId -EventChannel $EventChannel;
    } catch [EventInvalidLogonType] {
      Write-Output "Logon type for event is not interactive or terminal services. Will not run.";
      exit;
    } catch [EventNotFound] {
      Write-Output "Did not find specified logon event.";
      exit;
    }

    ## If the user is some kind of system type account then do not run
    if (($eventUser.UserName -match '^(DWM-[0-9]+|UMFD-[0-9]+|(LOCAL|NETWORK) SERVICE)' -and $eventUser.DomainName -like $env:COMPUTERNAME) -or ($eventUser.UserName -like 'SYSTEM' -and $eventUser.DomainName -like 'NT AUTHORITY')) {
      Write-Output "User is a system type user. Will not run.";
      exit;
    }

    $explorerProcesses += Get-Process -Name explorer -IncludeUserName |
      Where-Object -FilterScript { $_.UserName -like "$($eventUser.DomainName)\$($eventUser.UserName)" }
  } else {
    $explorerProcesses += $explorerProcesses += Get-Process -Name explorer -IncludeUserName;
  }

  ## Install printer drivers
  foreach ($dir in $PRINTER_DRIVER_REMOTE_DIR) {
    foreach ($driverScript in (Get-ChildItem -Path $dir.FullName -Filter *.ps1 | Select-Object -ExpandProperty FullName)) {
      Write-Output "Running script '$driverScript'";
      . "$driverScript";
    }
  }

  $managedPrinters = @{};
  

} finally {
  Stop-Transcript;
}
