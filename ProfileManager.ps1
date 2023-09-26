##
##  It is important that this logon script be executed using Task Scheduleder triggered by EventID 4624
##    (Logon) in Security log. This way this script can be given a reference to the EventId that
##    triggered it to detemine which user just logged on.
##
param(
  [String]$EventRecordId,
  [String]$EventChannel
);

## ProfileManager directories
$PROFILE_MGR_LOCAL_DIR = "$env:ProgramData\osd\ProfileManager";
$PROFILE_MGR_REMOTE_DIR = "$PSScriptRoot";
$LOG_DIR = "$PROFILE_MGR_LOCAL_DIR\Logs";
$LOG_FILE_NAME = "ProfileManager.$((Get-Date).ToString('YYYY-mm-dd_HH.MM.SS.log'))";
$LOG_FILE_PATH = "$LOG_DIR\$LOG_FILE_NAME";
$PRIVILEGED_SCRIPT_LOCAL_DIR = "$PROFILE_MGR_LOCAL_DIR\Privileged-Scripts";
$PRIVILEGED_SCRIPT_REMOTE_DIR = "$PROFILE_MGR_REMOTE_DIR\Privileged-Scripts";
$USER_SCRIPT_LOCAL_DIR = "$PROFILE_MGR_LOCAL_DIR\User-Scripts";
$USER_SCRIPT_REMOTE_DIR = "$PROFILE_MGR_REMOTE_DIR\User-Scripts";

if (-not $EventRecordId) {
  throw "No EventRecordId passed.";
}

if (-not $EventRecordId) {
  throw "No EventChannel passed.";
}

$logonEvent = Get-WinEvent -FilterXPath "*[System[(EventRecordID='$EventRecordId')]]" -LogName $EventChannel -ErrorAction Continue;
if (-not $logonEvent) {
  throw "Unable to find logon event with RecordID of '$EventRecordId' in '$EventChannel'";
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

## If the user is some kind of system type account then do not run
if (($logonUser -match '^(DWM-[0-9]+|UMFD-[0-9]+|(LOCAL|NETWORK) SERVICE)' -and $logonDomain -like $env:COMPUTERNAME) -or ($logonUser -like 'SYSTEM' -and $logonDomain -like 'NT AUTHORITY')) {
  Write-Output "User is a system type user. Will not run.";
  exit;
}

## If the logon type isn't interactive or terminal services then do not run
if ($logonType -notmatch '^(2|1[01])$') {
  Write-Output "Logon type is not interactive or terminal services. Will not run.";
  exit;
}

if (-not (Test-Path -Path $LOG_DIR -ErrorAction SilentlyContinue)) {
  mkdir "$LOG_DIR" | Out-Null;
}
Start-Transcript -Path $LOG_FILE_PATH;

try {

  foreach ($dir in @($PRIVILEGED_SCRIPT_LOCAL_DIR, $USER_SCRIPT_LOCAL_DIR)) {
    if (-not (Test-Path -Path $dir -ErrorAction SilentlyContinue)) {
      mkdir "$dir" | Out-Null;
    }
  }

  ## If the remote directories are available update the local directories
  if (Test-Path -Path $PRIVILEGED_SCRIPT_REMOTE_DIR -ErrorAction SilentlyContinue) {
    Get-ChildItem -Path $PRIVILEGED_SCRIPT_LOCAL_DIR | Remove-Item -Recurse -Confirm:$false -Force;
    Get-ChildItem -Path $PRIVILEGED_SCRIPT_REMOTE_DIR | Copy-Item -Destination $PRIVILEGED_SCRIPT_LOCAL_DIR -Recurse -Force -Confirm:$false;
  }

  if (Test-Path -Path $USER_SCRIPT_REMOTE_DIR -ErrorAction SilentlyContinue) {
    Get-ChildItem -Path $USER_SCRIPT_LOCAL_DIR | Remove-Item -Recurse -Confirm:$false -Force;
    Get-ChildItem -Path $USER_SCRIPT_REMOTE_DIR | Copy-Item -Destination $USER_SCRIPT_LOCAL_DIR -Recurse -Force -Confirm:$false;
  }

} finally {
  Stop-Transcript;
}
