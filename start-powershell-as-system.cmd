powershell.exe -Command "Start-Process -Verb RunAs -FilePath 'C:\Program Files\Sysinternals\PsExec64.exe' -ArgumentList @('-s','-i','powershell.exe','-NoExit','-Command','cd %~dp0')"