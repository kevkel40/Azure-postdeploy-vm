trap
{
    Write-Host $PSItem.ToString() -foregroundcolor red
}
try{Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction stop}catch{exit 1}
try{get-process | Where-Object{$_.processname -match "chrome"}|stop-process -erroraction silentlycontinue}catch{exit 1}
$arguments = @("/ua", "/installsource scheduler")
Start-Process -filepath "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" -wait -ArgumentList $arguments
try{get-process | Where-Object{$_.processname -match "chrome"}|stop-process -erroraction silentlycontinue}catch{exit 1}
try{Set-MpPreference -ScanParameters FullScan -ScanScheduleDay Everyday -DisableIntrusionPreventionSystem 0 -DisableRealtimeMonitoring 0 -DisableEmailScanning 0 -DisableRemovableDriveScanning 0 -EnableNetworkProtection Enabled -EnableControlledFolderAccess Enabled -ScanScheduleTime 12:00 -RemediationScheduleTime 13:00 -SignatureScheduleTime 11:00  -ExclusionPath "$($env:USERPROFILE)\Documents\PowerShell" -verbose -ErrorAction stop}catch{exit 1}
exit 0