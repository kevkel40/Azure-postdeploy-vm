trap
{
    Write-Host $PSItem.ToString() -foregroundcolor red
}
try{Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction stop}catch{exit 1}

try{$ChocoInstalled = Get-ChildItem C:\ProgramData\chocolatey\choco.exe -erroraction stop}catch{$ChocoInstalled = $false}
if($ChocoInstalled){
	$ChocoVersion = $ChocoInstalled.VersionInfo.ProductVersionRaw
	#get
	$url = 'https://github.com/chocolatey/choco/releases/latest'
	$realTagUrl = (([System.Net.WebRequest]::Create($url)).GetResponse()).ResponseUri.OriginalString
	[system.version]$WebVersion = $realTagUrl.split('/')[-1].Trim('v')

	if($ChocoVersion -ge $WebVersion){
		Write-Host "Choco version installed is latest" -foregroundcolor green
	}else{
		Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	}
}else{
	Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}
try{Set-MpPreference -ScanParameters FullScan -ScanScheduleDay Everyday -DisableIntrusionPreventionSystem 0 -DisableRealtimeMonitoring 0 -DisableEmailScanning 0 -DisableRemovableDriveScanning 0 -EnableNetworkProtection Enabled -EnableControlledFolderAccess Enabled -ScanScheduleTime 12:00 -RemediationScheduleTime 13:00 -SignatureScheduleTime 11:00  -ExclusionPath "$($env:USERPROFILE)\Documents\PowerShell" -verbose -ErrorAction stop}catch{exit 1}
exit 0
