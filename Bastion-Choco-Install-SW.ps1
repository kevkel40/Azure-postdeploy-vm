<#
	Installs packages if chocolatey is installed
#>
#allow installs to work
try{Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction stop}catch{exit 1}

#check chocolatey installed
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

$packages = @("googlechrome","git","visualstudiocode","postman","powershell-core","azure-cli","microsoftazurestorageexplorer","7-zip")

switch( hostname ){
	{$_ -match "datavm"}{
		write-host "datavm detected, selecting software" -Foregroundcolor Green
		#Data team software
			$packages += "azure-data-studio"
	}
	{$_ -match "qavm"}{
		write-host "qavm detected, selecting software" -Foregroundcolor Green
		#QA team software
			$packages += "db-visualizer"
			$packages += "intellijidea-community"
			$packages += "maven"
	}
	{$_ -match "webvm"}{
		write-host "webvm detected, selecting software" -Foregroundcolor Green
		#Web/API team software
			$packages += "stunnel"
			$packages += "cosmosdbexplorer"
			$packages += "jdk8"
			#maven --version=3.6.3 ?
		#redis cli
		$url = "https://github.com/microsoftarchive/redis/releases/download/win-3.2.100/Redis-x64-3.2.100.msi"
		$fileName = $url.split("/")[-1]
		$Outfile = "$($env:TEMP)\$($fileName)"
		Write-Host "Downloading $($fileName)..." -Foregroundcolor Yellow
		Invoke-WebRequest -Uri $url -Outfile $Outfile
		if(Test-Path $Outfile){
		  Write-Host "Installing $($fileName)..." -Foregroundcolor Yellow
		 $arguments = @("/I $($Outfile)", "/quiet")
		 Start-Process msiexec.exe -ArgumentList $arguments -Wait
		}
	}
	{$_ -match "infravm"}{
		write-host "Infravm detected, selecting software" -Foregroundcolor Green
		#Infra team software
		$packages += "notepadplusplus"
	}
}

#install all the selected packages

foreach($package in $packages){
	$arguments = @("install $($package) -y")
	Start-Process choco.exe -ArgumentList $arguments -Wait
}

#install windows subsystem for linux
Write-Verbose "Checking if Windows Linux subsystem is installed"
if((wsl --status).count -gt 50 ){
  Write-Host "Installing Windows subsystem for Linux" -Foregroundcolor Yellow
  wsl --install
}else{
  Write-Verbose "Windows subsystem for Linux already installed"
}

try{Set-MpPreference -ScanParameters FullScan -ScanScheduleDay Everyday -DisableIntrusionPreventionSystem 0 -DisableRealtimeMonitoring 0 -DisableEmailScanning 0 -DisableRemovableDriveScanning 0 -EnableNetworkProtection Enabled -EnableControlledFolderAccess Enabled -ScanScheduleTime 12:00 -RemediationScheduleTime 13:00 -SignatureScheduleTime 11:00  -ExclusionPath "$($env:USERPROFILE)\Documents\PowerShell" -verbose -ErrorAction stop}catch{exit 1}

Exit 0