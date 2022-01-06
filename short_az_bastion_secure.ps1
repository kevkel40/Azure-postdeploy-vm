<#
    .SYNOPSIS
    Configure required security on bastion vm's

    .DESCRIPTION
	Set a selection of security specific registry keys
	Rename Guest Account
	Set network profile to public
	Add Nuget
	Set PSGallery as trusted repository
	Install Windows Update PowerShell module
	Schedule Windows updates to run on system boot
	Set Windows Defender preferences: 
		FullScan:Everyday, -DisableIntrusionPreventionSystem 0, -DisableRealtimeMonitoring 0, -DisableEmailScanning 0,
		-DisableRemovableDriveScanning 0, -EnableNetworkProtection Enabled, -EnableControlledFolderAccess Enabled
	Run Windows updates, system may reboot
    .OUTPUTS
    Screen as collection of tabulated text

    .EXAMPLE
    PS> .\Bastion-SW-Install.ps1
    
#>
#post deploy commands

######################################
function set-reg_keys{
  Param(
    #Parameter that can be modified to control which resource groups this runs against
    [Parameter(
        Mandatory=$false,
        ValueFromPipeline=$true,
        HelpMessage="Enter one or more Windows registry setting as a hashtable object."
        )
    ]
    [System.Collections.Hashtable]
    $RegSet = $null
  )
	if(!($RegSet.count -eq 5)){
		Write-Host "RegSet parameter requires 5 key pairs in the hashtable: Path, Name, Type, Value, Hive" -ForegroundColor Red
    break
	}else{
		switch($RegSet.Hive){
			{$_ -eq "HKEY_LOCAL_MACHINE"}{$Hive = "HKLM"}
			{$_ -eq "HKEY_CURRENT_USER"}{$Hive = "HKCU"}
			default {$Hive = $false; break}
		}
		switch($RegSet.Type){
			{$_ -eq "REG_SZ"}{$Type = "String"}
			{$_ -eq "REG_EXPAND_SZ"}{$Type = "ExpandString"}
			{$_ -eq "REG_BINARY"}{$Type = "Binary"}
			{$_ -eq "REG_DWORD"}{$Type = "DWord"}
			{$_ -eq "REG_MULTI_SZ"}{$Type = "MultiString"}
			{$_ -eq "REG_QWORD"}{$Type = "Qword"}
			default {$Type = $false; break}
		}
		if(($Hive -eq $false) -or ($Type -eq $false)){
			Write-Host "Error with type or hive specified, cannot continue" -Foregroundcolor Red
			break
		}
		[string]$Path = $RegSet.Path
		[string]$Name = $RegSet.Name
		$Value = $RegSet.Value
    #see if reg path works, create if not
    $pathitems = $Path.split("\")
    $CurrentPath = ""
    $ItemNumber = 0
    foreach($Item in $pathitems){
      if($ItemNumber -eq 0){
        $CurrentPath = $Item
      }else{
        $OldPath = $CurrentPath
        $CurrentPath = "$($CurrentPath)\$($Item)"
      }
      try{
        Write-Verbose "Testing $($Hive):\$($CurrentPath)"
        $testpath = Test-Path -path "$($Hive):\$($CurrentPath)" -erroraction stop
        if(!$testpath){
          Write-Host "Reg path $($Hive):\$($CurrentPath) not found, attempting to create $($Item) at $($Hive):\$($OldPath)" -ForegroundColor Red
          New-Item -Path "$($Hive):\$($OldPath)\" -Name $Item
        }
      }catch{
        Write-Host "Failed at $($Hive):\$($CurrentPath), attempting to create $($Item) at $($Hive):\$($OldPath)" -ForegroundColor Red
        New-Item -Path "$($Hive):\$($OldPath)\" -Name $Item
      } 
      $ItemNumber ++ 
    }

    try{
			#Get-Item -path "$($Hive):\$($Path)\$($Name)" -erroraction stop
			if((Get-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name -erroraction stop).$Name -eq $Value){
  			Write-Verbose "$($Name) is already set to $($Value), no further action required."
			}else{
				Set-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name -Value $Value -Type $Type
				if((Get-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name).$Name -eq $Value){
					Write-Verbose "$($Name) succesfully set to $($Value), no further action required."
				}else{
					Write-Host "Error setting $($Hive):\$($Path)\$($Name) to $($Value), please remediate." -Foregroundcolor Red
				}
			}
		}catch{
			Write-Host "Item $($Name) does not exist at $($Hive):\$($Path), attempting to create"
			try{
        Set-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name -Value $Value -Type $Type -ErrorAction Stop
      }catch{

      }
			if((Get-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name).$Name -eq $Value){
				Write-Verbose "$($Name) succesfully set to $($Value), no further action required."
			}else{
				Write-Host "Error setting $($Hive):\$($Path)\$($Name) to $($Value), please remediate." -Foregroundcolor Red
			}
		}		
	}
}

function Get-NugetVersion {
  Param(
    #Parameter that can be modified to control which resource groups this runs against
    [Parameter(
        Mandatory=$true,
        HelpMessage="Enter the version of nuget installed as a four part system version object: Major Minor Build Revision"
        )
    ]
    [Microsoft.PackageManagement.Internal.Utility.Versions.FourPartVersion]
    $installed,

    [Parameter(
      Mandatory=$false,
      HelpMessage="Enter the lowest version of nuget required as a four part string: e.g. '2.8.5.201'"
      )
    ]
    [Microsoft.PackageManagement.Internal.Utility.Versions.FourPartVersion]
    $required = "2.8.5.201"
  )

  $returnvalue = $false

  #Major Minor Build Revision
  switch($installed){
    {$_ -ge $required}{
      $returnvalue = $true
      break
    }
    {$_ -lt $required}{
      $returnvalue = $false
      break
    }
    {$_ -gt $required}{
      $returnvalue = $true
      break
    }
    default {$returnvalue = $false}

  }
  return $returnvalue
}

######################################

#Security Baseline Config based on https://docs.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows

#test for file locally, download from github if not found

$URI = 'https://raw.githubusercontent.com/LeighdePaor/Azure-postdeploy-vm/main/regsettings.json'

if(Test-Path ".\regsettings.json"){
  $RegSettings = Get-Content .\regsettings.json | convertfrom-json
}else{
  $RegSettings = Invoke-WebRequest -Uri $URI | convertfrom-json
}

######################################
Clear-Host
Write-Host "Setting reg keys" -Foregroundcolor Yellow

foreach($Item in $RegSettings.regsetting){
	set-reg_keys -RegSet $Item
}

#default user setting change
$arguments = "load HKLM\ntuser.dat c:\users\default\ntuser.dat"
Start-Process reg.exe -ArgumentList $arguments -Wait

$arguments = "add HKLM\ntuser.dat\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /f"
Start-Process reg.exe -ArgumentList $arguments -Wait

$arguments = "add HKLM\ntuser.dat\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f"
Start-Process reg.exe -ArgumentList $arguments -Wait

$arguments = "unload HKLM\ntuser.dat"
Start-Process reg.exe -ArgumentList $arguments -Wait

######################################
Write-Verbose "Ensuring SMB1 is off"
if((Get-WindowsOptionalFeature -Online -FeatureName smb1protocol).state -notlike "DisabledWithPayloadRemoved"){Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -verbose}
#generate random 16-32 character name for guest account
$Array = @();$Array+=@(48..57);$array+=@(65..90);$array+=@(97..122)
$alphanumericstring = ""
for ($i=1; $i -le (get-random @(16..32)); $i++) {$alphanumericstring += [char](get-random $array)}
Write-Host "Renaming Guest Account" -Foregroundcolor Green
wmic useraccount where "name='Guest'" rename $alphanumericstring

Write-Verbose "Setting network profile to public"
Set-NetConnectionProfile -InterfaceAlias Ethernet -NetworkCategory "Public" -verbose

Write-Verbose "Adding Nuget"
try{
  $Nuget = Get-PackageProvider -name NuGet -ErrorAction stop
  if(!(Get-NugetVersion -installed ($Nuget.Version) -required "2.8.5.201")){
    Write-Host "NuGet version is too low, attempting to set higher" -ForegroundColor Red
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
  }
}catch{
  Write-Host "Error getting or adding Nuget as a package provider, trying to add version 2.8.5.201 or higher" -ForegroundColor Red
  Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
}


Write-Verbose "Getting PSGallery trusted repository status"
try{
  $PSGallery = Get-PSRepository -name PSGallery -ErrorAction stop
  if(!($PSGallery.InstallationPolicy -like "Trusted")){
    Write-Host "PSGallery.InstallationPolicy is not set to trusted, attempting to set" -ForegroundColor Red
    Set-PSRepository -name PSGallery -InstallationPolicy trusted -verbose
  }
}catch{
  Write-Host "Error recovering PSGallery as a PS Repository" -ForegroundColor Red
}

if((get-module -ListAvailable |Select-Object Name).Name -contains "PSWindowsUpdate"){
  Write-Verbose "PSWindowsUpdate PowerShell module detected as installed"
}else{
  Write-Host "Installing Windows Update PowerShell module" -Foregroundcolor Green
  Install-Module -Name PSWindowsUpdate -verbose
}

Write-Host "Setting Windows Defender preferences" -Foregroundcolor Green
Set-MpPreference -ScanParameters FullScan -ScanScheduleDay Everyday -DisableIntrusionPreventionSystem 0 -DisableRealtimeMonitoring 0 -DisableEmailScanning 0 -DisableRemovableDriveScanning 0 -EnableNetworkProtection Enabled -EnableControlledFolderAccess Enabled -ScanScheduleTime 12:00 -RemediationScheduleTime 13:00 -SignatureScheduleTime 11:00  -verbose
Write-Host "Setting Windows Defender attack surface reduction rules" -Foregroundcolor Green
#Configure the following attack surface reduction rules: 
#ref https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide
	# 'Block executable content from email client and webmail' = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
	# 'Block untrusted and unsigned processes that run from USB' = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
	# 'Block credential stealing from the Windows local security authority subsystem (lsass.exe)' = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
	# 'Block all Office applications from creating child processes' = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
	# 'Block JavaScript or VBScript from launching downloaded executable content' = "d3e037e1-3eb8-44c8-a917-57927947596d"
	# 'Block execution of potentially obfuscated scripts ' = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
	# 'Block Office applications from creating executable content' = "3b576869-a4ec-4529-8536-b80a7769e899"
	# 'Block Office communication application from creating child processes' = "26190899-1602-49e8-8b27-eb1d0a1ce869"
	# 'Block Win32 API calls from Office macros' = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
	# 'Block Adobe Reader from creating child processes' = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
	# 'Block Office applications from injecting code into other processes' = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc842"
$Values = @("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550","b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4","9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2","d4f940ab-401b-4efc-aadc-ad5f3c50688a","d3e037e1-3eb8-44c8-a917-57927947596d","5beb7efe-fd9a-4556-801d-275e5ffc04cc","3b576869-a4ec-4529-8536-b80a7769e899","26190899-1602-49e8-8b27-eb1d0a1ce869","92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b","7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c","75668c1f-73b5-4cf0-bb93-3ecf5cb7cc842")
Set-MpPreference -AttackSurfaceReductionRules_Actions Enabled, Enabled, Enabled, Enabled, Enabled, Enabled, Enabled, Enabled, Enabled, Enabled, Enabled -AttackSurfaceReductionRules_Ids $values
Write-Host "Downloading Policies" -Foregroundcolor Green
Invoke-WebRequest -Uri 'https://github.com/LeighdePaor/Azure-postdeploy-vm/raw/main/GroupPolicy.zip' -OutFile "$($env:TEMP)\GroupPolicy.zip"
Write-Host "Deploying Policies" -Foregroundcolor Green
Expand-Archive -Path "$($env:TEMP)\GroupPolicy.zip" -DestinationPath "C:\Windows\System32\GroupPolicy" -force
gpupdate /force
#Windows Defender signature updates
$arguments = "-removedefinitions -dynamicsignatures"
Start-Process "$($env:ProgramFiles)\Windows Defender\MpCmdRun.exe" -ArgumentList $arguments -Wait
$arguments = "-SignatureUpdate"
Start-Process "$($env:ProgramFiles)\Windows Defender\MpCmdRun.exe" -ArgumentList $arguments -Wait
#update Azure guest agent status
$arguments = "ADD HKLM\SOFTWARE\Qualys\QualysAgent\ScanOnDemand\Vulnerability /v ScanOnDemand /t REG_DWORD /d 1 /f"
Start-Process reg.exe -ArgumentList $arguments -Wait
#install windows subsystem for linux
Write-Host "Installing Windows Linux subsystem" -Foregroundcolor Yellow
if((wsl --status).count -lt 50 ){
  Write-Host "Installing Windows subsystem for Linux" -Foregroundcolor Yellow
  wsl --install
}else{
  Write-Host "Windows subsystem for Linux already installed" -Foregroundcolor green
}
#install windows updates
Write-Host "Running Windows updates, system may reboot" -Foregroundcolor Yellow
Get-WindowsUpdate -Install -confirm:$false -forceinstall -autoreboot -acceptall
