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
    $RegSet = $null
  )
  if(!(($RegSet | Get-Member | Where-Object {$_.MemberType -like "NoteProperty"}).count -eq 6)){
		Write-Host "Cannot process item RegSet parameter requires psobject with 6 NoteProperty items: Path, Name, Type, Value, Hive, Comment" -ForegroundColor Red
    break
	}else{
    $Names = (($RegSet | Get-Member | Where-Object {$_.MemberType -like "NoteProperty"}).name)
    foreach($Name in $names){
      if(!(@("Path", "Name", "Type", "Value", "Hive", "Comment") -contains  $name)){
        Write-Host "Cannot process item RegSet parameter requires psobject with 6 NoteProperty items: Path, Name, Type, Value, Hive, Comment" -ForegroundColor Red
        break
      }else{Write-Verbose "Valid noteproperty field object found"}
    }
		
    switch($RegSet.Hive){
			{$_ -eq "HKEY_LOCAL_MACHINE"}{
        $Hive = "HKLM"
        Write-Verbose "Hive = HKLM"
      }
			{$_ -eq "HKEY_CURRENT_USER"}{
        $Hive = "HKCU"
        Write-Verbose "Hive = HKCU"
      }
			default {
        $Hive = $false
        Write-Host "Error invalid Hive type, should be either HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER" -ForegroundColor Red
        break
      }
		}
		switch($RegSet.Type){
			{$_ -eq "REG_SZ"}{
        $Type = "String"
        Write-Verbose "Data Type = String"
        break
      }
			{$_ -eq "REG_EXPAND_SZ"}{
        $Type = "ExpandString"
        Write-Verbose "Data Type = ExpandString"
        break
      }
			{$_ -eq "REG_BINARY"}{
        $Type = "Binary"
        Write-Verbose "Data Type = Binary"
        break
      }
			{$_ -eq "REG_DWORD"}{
        $Type = "DWord"
        Write-Verbose "Data Type = DWord"
        break
      }
			{$_ -eq "REG_MULTI_SZ"}{
        $Type = "MultiString"
        Write-Verbose "Data Type = MultiString"
        break
      }
			{$_ -eq "REG_QWORD"}{
        $Type = "Qword"
        Write-Verbose "Data Type = QWord"
        break
      }
			default {
        $Type = $false
        Write-Host "Error invalid data type, should be one of REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ or REG_QWORD" -ForegroundColor Red        
        break
      }
		}
		if(($Hive -eq $false) -or ($Type -eq $false)){
			Write-Host "Error with type or hive specified, cannot continue" -Foregroundcolor Red
			break
		}
		[string]$Path = $RegSet.Path
    Write-Verbose "Looking for registry path $($Path)"
		[string]$Name = $RegSet.Name
    Write-Verbose "Looking for registry key $($Name)"
		$Value = $RegSet.Value
    Write-Verbose "Looking for key value $($Value)"
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
          Write-Host "Reg path $($Hive):\$($CurrentPath) not found, attempting to create $($Item) at $($Hive):\$($OldPath)" -ForegroundColor Green
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
				#handle null values
        if($null -eq $Value){
          Clear-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name
        }else{
          Set-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name -Value $Value -Type $Type
        }
        #check result of actions
				if((Get-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name).$Name -eq $Value){
					Write-Verbose "$($Name) succesfully set to $($Value), no further action required."
				}else{
					Write-Host "Error setting $($Hive):\$($Path)\$($Name) to $($Value), please remediate." -Foregroundcolor Red
				}
			}
		}catch{
			Write-Host "Item $($Name) does not exist at $($Hive):\$($Path), attempting to create" -ForegroundColor Green
			try{
				#handle null values
        if($null -eq $Value){
          Clear-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name
        }else{
          Set-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name -Value $Value -Type $Type -ErrorAction Stop
        }
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
  Write-Host "Local copy of regsettings.json found, applying"
  $RegSettings = (Get-Content .\regsettings.json | convertfrom-json).regsetting
}else{
  $RegSettings = (Invoke-WebRequest -Uri $URI -UseBasicParsing | convertfrom-json).regsetting
}

######################################
Clear-Host

#Allow PowerShell Modules install
Set-MpPreference -EnableControlledFolderAccess Disabled

Write-Verbose "Setting reg keys"

foreach($Item in $RegSettings){
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
Write-Verbose "Renaming Guest Account"
wmic useraccount where "name='Guest'" rename $alphanumericstring

Write-Verbose "Setting network profile to public"
Set-NetConnectionProfile -InterfaceAlias Ethernet -NetworkCategory "Public" -verbose

Write-Verbose "Adding Nuget"
try{
  $Nuget = Get-PackageProvider -name NuGet -ErrorAction stop
  if(!(Get-NugetVersion -installed ($Nuget.Version) -required "2.8.5.201")){
    Write-Host "NuGet version is too low, attempting to set higher" -ForegroundColor Green
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
    Write-Host "PSGallery.InstallationPolicy is not set to trusted, attempting to set" -ForegroundColor Green
    Set-PSRepository -name PSGallery -InstallationPolicy trusted -verbose
  }
}catch{
  Write-Host "Error recovering PSGallery as a PS Repository" -ForegroundColor Red
}

if((get-module -ListAvailable |Select-Object Name).Name -contains "PSWindowsUpdate"){
  Write-Verbose "PSWindowsUpdate PowerShell module detected as installed"
}else{
  Write-Verbose "Installing Windows Update PowerShell module"
  Install-Module -Name PSWindowsUpdate -verbose
}

Write-Verbose "Getting and applying Desired State Configuration"
if(Test-Path "$($PSScriptRoot)\SecurityBaselineConfig.ps1"){
  Write-Host "Local copy of SecurityBaselineConfig.ps1 found, applying"
  Invoke-Expression -Command "$($PSScriptRoot)\SecurityBaselineConfig.ps1"
}else{
  Invoke-Expression(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/LeighdePaor/Azure-postdeploy-vm/main/SecurityBaselineConfig.ps1')
}

#allow time for security baseline to apply
Start-Sleep -Seconds 10
Write-Verbose "Setting Windows Defender preferences"
Set-MpPreference -ScanParameters FullScan -ScanScheduleDay Everyday -DisableIntrusionPreventionSystem 0 -DisableRealtimeMonitoring 0 -DisableEmailScanning 0 -DisableRemovableDriveScanning 0 -EnableNetworkProtection Enabled -EnableControlledFolderAccess Enabled -ScanScheduleTime 12:00 -RemediationScheduleTime 13:00 -SignatureScheduleTime 11:00  -ExclusionPath "$($env:USERPROFILE)\Documents\PowerShell" -verbose
Write-Verbose "Setting Windows Defender attack surface reduction rules"
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
#Windows Defender signature updates
Write-Verbose "Forcing Windows Defender to update"
$arguments = "-removedefinitions -dynamicsignatures"
Start-Process "$($env:ProgramFiles)\Windows Defender\MpCmdRun.exe" -ArgumentList $arguments -Wait
$arguments = "-SignatureUpdate"
Start-Process "$($env:ProgramFiles)\Windows Defender\MpCmdRun.exe" -ArgumentList $arguments -Wait
#update Azure guest agent status
Write-Verbose "Forcing Azure Qualys scan agent to update"
$arguments = "ADD HKLM\SOFTWARE\Qualys\QualysAgent\ScanOnDemand\Vulnerability /v ScanOnDemand /t REG_DWORD /d 1 /f"
Start-Process reg.exe -ArgumentList $arguments -Wait
#install windows subsystem for linux
Write-Verbose "Checking if Windows Linux subsystem is installed"
if((wsl --status).count -gt 50 ){
  Write-Host "Installing Windows subsystem for Linux" -Foregroundcolor Yellow
  wsl --install
}else{
  Write-Verbose "Windows subsystem for Linux already installed"
}
#install windows updates
Write-Host "Running Windows updates, system may reboot" -Foregroundcolor Yellow
Get-WindowsUpdate -Install -confirm:$false -forceinstall -autoreboot -acceptall
Write-Host "Running Windows updates, system may reboot" -Foregroundcolor Yellow
