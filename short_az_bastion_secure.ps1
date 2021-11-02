<#
    .SYNOPSIS
    Configure required security on bastion vm's

    .DESCRIPTION
	Set a selection of security specific registry keys
	Rename Guest Account
	Set netowrk profile to public
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
		Write-Host "RegSet parameter requires 5 key pairs in the hashtable: Path, Name, Type, Value, Hive"
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
		$Path = $RegSet.Path
		$Name = $RegSet.Name
		$Value = $RegSet.Value
		#set-location -path "$($Hive):\$($Path)"
		try{
			Get-Item -path "$($Hive):\$($Path)\$($Name)" -erroraction stop
			if((Get-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name).$Name -eq $Value){
				Write-Host "$($Name) is already set to $($Value), no further action required."
			}else{
				Set-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name -Value $Value -Type $Type
				if((Get-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name).$Name -eq $Value){
					Write-Host "$($Name) succesfully set to $($Value), no further action required." -Foregroundcolor Green
				}else{
					Write-Host "Error setting $($Hive):\$($Path)\$($Name) to $($Value), please remediate." -Foregroundcolor Red
				}
			}
		}catch{
			Write-Host "Item $($Name) does not exist at $($Hive):\$($Path), attempting to create"
			Set-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name -Value $Value -Type $Type
			if((Get-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name).$Name -eq $Value){
				Write-Host "$($Name) succesfully set to $($Value), no further action required." -Foregroundcolor Green
			}else{
				Write-Host "Error setting $($Hive):\$($Path)\$($Name) to $($Value), please remediate." -Foregroundcolor Red
			}
		}		
	}
}
######################################

$RegSettings = @()

#turn off autoplay
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
	"Name" = "NoDriveTypeAutoRun"
	"Type" = "REG_DWORD"
	"Value" = 255
}
$RegSettings += $RegSetting


#turn off autoplay for nonvolume devices
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
	"Name" = "NoAutoplayfornonVolume"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

#don't cache logon credentials
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Microsoft\Windows Nt\CurrentVersion\Winlogon"
	"Name" = "CachedLogonsCount"
	"Type" = "REG_SZ"
	"Value" = 0
}
$RegSettings += $RegSetting

#Restrict Null Session Access
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
	"Name" = "RestrictNullSessAccess"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

#Require SMB2 signing
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
	"Name" = "RequireSecuritySignature"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SYSTEM\CurrentControlSet\Services\LanmanWorkStation\Parameters"
	"Name" = "RequireSecuritySignature"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

#restrict anonymous access
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SYSTEM\CurrentControlSet\Control\Lsa"
	"Name" = "restrictanonymoussam"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SYSTEM\CurrentControlSet\Control\Lsa"
	"Name" = "restrictanonymous"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

#install software based on VM name HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Microsoft\Windows\CurrentVersion\RunOnce"
	"Name" = "InstallSoftware"
	"Type" = "REG_SZ"
	"Value" = "IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/LeighdePaor/Azure-postdeploy-vm/main/Bastion-SW-Install.ps1')"
}
#$RegSettings += $RegSetting
######################################
Clear-Host
Write-Host "Setting reg keys" -Foregroundcolor Yellow

foreach($Item in $RegSettings){
	set-reg_keys -RegSet $Item
}
######################################
Write-Host "Ensuring SMB1 is off" -Foregroundcolor Yellow
if((Get-WindowsOptionalFeature -Online -FeatureName smb1protocol).state -notlike "DisabledWithPayloadRemoved"){Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol}
#generate random 16-32 character name for guest account
$Array = @();$Array+=@(48..57);$array+=@(65..90);$array+=@(97..122)
$alphanumericstring = ""
for ($i=1; $i -le (get-random @(16..32)); $i++) {$alphanumericstring += [char](get-random $array)}
Write-Host "Renaming Guest Account" -Foregroundcolor Yellow
wmic useraccount where "name='Guest'" rename $alphanumericstring
Write-Host "Setting network profile to public" -Foregroundcolor Yellow
Set-NetConnectionProfile -InterfaceAlias Ethernet -NetworkCategory "Public"
Write-Host "Adding Nuget" -Foregroundcolor Yellow
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
Write-Host "Setting PSGallery as trusted repository" -Foregroundcolor Yellow
Set-PSRepository -name PSGallery -InstallationPolicy trusted
Write-Host "Installing Windows Update PowerShell module" -Foregroundcolor Yellow
Install-Module -Name PSWindowsUpdate
#Write-Host "Scheduling Windows updates to run on system boot" -Foregroundcolor Yellow
#$trigger = New-JobTrigger -AtStartup -RandomDelay 00:00:30
#$ScheduledJobOption = New-ScheduledJobOption -RunElevated
#Register-ScheduledJob -Trigger $trigger -Name WindowsUpdate -ScriptBlock {Get-WindowsUpdate -Install -confirm:$false -forceinstall -autoreboot -acceptall} -ScheduledJobOption $ScheduledJobOption -credential (Get-Credential -message "enter password for scheduled updates command" -username (whoami))
Write-Host "Setting Windows Defender preferences" -Foregroundcolor Yellow
Set-MpPreference -ScanParameters FullScan -ScanScheduleDay Everyday -DisableIntrusionPreventionSystem 0 -DisableRealtimeMonitoring 0 -DisableEmailScanning 0 -DisableRemovableDriveScanning 0 -EnableNetworkProtection Enabled -EnableControlledFolderAccess Enabled -verbose
Write-Host "Running Windows updates, system may reboot" -Foregroundcolor Yellow
Get-WindowsUpdate -Install -confirm:$false -forceinstall -autoreboot -acceptall
