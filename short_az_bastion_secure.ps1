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
			break
		}
		$Path = $RegSet.Path
		$Name = $RegSet.Name
		$Value = $RegSet.Value
		try{
			Get-Item -path "$($Hive):\$($Path)\$($Name)" -erroraction stop
			if((Get-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name).$Name -eq $Value){
			}else{
				Set-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name -Value $Value -Type $Type
			}
		}catch{
			Set-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name -Value $Value -Type $Type
		}		
	}
}
$RegSettings = @()
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
	"Name" = "NoDriveTypeAutoRun"
	"Type" = "REG_DWORD"
	"Value" = 255
}
$RegSettings += $RegSetting
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
	"Name" = "NoAutoplayfornonVolume"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Microsoft\Windows Nt\CurrentVersion\Winlogon"
	"Name" = "CachedLogonsCount"
	"Type" = "REG_SZ"
	"Value" = 0
}
$RegSettings += $RegSetting
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
	"Name" = "RestrictNullSessAccess"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting
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

foreach($Item in $RegSettings){
	set-reg_keys -RegSet $Item
}
######################################
if((Get-WindowsOptionalFeature -Online -FeatureName smb1protocol).state -notlike "DisabledWithPayloadRemoved"){Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol}
wmic useraccount where "name='Guest'" rename "GuessThis"
Set-NetConnectionProfile -InterfaceAlias Ethernet -NetworkCategory "Public"
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
Set-PSRepository -name PSGallery -InstallationPolicy trusted
Install-Module -Name PSWindowsUpdate
Set-MpPreference -ScanParameters FullScan -ScanScheduleDay Everyday -DisableIntrusionPreventionSystem 0 -DisableRealtimeMonitoring 0 -DisableEmailScanning 0 -DisableRemovableDriveScanning 0 -EnableNetworkProtection Enabled -EnableControlledFolderAccess Enabled -verbose
Get-WindowsUpdate -Install -confirm:$false -forceinstall -IgnoreReboot -acceptall
