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
        Write-Host "Testing $($Hive):\$($CurrentPath)"
        $testpath = Test-Path -path "$($Hive):\$($CurrentPath)" -erroraction stop
        if(!$testpath){
          Write-Host "Reg path $($Hive):\$($CurrentPath) not found, attempting to create $($Item) at $($Hive):\$($OldPath)"
          New-Item -Path "$($Hive):\$($OldPath)\" -Name $Item
        }
      }catch{
        Write-Host "Failed at $($Hive):\$($CurrentPath), attempting to create $($Item) at $($Hive):\$($OldPath)"
        New-Item -Path "$($Hive):\$($OldPath)\" -Name $Item
      } 
      $ItemNumber ++ 
    }

    try{
			#Get-Item -path "$($Hive):\$($Path)\$($Name)" -erroraction stop
			if((Get-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name -erroraction stop).$Name -eq $Value){
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
			try{
        Set-ItemProperty -Path "$($Hive):\$($Path)" -Name $Name -Value $Value -Type $Type -ErrorAction Stop
      }catch{

      }
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
#NTLM
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
	"Name" = "NtlmMinClientSec"
	"Type" = "REG_DWORD"
	"Value" = 20080000
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
	"Name" = "NtlmMinServerSec"
	"Type" = "REG_DWORD"
	"Value" = 20080000
}
$RegSettings += $RegSetting

#RDS
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
	"Name" = "DisablePasswordSaving"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

#credentials delegation
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows\CredentialsDelegation"
	"Name" = "AllowDefCredentialsWhenNTLMOnly"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

#Microsoft data harvest
# Do not show feedback notifications
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows\DataCollection"
	"Name" = "DoNotShowFeedbackNotifications"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

#WindowsDefender
# Scan removable drives
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows Defender\Scan"
	"Name" = "DisableRemovableDriveScanning"
	"Type" = "REG_DWORD"
	"Value" = 0
}
$RegSettings += $RegSetting

#Prohibit unicast response to multicast or broadcast requests
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
	"Name" = "DisableUnicastResponsesToMulticastBroadcast"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
	"Name" = "DisableUnicastResponsesToMulticastBroadcast"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
	"Name" = "DisableUnicastResponsesToMulticastBroadcast"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
	"Name" = "DisableUnicastResponsesToMulticastBroadcast"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

#Enable firewall
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
	"Name" = "EnableFirewall"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
	"Name" = "EnableFirewall"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
	"Name" = "EnableFirewall"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
	"Name" = "EnableFirewall"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

#Set firewall outbound action
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
	"Name" = "DefaultOutboundAction"
	"Type" = "REG_DWORD"
	"Value" = 0
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
	"Name" = "DefaultOutboundAction"
	"Type" = "REG_DWORD"
	"Value" = 0
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
	"Name" = "DefaultOutboundAction"
	"Type" = "REG_DWORD"
	"Value" = 0
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
	"Name" = "DefaultOutboundAction"
	"Type" = "REG_DWORD"
	"Value" = 0
}
$RegSettings += $RegSetting

#Set firewall inbound action
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\WindowsFirewall\PrivateProfile"
	"Name" = "DefaultInboundAction"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
	"Name" = "DefaultInboundAction"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
	"Name" = "DefaultInboundAction"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
	"Name" = "DefaultInboundAction"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

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

#Enable SMB2 signing
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
	"Name" = "EnableSecuritySignature"
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

#No cached logons
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Microsoft\Windows Nt\CurrentVersion\Winlogon"
	"Name" = "CachedLogonsCount"
	"Type" = "REG_SZ"
	"Value" = 0
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_CURRENT_USER"
	"Path" = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
	"Name" = "NoDriveTypeAutoRun"
	"Type" = "REG_DWORD"
	"Value" = 255
}

$RegSettings += $RegSetting


######################################
Clear-Host
Write-Host "Setting reg keys" -Foregroundcolor Yellow

foreach($Item in $RegSettings){
	set-reg_keys -RegSet $Item
}

#default user setting change
$arguments = "load HKLM\ntuser.dat c:\users\default\ntuser.dat"
Start-Process reg.exe -ArgumentList $arguments -Wait

$arguments = "add HKLM\ntuser.dat\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
Start-Process reg.exe -ArgumentList $arguments -Wait

$arguments = "add HKLM\ntuser.dat\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255"
Start-Process reg.exe -ArgumentList $arguments -Wait

$arguments = "unload HKLM\ntuser.dat"
Start-Process reg.exe -ArgumentList $arguments -Wait


# $RegSetting = @{
# 	"Hive" = "HKEY_CURRENT_USER"
# 	"Path" = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
# 	"Name" = "NoDriveTypeAutoRun"
# 	"Type" = "REG_DWORD"
# 	"Value" = 255
# }

#$arguments = "add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255"
#Start-Process reg.exe -ArgumentList $arguments -Wait


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
Write-Host "Setting Windows Defender preferences" -Foregroundcolor Yellow
Set-MpPreference -ScanParameters FullScan -ScanScheduleDay Everyday -DisableIntrusionPreventionSystem 0 -DisableRealtimeMonitoring 0 -DisableEmailScanning 0 -DisableRemovableDriveScanning 0 -EnableNetworkProtection Enabled -EnableControlledFolderAccess Enabled -ScanScheduleTime 12:00 -RemediationScheduleTime 13:00 -SignatureScheduleTime 11:00  -verbose
Write-Host "Downloading Policies"
Invoke-WebRequest -Uri 'https://github.com/LeighdePaor/Azure-postdeploy-vm/raw/main/GroupPolicy.zip' -OutFile "$($env:TEMP)\GroupPolicy.zip"
Write-Host "Deploying Policies"
Expand-Archive -Path "$($env:TEMP)\GroupPolicy.zip" -DestinationPath "C:\Windows\System32\GroupPolicy" -force
gpupdate /force
Write-Host "Running Windows updates, system may reboot" -Foregroundcolor Yellow
Get-WindowsUpdate -Install -confirm:$false -forceinstall -autoreboot -acceptall
