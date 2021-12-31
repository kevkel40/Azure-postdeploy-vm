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
######################################

$RegSettings = @()
#undock stupid recommendation in Azure vm!
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
	"Name" = "UndockWithoutLogon"
	"Type" = "REG_DWORD"
	"Value" = 0
}
$RegSettings += $RegSetting

#software certificate restriction policies
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
	"Name" = "AuthenticodeEnabled"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

#log file sizes
# application
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows\EventLog\Application"
	"Name" = "MaxSize"
	"Type" = "REG_DWORD"
	"Value" = 196608
}
$RegSettings += $RegSetting

# system
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows\EventLog\System"
	"Name" = "MaxSize"
	"Type" = "REG_DWORD"
	"Value" = 196608
}
$RegSettings += $RegSetting

# security
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows\EventLog\Security"
	"Name" = "MaxSize"
	"Type" = "REG_DWORD"
	"Value" = 196608
}
$RegSettings += $RegSetting

# setup
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows\EventLog\Setup"
	"Name" = "MaxSize"
	"Type" = "REG_DWORD"
	"Value" = 196608
}
$RegSettings += $RegSetting

#NTLM versions
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Netlogon\Parameters"
	"Name" = "AllowNT4Crypto"
	"Type" = "REG_DWORD"
	"Value" = 0
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "System\CurrentControlSet\Control\Lsa"
	"Name" = "LmCompatibilityLevel"
	"Type" = "REG_DWORD"
	"Value" = 5
}
$RegSettings += $RegSetting

#Windows Updates
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
	"Name" = "SetDisablePauseUXAccess"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

#No to Cortana
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\Windows\Windows Search"
	"Name" = "AllowCortanaAboveLock"
	"Type" = "REG_DWORD"
	"Value" = 0
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SOFTWARE\Policies\Microsoft\Windows\Windows Search"
	"Name" = "AllowCortana"
	"Type" = "REG_DWORD"
	"Value" = 0
}
$RegSettings += $RegSetting

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

#app credential entry
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Microsoft\Windows\CurrentVersion\Policies\CredUI"
	"Name" = "EnableSecureCredentialPrompting"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

#credentials reveal
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows\CredUI"
	"Name" = "DisablePasswordReveal"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

#stupid questions blocking
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows\System"
	"Name" = "NoLocalPasswordResetQuestions"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

#app notificatio0ns on lock screen (don't ask!)
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows\System"
	"Name" = "DisableLockScreenAppNotifications"
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

# minimise telemetry colection
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows\DataCollection"
	"Name" = "AllowTelemetry"
	"Type" = "REG_DWORD"
	"Value" = 0
}
$RegSettings += $RegSetting

#Google location harvest
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Google\Chrome"
	"Name" = "DefaultGeolocationSetting"
	"Type" = "REG_DWORD"
	"Value" = 2
}
$RegSettings += $RegSetting

#WindowsDefender
# Spynet
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows Defender\Spynet"
	"Name" = "SubmitSamplesConsent"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows Defender\Spynet"
	"Name" = "SpynetReporting"
	"Type" = "REG_DWORD"
	"Value" = 1
}
$RegSettings += $RegSetting

$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows Defender\Spynet"
	"Name" = "DisableBlockAtFirstSeen"
	"Type" = "REG_DWORD"
	"Value" = 0
}
$RegSettings += $RegSetting

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

#Turn off multicast name resolution
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "Software\Policies\Microsoft\Windows NT\DNSClient"
	"Name" = "EnableMulticast"
	"Type" = "REG_DWORD"
	"Value" = 0
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

#Clear pagefile on shutdown
$RegSetting = @{
	"Hive" = "HKEY_LOCAL_MACHINE"
	"Path" = "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
	"Name" = "ClearPageFileAtShutdown"
	"Type" = "REG_DWORD"
	"Value" = 1
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

$arguments = "add HKLM\ntuser.dat\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /f"
Start-Process reg.exe -ArgumentList $arguments -Wait

$arguments = "add HKLM\ntuser.dat\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f"
Start-Process reg.exe -ArgumentList $arguments -Wait

$arguments = "unload HKLM\ntuser.dat"
Start-Process reg.exe -ArgumentList $arguments -Wait

######################################
Write-Host "Ensuring SMB1 is off" -Foregroundcolor Green
if((Get-WindowsOptionalFeature -Online -FeatureName smb1protocol).state -notlike "DisabledWithPayloadRemoved"){Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol}
#generate random 16-32 character name for guest account
$Array = @();$Array+=@(48..57);$array+=@(65..90);$array+=@(97..122)
$alphanumericstring = ""
for ($i=1; $i -le (get-random @(16..32)); $i++) {$alphanumericstring += [char](get-random $array)}
Write-Host "Renaming Guest Account" -Foregroundcolor Green
wmic useraccount where "name='Guest'" rename $alphanumericstring
Write-Host "Setting network profile to public" -Foregroundcolor Green
Set-NetConnectionProfile -InterfaceAlias Ethernet -NetworkCategory "Public"
Write-Host "Adding Nuget" -Foregroundcolor Green
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
Write-Host "Setting PSGallery as trusted repository" -Foregroundcolor Green
Set-PSRepository -name PSGallery -InstallationPolicy trusted
Write-Host "Installing Windows Update PowerShell module" -Foregroundcolor Green
Install-Module -Name PSWindowsUpdate
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
Write-Host "Running Windows updates, system may reboot" -Foregroundcolor Yellow
Get-WindowsUpdate -Install -confirm:$false -forceinstall -autoreboot -acceptall
