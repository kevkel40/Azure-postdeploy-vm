Configuration SecurityBaselineConfig
{
  param ()
	
	Import-DSCResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	
	Node localhost
	{
		AuditPolicySubcategory "CCE-37133-6: Ensure 'Audit Account Lockout' is set to 'Success and Failure' (Success)"
		{
			Name = 'Account Lockout'
			AuditFlag = 'Success'
			Ensure = 'Present'
		}

		AuditPolicySubcategory "CCE-37133-6: Ensure 'Audit Account Lockout' is set to 'Success and Failure' (Failure)"
		{
			Name = 'Account Lockout'
			AuditFlag = 'Failure'
			Ensure = 'Present'
		}

		AuditPolicySubcategory "CCE-38329-9: Ensure 'Audit Application Group Management' is set to 'Success and Failure' (Success)"
		{
	 		Name = 'Application Group Management'
	 		AuditFlag = 'Success'
	 		Ensure = 'Absent'
		}
		 
 		AuditPolicySubcategory "CCE-38329-9: Ensure 'Audit Application Group Management' is set to 'Success and Failure' (Failure)"
		{
	 		Name = 'Application Group Management'
	 		AuditFlag = 'Failure'
	 		Ensure = 'Absent'
		}

		AuditPolicySubcategory "CCE-38004-8: Ensure 'Audit Computer Account Management' is set to 'Success and Failure' (Success)"
		{
	 		Name = 'Computer Account Management'
	 		AuditFlag = 'Success'
	 		Ensure = 'Absent'
		}

 		AuditPolicySubcategory "CCE-38004-8: Ensure 'Audit Computer Account Management' is set to 'Success and Failure' (Failure)"
		{
	 		Name = 'Computer Account Management'
	 		AuditFlag = 'Failure'
	 		Ensure = 'Absent'
		}

		AuditPolicySubCategory "CCE-37741-6: Ensure 'Audit Credential Validation' is set to 'Success and Failure' (Success)"
		{
	 		Name = 'Credential Validation'
	 		AuditFlag = 'Success'
			Ensure = 'Present'
		}

 		AuditPolicySubCategory "CCE-37741-6: Ensure 'Audit Credential Validation' is set to 'Success and Failure' (Failure)"
		{
	 		Name = 'Credential Validation'
	 		AuditFlag = 'Failure'
			Ensure = 'Present'
		}

		AuditPolicySubcategory "CCE-36265-7: Ensure 'Audit Distribution Group Management' is set to 'Success and Failure' (Success)"
		{
	 		Name = 'Distribution Group Management'
	 		AuditFlag = 'Success'
	 		Ensure = 'Absent'
		}

 		AuditPolicySubcategory "CCE-36265-7: Ensure Audit Distribution Group Management is set to Success and Failure (Failure)"
		{
	 		Name = 'Distribution Group Management'
	 		AuditFlag = 'Failure'
	 		Ensure = 'Absent'
		}
		 
		AuditPolicySubcategory "AZ-WIN-00026: Ensure 'Audit Group Membership' is set to 'Success'"
		{
	 		Name = 'Group Membership'
	 		AuditFlag = 'Success'
			Ensure = 'Present'
		}

		AuditPolicySubcategory "CCE-38237-4: Ensure 'Audit Logoff' is set to 'Success'"
		{
			Name = 'Logoff'
	 		AuditFlag = 'Success'
			Ensure = 'Present'
		}

		AuditPolicySubCategory "CCE-38036-0: Ensure 'Audit Logon' is set to 'Success and Failure' (Success)"
		{
	 		Name = 'Logon'
	 		AuditFlag = 'Success'
			Ensure = 'Present'
		}

 		AuditPolicySubCategory "CCE-38036-0: Ensure 'Audit Logon' is set to 'Success and Failure' (Failure)"
		{
	 		Name = 'Logon'
	 		AuditFlag = 'Failure'
			Ensure = 'Present'
		}
		
		AuditPolicySubcategory "AZ-WIN-00111: Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure' (Success)"
		{
	 		Name = 'MPSSVC Rule-Level Policy Change'
	 		AuditFlag = 'Success'
			Ensure = 'Present'
		}
		
		AuditPolicySubcategory "AZ-WIN-00111: Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure' (Failure)"
		{
	 		Name = 'MPSSVC Rule-Level Policy Change'
	 		AuditFlag = 'Failure'
			Ensure = 'Present'
		}


		AuditPolicySubcategory "CCE-37855-4: Ensure 'Audit Other Account Management Events' is set to 'Success and Failure' (Success)"
		{
	 		Name = 'Other Account Management Events'
	 		AuditFlag = 'Success'
	 		Ensure = 'Absent'
		}

		AuditPolicySubcategory "CCE-37855-4: Ensure 'Audit Other Account Management Events' is set to 'Success and Failure' (Failure)"
		{
	 		Name = 'Other Account Management Events'
	 		AuditFlag = 'Failure'
	 		Ensure = 'Absent'
		}
		
		AuditPolicySubcategory "CCE-36322-6: Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure' (Failure)" 
		{
			Name = 'Other Logon/Logoff Events'
			AuditFlag = 'Failure'
			Ensure = 'Present'
		}
		
		AuditPolicySubcategory "CCE-36322-6: Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure' (Success)" 
		{
			Name = 'Other Logon/Logoff Events'
			AuditFlag = 'Success'
			Ensure = 'Present'
		}

		AuditPolicySubcategory "AZ-WIN-00113: Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'(Success)" 
		{
			Name = 'Other Object Access Events'
			AuditFlag = 'Success'
			Ensure = 'Present'
		}

		AuditPolicySubcategory "AZ-WIN-00113: Ensure 'Audit Other Object Access Events' is set to 'Success and Failure' (Failure)" 
		{
			Name = 'Other Object Access Events'
			AuditFlag = 'Failure'
			Ensure = 'Present'
		}

		AuditPolicySubcategory "AZ-WIN-00182: Ensure 'Audit PNP Activity' is set to 'Success'"
		{
			Name = 'Plug and Play Events'
	 		AuditFlag = 'Success'
			Ensure = 'Present'
		}

		AuditPolicySubcategory "CCE-36059-4: Ensure 'Audit Process Creation' is set to 'Success and Failure' (Success)"
		{
			Name = 'Process Creation'
	 		AuditFlag = 'Success'
			Ensure = 'Present'
		}
		
		AuditPolicySubcategory "CCE-36059-4: Ensure 'Audit Process Creation' is set to 'Success and Failure' (Failure)"
		{
			Name = 'Process Creation'
	 		AuditFlag = 'Failure'
			Ensure = 'Present'
		}
		
		AuditPolicySubCategory "CCE-37617-8: Ensure 'Audit Removable Storage' is set to 'Success and Failure' (Success)"
		{
	 		Name = 'Removable Storage'
	 		AuditFlag = 'Success'
			Ensure = 'Present'
		}

 		AuditPolicySubCategory "CCE-37617-8: Ensure 'Audit Removable Storage' is set to 'Success and Failure' (Failure)"
		{
	 		Name = 'Removable Storage'
	 		AuditFlag = 'Failure'
			Ensure = 'Present'
		}

		AuditPolicySubcategory "CCE-38034-5: Ensure 'Audit Security Group Management' is set to 'Success and Failure'"
		{
			Name = 'Security Group Management'
	 		AuditFlag = 'Success'
			Ensure = 'Present'
		}

		AuditPolicySubcategory "CCE-36266-5: Ensure 'Audit Special Logon' is set to 'Success'"
		{
			Name = 'Special Logon'
			AuditFlag = 'Success'
			Ensure = 'Present'
		}

		AuditPolicySubCategory "CCE-37856-2: Ensure 'Audit User Account Management' is set to 'Success and Failure' (Success)"
		{
	 		Name = 'User Account Management'
	 		AuditFlag = 'Success'
			Ensure = 'Present'
		}

 		AuditPolicySubCategory "CCE-37856-2: Ensure 'Audit User Account Management' is set to 'Success and Failure' (Failure)"
		{
	 		Name = 'User Account Management'
	 		AuditFlag = 'Failure'
			Ensure = 'Present'
		}

		AuditPolicySubcategory "NOT_ASSIGNED: Audit Kerberos Authentication Service (Success)"
		{
	 		Name = 'Kerberos Authentication Service'
	 		AuditFlag = 'Success'
	 		Ensure = 'Absent'
		}

 		AuditPolicySubcategory "NOT_ASSIGNED: Audit Kerberos Authentication Service (Failure)"
		{
	 		Name = 'Kerberos Authentication Service'
	 		AuditFlag = 'Failure'
	 		Ensure = 'Absent'
		}

		AuditPolicySubcategory "NOT_ASSIGNED: Audit Kerberos Service Ticket Operations (Success)"
		{
	 		Name = 'Kerberos Service Ticket Operations'
	 		AuditFlag = 'Success'
	 		Ensure = 'Absent'
		}

 		AuditPolicySubcategory "NOT_ASSIGNED: Audit Kerberos Service Ticket Operations (Failure)"
		{
	 		Name = 'Kerberos Service Ticket Operations'
	 		AuditFlag = 'Failure'
	 		Ensure = 'Absent'
		}

		AuditPolicySubcategory "NOT_ASSIGNED: Audit Non Sensitive Privilege Use (Success)"
		{
	 		Name = 'Non Sensitive Privilege Use'
	 		AuditFlag = 'Success'
	 		Ensure = 'Absent'
		}

 		AuditPolicySubcategory "NOT_ASSIGNED: Audit Non Sensitive Privilege Use (Failure)"
		{
	 		Name = 'Non Sensitive Privilege Use'
	 		AuditFlag = 'Failure'
	 		Ensure = 'Absent'
		}

		AuditPolicySubcategory "CCE-36144-4: Ensure 'Audit Security System Extension' is set to 'Success "
		{
			Name      = 'Security System Extension'
			AuditFlag = 'Success'
			Ensure = 'Present'
		}

		AuditPolicySubcategory "CCE-36267-3: Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure' (Failure)"
		{
			Name      = 'Sensitive Privilege Use'
			AuditFlag = 'Failure'
			Ensure = 'Present'
		}

		AuditPolicySubcategory "CCE-36267-3: Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure' (Success)"
		{
			Name      = 'Sensitive Privilege Use'
			AuditFlag = 'Success'
			Ensure = 'Present'
		}
    
		UserRightsAssignment "CCE-35818-4: Configure 'Access this computer from the network'"
		{
			Policy = 'Access_this_computer_from_the_network'
			Force = $True
			Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\AUTHENTICATED USERS')	
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-37072-6: Configure 'Allow log on through Remote Desktop Services'"
		{
			Policy = 'Allow_log_on_through_Remote_Desktop_Services'
			Force = $True
			Identity = @('BUILTIN\Administrators')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-37659-0: Configure 'Allow log on locally'"
		{
			Policy = 'Allow_log_on_locally'
			Force = $True
			Identity = @('BUILTIN\Administrators')
			Ensure = 'Present'
		}
		
		UserRightsAssignment "CCE-35823-4: Configure 'Create symbolic links'"
		{
			Policy = 'Create_symbolic_links'
			Force = $True
			Identity = @('BUILTIN\Administrators')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-37954-5: Configure 'Deny access to this computer from the network'"
		{
			Policy = 'Deny_access_to_this_computer_from_the_network'
			Force = $True
			Identity = @('BUILTIN\Guests')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-35906-7: Configure 'Manage auditing and security log'"
		{
			Policy = 'Manage_auditing_and_security_log'
			Identity = @('BUILTIN\Administrators')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-35912-5: Ensure 'Back up files and directories' is set to 'Administrators'"
		{
			Policy = 'Back_up_files_and_directories'
			Force = $True
			Identity = @('BUILTIN\Backup Operators')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-37452-0: Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
		{
			Policy = 'Change_the_system_time'
			Force = $True
			Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-37700-2: Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
		{
			Policy = 'Change_the_time_zone'
			Force = $True
			Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-35821-8: Ensure 'Create a pagefile' is set to 'Administrators'"
		{
			Policy = 'Create_a_pagefile'
			Force = $True
			Identity = @('BUILTIN\Administrators')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-37453-8: Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
		{
			Policy = 'Create_global_objects'
			Force = $True
			Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\SERVICE', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE')
		}

		UserRightsAssignment "CCE-36923-1: Ensure 'Deny log on as a batch job' to include 'Guests'"
		{
			Policy = 'Deny_log_on_as_a_batch_job'
			Force = $True
			Identity = @('BUILTIN\Guests')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-36877-9: Ensure 'Deny log on as a service' to include 'Guests'"
		{
			Policy = 'Deny_log_on_as_a_service'
			Force = $True
			Identity = @('BUILTIN\Guests')
		}

		UserRightsAssignment "CCE-37146-8: Ensure 'Deny log on locally' to include 'Guests'"
		{
			Policy = 'Deny_log_on_locally'
			Force = $True
			Identity = @('BUILTIN\Guests')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-36867-0: Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'"
		{
			Policy = 'Deny_log_on_through_Remote_Desktop_Services'
			Force = $True
			Identity = @('BUILTIN\Guests')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-37877-8: Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
		{
			Policy = 'Force_shutdown_from_a_remote_system'
			Force = $True
			Identity = @('BUILTIN\Administrators')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-37639-2: Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
		{
			Policy = 'Generate_security_audits'
			Force = $True
			Identity = @('NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-38326-5: Ensure 'Increase scheduling priority' is set to 'Administrators'"
		{
			Policy = 'Increase_scheduling_priority'
			Force = $True
			Identity = @('BUILTIN\Administrators')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-36318-4: Ensure 'Load and unload device drivers' is set to 'Administrators'"
		{
			Policy = 'Load_and_unload_device_drivers'
			Force = $True
			Identity = @('BUILTIN\Administrators')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-38113-7: Ensure 'Modify firmware environment values' is set to 'Administrators'"
		{
			Policy = 'Modify_firmware_environment_values'
			Force = $True
			Identity = @('BUILTIN\Administrators')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-36143-6: Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
		{
			Policy = 'Perform_volume_maintenance_tasks'
			Force = $True
			Identity = @('BUILTIN\Administrators')
		}

		UserRightsAssignment "CCE-37131-0: Ensure 'Profile single process' is set to 'Administrators'"
		{
			Policy = 'Profile_single_process'
			Force = $True
			Identity = @('BUILTIN\Administrators')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-36052-9: Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'"
		{
			Policy = 'Profile_system_performance'
			Force = $True
			Identity = @('BUILTIN\Administrators')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-37430-6: Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
		{
			Policy = 'Replace_a_process_level_token'
			Force = $True
			Identity = @('NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-37613-7: Ensure 'Restore files and directories' is set to 'Administrators'"
		{
			Policy = 'Restore_files_and_directories'
			Force = $True
			Identity = @('BUILTIN\Administrators', 'BUILTIN\Backup Operators')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-38328-1: Ensure 'Shut down the system' is set to 'Administrators'"
		{
			Policy = 'Shut_down_the_system'
			Force = $True
			Identity = @('BUILTIN\Administrators')
			Ensure = 'Present'
		}

		UserRightsAssignment "CCE-38325-7: Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
		{
			Policy = 'Take_ownership_of_files_or_other_objects'
			Force = $True
			Identity = @('BUILTIN\Administrators')
			Ensure = 'Present'
		}

		UserRightsAssignment "NOT_ASSIGNED: Bypass traverse checking"
		{
			Policy = 'Bypass_traverse_checking'
			Force = $True
			Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\AUTHENTICATED USERS', 'BUILTIN\Backup Operators', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE')
			Ensure = 'Present'
		}

		UserRightsAssignment "NOT_ASSIGNED: Increase a process working set"
		{
			Policy = 'Increase_a_process_working_set'
			Force = $True
			Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE')
			Ensure = 'Present'
		}

		UserRightsAssignment "NOT_ASSIGNED: Remove computer from docking station"
		{
			Policy = 'Remove_computer_from_docking_station'
			Force = $True
			Identity = @('BUILTIN\Administrators')
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00180: Recovery console: Allow floppy copy and access to all drives and all folders'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'setcommand'
			ValueData = 0
			Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37701-0: Ensure Devices: Allowed to format and eject removable media is set to Administrators'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllocateDASD'
			ValueData = '0'
			Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
			ValueType = 'String'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): Qualys ID90007: Enabled Cached Logon Credential and ensure it is set to 0'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'CachedLogonsCount'
			ValueData = '0'
			Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
			ValueType = 'String'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36512-2: Ensure Enumerate administrator accounts on elevation is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnumerateAdministrators'
			ValueData = 0
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36809-2: Ensure Turn off shell protocol protected mode is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'PreXPSP2ShellProtocolBehavior'
			ValueData = 0
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36875-3: Ensure Turn off Autoplay is set to Enabled: All drives'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NoDriveTypeAutoRun'
			ValueData = 255
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38217-6: Ensure Set the default behavior for AutoRun is set to Enabled: Do not execute any autorun commands'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NoAutorun'
			ValueData = 1
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36788-8: Ensure Shutdown: Allow system to be shut down without having to log on is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'ShutdownWithoutLogon'
			ValueData = 0
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36494-3: Ensure User Account Control: Admin Approval Mode for the Built-in Administrator account is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'FilterAdministratorToken'
			ValueData = 1
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36863-9: Ensure User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableUIADesktopToggle'
			ValueData = 0
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37029-6: Ensure User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode is set to Prompt for consent on the secure desktop'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'ConsentPromptBehaviorAdmin'
			ValueData = 2
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36977-7: Ensure Sign-in last interactive user automatically after a system-initiated restart is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableAutomaticRestartSignOn'
			ValueData = 1
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36925-6: Include command line in process creation events'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
			ValueData = 1
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36533-8: Ensure User Account Control: Detect application installations and prompt for elevation is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableInstallerDetection'
			ValueData = 1
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37057-7: Ensure User Account Control: Only elevate UIAccess applications that are installed in secure locations is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableSecureUIAPaths'
			ValueData = 1
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36869-6: Ensure User Account Control: Run all administrators in Admin Approval Mode is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableLUA'
			ValueData = 1
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36866-2: Ensure User Account Control: Switch to the secure desktop when prompting for elevation is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'PromptOnSecureDesktop'
			ValueData = 1
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37064-3: Ensure User Account Control: Virtualize file and registry write failures to per-user locations is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableVirtualization'
			ValueData = 1
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00120: Devices: Allow undock without having to log on'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'UndockWithoutLogon'
			ValueData = 0
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37637-6: Ensure Interactive logon: Do not require CTRL+ALT+DEL is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableCAD'
			ValueData = 0
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37712-7: Ensure Turn off background refresh of Group Policy is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableBkGndGroupPolicy'
			ValueData = 0
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36864-7: Ensure User Account Control: Behavior of the elevation prompt for standard users is set to Automatically deny elevation requests'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'ConsentPromptBehaviorUser'
			ValueData = 0
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36056-0: Ensure Interactive logon: Do not display last user name is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DontDisplayLastUserName'
			ValueData = 1
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38354-7: Ensure Allow Microsoft accounts to be optional is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'MSAOptional'
			ValueData = 1
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37755-6: Ensure Network Security: Configure encryption Types allowed for Kerberos is set to RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption Types'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'SupportedEncryptionTypes'
			ValueData = 2147483644
			Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): NOT_ASSIGNED: Enable Windows Error Reporting'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'Disabled'
			ValueData = 0
			Key = 'HKLM:\Software\Microsoft\Windows\Windows Error Reporting'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00168: Ensure Allow Input Personalization is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowInputPersonalization'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\InputPersonalization'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37126-0: Ensure Prevent downloading of enclosures is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableEnclosureDownload'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00152: Specify the interval to check for definition updates'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'SignatureUpdateInterval'
			ValueData = 8
			Key = 'HKLM:\Software\Policies\Microsoft\Microsoft Antimalware\Signature Updates'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37843-0: Ensure Enable Windows NTP Client is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'Enabled'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00178: Enable Turn on behavior monitoring'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableBehaviorMonitoring'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00177: Enable Scan removable drives by setting DisableRemovableDriveScanning  to 0'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableRemovableDriveScanning'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00173: Disable Configure local setting override for reporting to Microsoft MAPS'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'LocalSettingOverrideSpynetReporting'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00126: Enable Send file samples when further analysis is required for Send Safe Samples'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'SubmitSamplesConsent'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36625-2: Ensure Turn off downloading of print drivers over HTTP is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableWebPnPDownload'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37346-4: Ensure Enable RPC Endpoint Mapper Client Authentication is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableAuthEpResolution'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc'
			ValueType = 'Dword'
		}
		
		RegistryPolicyFile 'Registry(POL): CCE-37929-7: Ensure Always prompt for password upon connection is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'fPromptForPassword'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36627-8: Ensure Set client connection encryption level is set to Enabled: High Level'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'MinEncryptionLevel'
			ValueData = 3
			Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37567-5: Ensure Require secure RPC communication is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'fEncryptRPCTraffic'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00149: Require user authentication for remote connections by using Network Level Authentication'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'UserAuthentication'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37281-3: Ensure Configure Solicited Remote Assistance is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'fAllowToGetHelp'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36388-7: Ensure Configure Offer Remote Assistance is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'fAllowUnsolicited'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36223-6: Ensure Do not allow passwords to be saved is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisablePasswordSaving'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38180-6: Ensure Do not use temporary folders per session is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'PerSessionTempDir'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37946-1: Do not delete temp folders upon exit'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DeleteTempDirsOnExit'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00144: Ensure Turn off Microsoft consumer experiences is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableWindowsConsumerFeatures'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\CloudContent'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37534-5: Ensure Do not display the password reveal button is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisablePasswordReveal'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\CredUI'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00169: Ensure Allow Telemetry is set to Enabled: 0 - Security [Enterprise Only]'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowTelemetry'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00140: Ensure Do not show feedback notifications is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DoNotShowFeedbackNotifications'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37948-7: Ensure Application: Specify the maximum log file size is set to Enabled: 32,768 or greater'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'MaxSize'
			ValueData = '0x8000'
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37775-4: Ensure Application: Control Event Log behavior when the log file reaches its maximum size is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'Retention'
			ValueData = '0'
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
			ValueType = 'String'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37695-4: Ensure Security: Specify the maximum log file size is set to Enabled: 196,608 or greater'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'MaxSize'
			ValueData = 196608
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37145-0: Ensure Security: Control Event Log behavior when the log file reaches its maximum size is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'Retention'
			ValueData = '0'
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
			ValueType = 'String'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37526-1: Ensure Setup: Specify the maximum log file size is set to Enabled: 32,768 or greater'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'MaxSize'
			ValueData = '0x8000'
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38276-2: Ensure Setup: Control Event Log behavior when the log file reaches its maximum size is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'Retention'
			ValueData = '0'
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup'
			ValueType = 'String'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36092-5: Ensure System: Specify the maximum log file size is set to Enabled: 32,768 or greater'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'MaxSize'
			ValueData = '0x8000'
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36160-0: Ensure System: Control Event Log behavior when the log file reaches its maximum size is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'Retention'
			ValueData = '0'
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
			ValueType = 'String'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37636-8: Ensure Disallow Autoplay for non-volume devices is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NoAutoplayfornonVolume'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37809-1: Ensure Turn off Data Execution Prevention for Explorer is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NoDataExecutionPrevention'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36660-9: Ensure Turn off heap termination on corruption is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NoHeapTerminationOnCorruption'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36169-1: Ensure Configure registry policy processing: Process even if the Group Policy objects have not changed is set to Enabled: TRUE'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NoGPOListChanges'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36169-1: Ensure Configure registry policy processing: Do not apply during periodic background processing is set to Enabled: FALSE'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NoBackgroundPolicy'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37490-0: Ensure Always install with elevated privileges is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AlwaysInstallElevated'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36400-0: Ensure Allow user control over installs is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableUserControl'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37163-3: Ensure Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'ExitOnMSICW'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Internet Connection Wizard'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00171: Ensure Enable insecure guest logons is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowInsecureGuestAuth'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38188-9: Ensure Require domain users to elevate when setting a networks location is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NC_StdDomainUserSetLocation'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00172: Ensure Prohibit use of Internet Connection Sharing on your DNS domain network is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NC_PersonalFirewallConfig'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38002-2: Ensure Prohibit installation and configuration of Network Bridge on your DNS domain network is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NC_AllowNetBridge_NLA'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00172: Prohibit use of Internet Connection Sharing on your DNS domain network'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NC_ShowSharedAccessUI'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38348-9: Ensure Prevent enabling lock screen slide show is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NoLockScreenSlideshow'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
			ValueType = 'Dword'
		}
		
		RegistryPolicyFile 'Registry(POL): CCE-38347-1: Ensure Prevent enabling lock screen camera is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NoLockScreenCamera'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00155: System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AuthenticodeEnabled'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-35893-7: Ensure Turn off app notifications on the lock screen is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableLockScreenAppNotifications'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-35894-5: Ensure Enumerate local users on domain-joined computers is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnumerateLocalUsers'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
			ValueType = 'Dword'
		}
		
		RegistryPolicyFile 'Registry(POL): CCE-37528-7: Ensure Turn on convenience PIN sign-in is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowDomainPINLogon'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00138: Ensure Block user from showing account details on sign-in is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'BlockUserFromShowingAccountDetailsOnSignin'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37838-0: Ensure Do not enumerate connected users on domain-joined computers is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DontEnumerateConnectedUsers'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38353-9: Ensure Do not display network selection UI is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DontDisplayNetworkSelectionUI'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-35859-8: Ensure Configure Windows SmartScreen is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableSmartScreen'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00170: Ensure Continue experiences on this device is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableCdp'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38338-0: Ensure Minimize the number of simultaneous connections to the Internet or a Windows Domain is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'fMinimizeConnections'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00133: Ensure Allow search and Cortana to use location is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowSearchToUseLocation'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38277-0: Ensure Allow indexing of encrypted files is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowIndexingEncryptedStoresOrItems'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00131: Ensure Allow Cortana is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowCortana'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00130: Ensure Allow Cortana above lock screen is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowCortanaAboveLock'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38223-4: Ensure Allow unencrypted traffic is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowUnencryptedTraffic'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36254-1: Ensure Allow Basic authentication is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowBasic'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38318-2: Ensure Disallow Digest authentication is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowDigest'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36000-8: Ensure Disallow WinRM from storing RunAs credentials is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableRunAs'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00088: Windows Firewall: Domain: Allow unicast response'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36062-8: Ensure Windows Firewall: Domain: Firewall state is set to On'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableFirewall'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38041-0: Ensure Windows Firewall: Domain: Settings: Display a notification is set to No'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableNotifications'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38117-8: Ensure Windows Firewall: Domain: Inbound connections is set to Block'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DefaultInboundAction'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38040-2: Ensure Windows Firewall: Domain: Settings: Apply local connection security rules is set to Yes'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowLocalIPsecPolicyMerge'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36146-9: Ensure Windows Firewall: Domain: Outbound connections is set to Allow'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DefaultOutboundAction'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37860-4: Ensure Windows Firewall: Domain: Settings: Apply local firewall rules is set to Yes'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowLocalPolicyMerge'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
			ValueType = 'Dword'
		}
		
		RegistryPolicyFile 'Registry(POL): CCE-37523-8: Ensure Windows Firewall: Domain: Logging: Log dropped packets is set to Yes'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'LogDroppedPackets'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36088-3: Ensure Windows Firewall: Domain: Logging: Size limit is set to 16,384 KB or greater'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'LogFileSize'
			ValueData = 16384
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36393-7: Ensure Windows Firewall: Domain: Logging: Log successful connections is set to Yes'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'LogSuccessfulConnections'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37621-0: Ensure Windows Firewall: Private: Settings: Display a notification is set to No'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableNotifications'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37438-9: Ensure Windows Firewall: Private: Settings: Apply local firewall rules is set to Yes'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowLocalPolicyMerge'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38332-3: Ensure Windows Firewall: Private: Outbound connections is set to Allow'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DefaultOutboundAction'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36063-6: Ensure Windows Firewall: Private: Settings: Apply local connection security rules is set to Yes'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowLocalIPsecPolicyMerge'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38042-8: Ensure Windows Firewall: Private: Inbound connections is set to Block'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DefaultInboundAction'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38239-0: Ensure Windows Firewall: Private: Firewall state is set to On'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableFirewall'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00089: Windows Firewall: Private: Allow unicast response'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38178-0: Ensure Windows Firewall: Private: Logging: Size limit is set to 16,384 KB or greater'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'LogFileSize'
			ValueData = 16384
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-35972-9: Ensure Windows Firewall: Private: Logging: Log dropped packets is set to Yes'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'LogDroppedPackets'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37387-8: Ensure Windows Firewall: Private: Logging: Log successful connections is set to Yes'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'LogSuccessfulConnections'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37862-0: Ensure Windows Firewall: Public: Firewall state is set to On'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableFirewall'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36057-8: Ensure Windows Firewall: Public: Inbound connections is set to Block'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DefaultInboundAction'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36268-1: Ensure Windows Firewall: Public: Settings: Apply local connection security rules is set to No'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowLocalIPsecPolicyMerge'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37861-2: Ensure Windows Firewall: Public: Settings: Apply local firewall rules is set to No'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowLocalPolicyMerge'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
			ValueType = 'Dword'
		}
		
		RegistryPolicyFile 'Registry(POL): CCE-38043-6: Ensure Windows Firewall: Public: Settings: Display a notification is set to Yes'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableNotifications'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37434-8: Ensure Windows Firewall: Public: Outbound connections is set to Allow'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DefaultOutboundAction'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00090: Windows Firewall: Public: Allow unicast response'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36395-2: Ensure Windows Firewall: Public: Logging: Size limit is set to 16,384 KB or greater'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'LogFileSize'
			ValueData = 16384
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37265-6: Ensure Windows Firewall: Public: Logging: Log dropped packets is set to Yes'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'LogDroppedPackets'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36394-5: Ensure Windows Firewall: Public: Logging: Log successful connections is set to Yes'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'LogSuccessfulConnections'
			ValueData = 1
			Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36316-8: Ensure Network access: Do not allow anonymous enumeration of SAM accounts is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'RestrictAnonymousSAM'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36148-5: Ensure Network access: Let Everyone permissions apply to anonymous users is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EveryoneIncludesAnonymous'
			ValueData = 0
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36077-6: Ensure Network access: Do not allow anonymous enumeration of SAM accounts and shares is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'RestrictAnonymous'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00142: Ensure Network access: Restrict clients allowed to make remote calls to SAM is set to Administrators: Remote Access: Allow'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'RestrictRemoteSAM'
			ValueData = 'O:BAG:BAD:(A;;RC;;;BA)'
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
			ValueType = 'String'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37623-6: Ensure Network access: Sharing and security model for local accounts is set to Classic - local users authenticate as themselves'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'ForceGuest'
			ValueData = 0
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38341-4: Ensure Network security: Allow Local System to use computer identity for NTLM is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'UseMachineId'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36326-7: Ensure Network security: Do not store LAN Manager hash value on next password change is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NoLMHash'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36173-3: Ensure Network security: LAN Manager authentication level is set to Send NTLMv2 response only. Refuse LM & NTLM'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'LmCompatibilityLevel'
			ValueData = 5
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-35907-5: Ensure Audit: Shut down system immediately if unable to log security audits is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'CrashOnAuditFail'
			ValueData = 0
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37850-5: Ensure Audit: Force audit policy subcategory settings to override audit policy category settings is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'SCENoApplyLegacyAuditPolicy'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
			ValueType = 'Dword'
			Ensure = 'Present'
		}
		
		RegistryPolicyFile 'Registry(POL): CCE-37615-2: Limit local account use of blank passwords to console logon only is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'LimitBlankPasswordUse'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37553-5: Ensure Network security: Minimum session security for NTLM SSP based  clients is set to Require NTLMv2 session security, Require 128-bit encryption'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NTLMMinClientSec'
			ValueData = 537395200
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37835-6: Ensure Network security: Minimum session security for NTLM SSP based servers is set to Require NTLMv2 session security, Require 128-bit encryption'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NTLMMinServerSec'
			ValueData = 537395200
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37035-3: Ensure Network security: Allow LocalSystem NULL session fallback is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowNullSessionFallback'
			ValueData = 0
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38047-7: Ensure Network Security: Allow PKU2U authentication requests to this computer to use online identities is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AllowOnlineID'
			ValueData = 0
			Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\pku2u'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37942-0: Ensure Devices: Prevent users from installing printer drivers is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AddPrinterDrivers'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37194-8: Network access: Remotely accessible registry paths'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'Machine'
			ValueData = 'System\CurrentControlSet\Control\ProductOptions|#|System\CurrentControlSet\Control\Server Applications|#|Software\Microsoft\Windows NT\CurrentVersion'
			Key = 'HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths'
			ValueType = 'MultiString'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36347-3: Network access: Remotely accessible registry paths and sub-paths'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'Machine'
			ValueData = 'System\CurrentControlSet\Control\Print\Printers|#|System\CurrentControlSet\Services\Eventlog|#|Software\Microsoft\OLAP Server|#|Software\Microsoft\Windows NT\CurrentVersion\Print|#|Software\Microsoft\Windows NT\CurrentVersion\Windows|#|System\CurrentControlSet\Control\ContentIndex|#|System\CurrentControlSet\Control\Terminal Server|#|System\CurrentControlSet\Control\Terminal Server\UserConfig|#|System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration|#|Software\Microsoft\Windows NT\CurrentVersion\Perflib|#|System\CurrentControlSet\Services\SysmonLog'
			Key = 'HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths'
			ValueType = 'MultiString'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37644-2: Ensure System objects: Strengthen default permissions of internal system objects is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'ProtectionMode'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37885-1: Ensure System objects: Require case insensitivity for non-Windows subsystems is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'ObCaseInsensitive'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00181: Shutdown: Clear virtual memory pagefile'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'ClearPageFileAtShutdown'
			ValueData = 0
			Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-35921-6: Ensure System settings: Optional subsystems is set to Defined:'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'Optional'
			ValueData = '0'
			Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\SubSYSTEMs'
			ValueType = 'MultiString'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00156: Detect change from default RDP port'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'PortNumber'
			ValueData = 3389
			Key = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37912-3: Ensure Boot-Start Driver Initialization Policy is set to Enabled: Good, unknown and bad but critical'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DriverLoadPolicy'
			ValueData = 3
			Key = 'HKLM:\System\CurrentControlSet\Policies\EarlyLaunch'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37972-7: Ensure Microsoft network server: Disconnect clients when logon hours expire is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableForcedLogoff'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38095-6: Ensure Network access: Shares that can be accessed anonymously is set to None'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'NullSessionShares'
			ValueData = $null
			Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
			ValueType = 'MultiString'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36021-4: Ensure Network access: Restrict anonymous access to Named Pipes and Shares is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'RestrictNullSessAccess'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}
		
		RegistryPolicyFile 'Registry(POL): AZ-WIN-00175: Disable SMB v1 server'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'SMB1'
			ValueData = 0
			Key = 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-35988-5: Ensure Microsoft network server: Digitally sign communications (if client agrees) is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableSecuritySignature'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-38046-9: Ensure Microsoft network server: Amount of idle time required before suspending session is set to 15 or fewer minute, but not 0'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'AutoDisconnect'
			ValueData = 15
			Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}
		
		RegistryPolicyFile 'Registry(POL): CCE-37864-6: Ensure Microsoft network server: Digitally sign communications (always) is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'RequireSecuritySignature'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00175: Disable SMB v1 client'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DependsOnService'
			ValueData = "'Bowser','MRxSmb20','NSI'"
			Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation'
			ValueType = 'MultiString'
			Ensure = 'Present'
		}
		
		RegistryPolicyFile 'Registry(POL): CCE-36325-9: Ensure Microsoft network client: Digitally sign communications (always) is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'RequireSecuritySignature'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36269-9: Ensure Microsoft network client: Digitally sign communications (if server agrees) is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableSecuritySignature'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37863-8: Ensure Microsoft network client: Send unencrypted password to third-party SMB servers is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnablePlainTextPassword'
			ValueData = 0
			Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36858-9: Ensure Network security: LDAP client signing requirements is set to Negotiate signing or higher'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'LDAPClientIntegrity'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Services\LDAP'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37614-5: Ensure Domain member: Require strong  session key is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'RequireStrongKey'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37508-9: Ensure Domain member: Disable machine account password changes is set to Disabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'DisablePasswordChange'
			ValueData = 0
			Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37222-7: Ensure Domain member: Digitally sign secure channel data (when possible) is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'SignSecureChannel'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37130-2: Ensure Domain member: Digitally encrypt secure channel data is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'SealSecureChannel'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-36142-8: Ensure Domain member: Digitally encrypt or sign secure channel data is set to Enabled'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'RequireSignOrSeal'
			ValueData = 1
			Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): CCE-37431-4: Ensure Domain member: Maximum machine account password age is set to 30 or fewer days, but not 0'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'MaximumPasswordAge'
			ValueData = 30
			Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile 'Registry(POL): AZ-WIN-00176: Disable Windows Search Service'
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'Start'
			ValueData = 4
			Key = 'HKLM:\System\CurrentControlSet\Services\Wsearch'
			ValueType = 'Dword'
			Ensure = 'Present'
		}

		RegistryPolicyFile "AZ-WIN-00145: Ensure 'Turn off multicast name resolution' is set to 'Enabled'"
		{
			TargetType = 'ComputerConfiguration'
			ValueName = 'EnableMulticast'
			ValueData = 0
			Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient'
			ValueType = 'Dword'
			Ensure = 'Present'
    }

		UserRightsAssignment 'CCE-36860-5: Configure Enable computer and user accounts to be trusted for delegation'
		{
			Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
			Force = $True
			Identity = @()
			Ensure = 'Present'
		}

		UserRightsAssignment 'CCE-36495-0: Ensure Lock pages in memory is set to No One'
		{
			Policy = 'Lock_pages_in_memory'
			Force = $True
			Identity = @()
			Ensure = 'Present'
		}
		
		UserRightsAssignment 'CCE-36054-5: Ensure Modify an object label is set to No One'
		{
			Policy = 'Modify_an_object_label'
			Force = $True
			Identity = @()
			Ensure = 'Present'
		}
    
		UserRightsAssignment 'CCE-36861-3: Ensure Create a token object is set to No One'
		{
			Policy = 'Create_a_token_object'
			Force = $True
			Identity = @()
			Ensure = 'Present'
		}

		UserRightsAssignment 'CCE-36532-0: Ensure Create permanent shared objects is set to No One'
		{
			Policy = 'Create_permanent_shared_objects'
			Force = $True
			Identity = @()
			Ensure = 'Present'
		}

		UserRightsAssignment 'CCE-37056-9: Ensure Access Credential Manager as a trusted caller is set to No One'
		{
			Policy = 'Access_Credential_Manager_as_a_trusted_caller'
			Force = $True
			Identity = @()
			Ensure = 'Present'
		}

		UserRightsAssignment 'CCE-36876-1: Ensure Act as part of the operating system is set to No One'
		{
			Policy = 'Act_as_part_of_the_operating_system'
			Force = $True
			Identity = @()
			Ensure = 'Present'
		}

		AccountPolicy AccountPolicies
		{
			Name = 'PasswordPolicies'
			Enforce_password_history = "24"
			Maximum_Password_Age = "42"
			Minimum_Password_Age = "1"
			Minimum_Password_Length = "14"
			Password_must_meet_complexity_requirements = 'Enabled'
			Store_passwords_using_reversible_encryption = 'Disabled'
			Account_lockout_threshold = '4'
		}
		
		SecurityOption LocalPolicies
		{
			Name = 'SecurityOptions'
			Accounts_Block_Microsoft_accounts = 'This policy is disabled'
			Network_access_Shares_that_can_be_accessed_anonymously = $null
			Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = "2"
			Interactive_logon_Machine_inactivity_limit = '850'
			Network_security_Configure_encryption_types_allowed_for_Kerberos = "DES_CBC_CRC, DES_CBC_MD5, RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1"
			Network_access_Allow_anonymous = 'Disabled'
			Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
			Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
			System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = "User must enter a password each time they use a key"
		}
	}
}

SecurityBaselineConfig

Start-DscConfiguration -Path .\SecurityBaselineConfig\ -force -verbose