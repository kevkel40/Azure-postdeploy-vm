$RequiredModules = @('PSDesiredStateConfiguration','AuditPolicyDSC','SecurityPolicyDSC','GPRegistryPolicyDsc')
foreach($Module in $RequiredModules){
	if(!((get-module -ListAvailable).name -contains $module)){
		Install-module -name $Module -force
	}
}

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
			Ensure = 'Present'
			AuditFlag = 'Success'
		}

		AuditPolicySubcategory "CCE-37133-6: Ensure 'Audit Account Lockout' is set to 'Success and Failure' (Failure)"
		{
			Name = 'Account Lockout'
			Ensure = 'Present'
			AuditFlag = 'Failure'
		}

	 	AuditPolicySubcategory "CCE-38329-9: Ensure 'Audit Application Group Management' is set to 'Success and Failure' (Success)"
	 	{
	 	 	Name = 'Application Group Management'
	 	 	Ensure = 'Absent'
	 	 	AuditFlag = 'Success'
		 }
		 
 	 	AuditPolicySubcategory "CCE-38329-9: Ensure 'Audit Application Group Management' is set to 'Success and Failure' (Failure)"
	 	{
	 	 	Name = 'Application Group Management'
	 	 	Ensure = 'Absent'
	 	 	AuditFlag = 'Failure'
	 	}
		AuditPolicySubcategory "CCE-38004-8: Ensure 'Audit Computer Account Management' is set to 'Success and Failure' (Success)"
	 	{
	 	 	Name = 'Computer Account Management'
	 	 	Ensure = 'Absent'
	 	 	AuditFlag = 'Success'
	 	}

 	 	AuditPolicySubcategory "CCE-38004-8: Ensure 'Audit Computer Account Management' is set to 'Success and Failure' (Failure)"
	 	{
	 	 	Name = 'Computer Account Management'
	 	 	Ensure = 'Absent'
	 	 	AuditFlag = 'Failure'
	 	}

	 	AuditPolicySubCategory "CCE-37741-6: Ensure 'Audit Credential Validation' is set to 'Success and Failure' (Success)"
	 	{
	 	 	Name = 'Credential Validation'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'
	 	}

 	 	AuditPolicySubCategory "CCE-37741-6: Ensure 'Audit Credential Validation' is set to 'Success and Failure' (Failure)"
	 	{
	 	 	Name = 'Credential Validation'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'
	 	}

	 	AuditPolicySubcategory "CCE-36265-7: Ensure 'Audit Distribution Group Management' is set to 'Success and Failure' (Success)"
	 	{
	 	 	Name = 'Distribution Group Management'
	 	 	Ensure = 'Absent'
	 	 	AuditFlag = 'Success'
	 	}

 	 	AuditPolicySubcategory "CCE-36265-7: Ensure 'Audit Distribution Group Management' is set to 'Success and Failure' (Failure)"
	 	{
	 	 	Name = 'Distribution Group Management'
	 	 	Ensure = 'Absent'
	 	 	AuditFlag = 'Failure'
		 }
		 
		 AuditPolicySubcategory "AZ-WIN-00026: Ensure 'Audit Group Membership' is set to 'Success'"
	 	{
	 	 	Name = 'Group Membership'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'
		 }

	 	AuditPolicySubcategory "CCE-38237-4: Ensure 'Audit Logoff' is set to 'Success'"
	 	{
			Name = 'Logoff'
			Ensure = 'Present'
	 		AuditFlag = 'Success'
	 	}

	 	AuditPolicySubCategory "CCE-38036-0: Ensure 'Audit Logon' is set to 'Success and Failure' (Success)"
	 	{
	 	 	Name = 'Logon'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'
	 	}

 	 	AuditPolicySubCategory "CCE-38036-0: Ensure 'Audit Logon' is set to 'Success and Failure' (Failure)"
	 	{
	 	 	Name = 'Logon'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'
		 }
		
		AuditPolicySubcategory "AZ-WIN-00111: Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure' (Success)"
	 	{
	 	 	Name = 'MPSSVC Rule-Level Policy Change'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'
		 }
		
		AuditPolicySubcategory "AZ-WIN-00111: Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure' (Failure)"
	 	{
	 	 	Name = 'MPSSVC Rule-Level Policy Change'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'
		 }


	 	AuditPolicySubcategory "CCE-37855-4: Ensure 'Audit Other Account Management Events' is set to 'Success and Failure' (Success)"
	 	{
	 	 	Name = 'Other Account Management Events'
	 	 	Ensure = 'Absent'
	 	 	AuditFlag = 'Success'
		 }

		 AuditPolicySubcategory "CCE-37855-4: Ensure 'Audit Other Account Management Events' is set to 'Success and Failure' (Failure)"
	 	{
	 	 	Name = 'Other Account Management Events'
	 	 	Ensure = 'Absent'
	 	 	AuditFlag = 'Failure'
	 	}
		
		AuditPolicySubcategory "CCE-36322-6: Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure' (Failure)" 
		{
			Name = 'Other Logon/Logoff Events'
			Ensure = 'Present'
			AuditFlag = 'Failure'
		}
		
		AuditPolicySubcategory "CCE-36322-6: Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure' (Success)" 
		{
			Name = 'Other Logon/Logoff Events'
			Ensure = 'Present'
			AuditFlag = 'Success'
		}

		AuditPolicySubcategory "AZ-WIN-00113: Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'(Success)" 
		{
			Name = 'Other Object Access Events'
			Ensure = 'Present'
			AuditFlag = 'Success'
		}

		AuditPolicySubcategory "AZ-WIN-00113: Ensure 'Audit Other Object Access Events' is set to 'Success and Failure' (Failure)" 
		{
			Name = 'Other Object Access Events'
			Ensure = 'Present'
			AuditFlag = 'Failure'
		}

	 	AuditPolicySubcategory "AZ-WIN-00182: Ensure 'Audit PNP Activity' is set to 'Success'"
	 	{
			Name = 'Plug and Play Events'
			Ensure = 'Present'
	 	 	AuditFlag = 'Success'
		}

	 	AuditPolicySubcategory "CCE-36059-4: Ensure 'Audit Process Creation' is set to 'Success and Failure' (Success)"
	 	{
			Name = 'Process Creation'
			Ensure = 'Present'
	 	 	AuditFlag = 'Success'
		}
		
	 	AuditPolicySubcategory "CCE-36059-4: Ensure 'Audit Process Creation' is set to 'Success and Failure' (Failure)"
	 	{
			Name = 'Process Creation'
			Ensure = 'Present'
	 	 	AuditFlag = 'Failure'
		}
		
	 	AuditPolicySubCategory "CCE-37617-8: Ensure 'Audit Removable Storage' is set to 'Success and Failure' (Success)"
	 	{
	 	 	Name = 'Removable Storage'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'
	 	}

 	 	AuditPolicySubCategory "CCE-37617-8: Ensure 'Audit Removable Storage' is set to 'Success and Failure' (Failure)"
	 	{
	 	 	Name = 'Removable Storage'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'
	 	}

	 	AuditPolicySubcategory "CCE-38034-5: Ensure 'Audit Security Group Management' is set to 'Success and Failure'"
	 	{
			Name = 'Security Group Management'
			Ensure = 'Present'
	 	 	AuditFlag = 'Success'
	 	}

	 	AuditPolicySubcategory "CCE-36266-5: Ensure 'Audit Special Logon' is set to 'Success'"
	 	{
			Name = 'Special Logon'
			Ensure = 'Present'
			AuditFlag = 'Success'
	 	}

	 	AuditPolicySubCategory "CCE-37856-2: Ensure 'Audit User Account Management' is set to 'Success and Failure' (Success)"
	 	{
	 	 	Name = 'User Account Management'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'
	 	}

 	 	AuditPolicySubCategory "CCE-37856-2: Ensure 'Audit User Account Management' is set to 'Success and Failure' (Failure)"
	 	{
	 	 	Name = 'User Account Management'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'
	 	}

	 	AuditPolicySubcategory "NOT_ASSIGNED: Audit Kerberos Authentication Service (Success)"
	 	{
	 	 	Name = 'Kerberos Authentication Service'
	 	 	Ensure = 'Absent'
	 	 	AuditFlag = 'Success'
	 	}

 	 	AuditPolicySubcategory "NOT_ASSIGNED: Audit Kerberos Authentication Service (Failure)"
	 	{
	 	 	Name = 'Kerberos Authentication Service'
	 	 	Ensure = 'Absent'
	 	 	AuditFlag = 'Failure'
	 	}

	 	AuditPolicySubcategory "NOT_ASSIGNED: Audit Kerberos Service Ticket Operations (Success)"
	 	{
	 	 	Name = 'Kerberos Service Ticket Operations'
	 	 	Ensure = 'Absent'
	 	 	AuditFlag = 'Success'
	 	}

 	 	AuditPolicySubcategory "NOT_ASSIGNED: Audit Kerberos Service Ticket Operations (Failure)"
	 	{
	 	 	Name = 'Kerberos Service Ticket Operations'
	 	 	Ensure = 'Absent'
	 	 	AuditFlag = 'Failure'
	 	}

	 	AuditPolicySubcategory "NOT_ASSIGNED: Audit Non Sensitive Privilege Use (Success)"
	 	{
	 	 	Name = 'Non Sensitive Privilege Use'
	 	 	Ensure = 'Absent'
	 	 	AuditFlag = 'Success'
	 	}

 	 	AuditPolicySubcategory "NOT_ASSIGNED: Audit Non Sensitive Privilege Use (Failure)"
	 	{
	 	 	Name = 'Non Sensitive Privilege Use'
	 	 	Ensure = 'Absent'
	 	 	AuditFlag = 'Failure'
		 }

		AuditPolicySubcategory "CCE-36144-4: Ensure 'Audit Security System Extension' is set to 'Success "
		{
			Name      = 'Security System Extension'
			Ensure    = 'Present'
			AuditFlag = 'Success'
		}

		 AuditPolicySubcategory "CCE-36267-3: Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure' (Failure)"
		{
			Name      = 'Sensitive Privilege Use'
			Ensure    = 'Present'
			AuditFlag = 'Failure'
		}

		AuditPolicySubcategory "CCE-36267-3: Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure' (Success)"
		{
			Name      = 'Sensitive Privilege Use'
			Ensure    = 'Present'
			AuditFlag = 'Success'
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
		}
		
		UserRightsAssignment "CCE-35818-4: Configure 'Access this computer from the network'"
		{
			Policy = 'Access_this_computer_from_the_network'
			Force = $True
			Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\AUTHENTICATED USERS')	
		}

		UserRightsAssignment "CCE-37072-6: Configure 'Allow log on through Remote Desktop Services'"
		{
			Policy = 'Allow_log_on_through_Remote_Desktop_Services'
			Force = $True
			Identity = @('BUILTIN\Administrators')
		}

	   UserRightsAssignment "CCE-37659-0: Configure 'Allow log on locally'"
		{
			Policy = 'Allow_log_on_locally'
			Force = $True
			Identity = @('BUILTIN\Administrators')
		}
		
		UserRightsAssignment "CCE-35823-4: Configure 'Create symbolic links'"
		{
			Policy = 'Create_symbolic_links'
			Force = $True
			Identity = @('BUILTIN\Administrators')
		}

		UserRightsAssignment "CCE-37954-5: Configure 'Deny access to this computer from the network'"
		{
			Policy = 'Deny_access_to_this_computer_from_the_network'
			Force = $True
			Identity = @('BUILTIN\Guests')
		}

		UserRightsAssignment "CCE-35906-7: Configure 'Manage auditing and security log'"
		{
			Policy = 'Manage_auditing_and_security_log'
			Identity = @('BUILTIN\Administrators')
		}

		UserRightsAssignment "CCE-35912-5: Ensure 'Back up files and directories' is set to 'Administrators'"
		{
			Policy = 'Back_up_files_and_directories'
			Force = $True
			Identity = @('BUILTIN\Backup Operators')
		}

		UserRightsAssignment "CCE-37452-0: Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
		{
			Policy = 'Change_the_system_time'
			Force = $True
			Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE')
		}

		UserRightsAssignment "CCE-37700-2: Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
		{
			Policy = 'Change_the_time_zone'
			Force = $True
			Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE')
		}

		UserRightsAssignment "CCE-35821-8: Ensure 'Create a pagefile' is set to 'Administrators'"
		{
			Policy = 'Create_a_pagefile'
			Force = $True
			Identity = @('BUILTIN\Administrators')
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
		}

		UserRightsAssignment "CCE-36867-0: Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'"
		{
			Policy = 'Deny_log_on_through_Remote_Desktop_Services'
			Force = $True
			Identity = @('BUILTIN\Guests')
		}

		UserRightsAssignment "CCE-37877-8: Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
		{
			Policy = 'Force_shutdown_from_a_remote_system'
			Force = $True
			Identity = @('BUILTIN\Administrators')
		}

		UserRightsAssignment "CCE-37639-2: Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
		{
			Policy = 'Generate_security_audits'
			Force = $True
			Identity = @('NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE')
		}

		UserRightsAssignment "CCE-38326-5: Ensure 'Increase scheduling priority' is set to 'Administrators'"
		{
			Policy = 'Increase_scheduling_priority'
			Force = $True
			Identity = @('BUILTIN\Administrators')
		}

		UserRightsAssignment "CCE-36318-4: Ensure 'Load and unload device drivers' is set to 'Administrators'"
		{
			Policy = 'Load_and_unload_device_drivers'
			Force = $True
			Identity = @('BUILTIN\Administrators')
		}

		UserRightsAssignment "CCE-38113-7: Ensure 'Modify firmware environment values' is set to 'Administrators'"
		{
			Policy = 'Modify_firmware_environment_values'
			Force = $True
			Identity = @('BUILTIN\Administrators')
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
		}

		UserRightsAssignment "CCE-36052-9: Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'"
		{
			Policy = 'Profile_system_performance'
			Force = $True
			Identity = @('BUILTIN\Administrators')
		}

		UserRightsAssignment "CCE-37430-6: Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
		{
			Policy = 'Replace_a_process_level_token'
			Force = $True
			Identity = @('NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE')
		}

		UserRightsAssignment "CCE-37613-7: Ensure 'Restore files and directories' is set to 'Administrators'"
		{
			Policy = 'Restore_files_and_directories'
			Force = $True
			Identity = @('BUILTIN\Administrators', 'BUILTIN\Backup Operators')
		}

		UserRightsAssignment "CCE-38328-1: Ensure 'Shut down the system' is set to 'Administrators'"
		{
			Policy = 'Shut_down_the_system'
			Force = $True
			Identity = @('BUILTIN\Administrators')
		}

		UserRightsAssignment "CCE-38325-7: Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
		{
			Policy = 'Take_ownership_of_files_or_other_objects'
			Force = $True
			Identity = @('BUILTIN\Administrators')
		}

		UserRightsAssignment "NOT_ASSIGNED: Bypass traverse checking"
		{
			Policy = 'Bypass_traverse_checking'
			Force = $True
			Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\AUTHENTICATED USERS', 'BUILTIN\Backup Operators', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE')
		}

		UserRightsAssignment "NOT_ASSIGNED: Increase a process working set"
		{
			Policy = 'Increase_a_process_working_set'
			Force = $True
			Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE')
		}

		UserRightsAssignment "NOT_ASSIGNED: Remove computer from docking station"
		{
			Policy = 'Remove_computer_from_docking_station'
			Force = $True
			Identity = @('BUILTIN\Administrators')
		}

		RegistryPolicyFile 'AZ-WIN-00145: Registry(POL): HKLM:\software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast'
        {
              ValueData = 1
              Key = 'HKLM:\software\Policies\Microsoft\Windows NT\DNSClient'
              TargetType = 'ComputerConfiguration'
              ValueName = 'EnableMulticast'
              ValueType = 'Dword'
		}
		
		RegistryPolicyFile 'Registry(POL): HKLM:\software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
		{
			ValueData = 196608
			Key = 'HKLM:\software\Policies\Microsoft\Windows\EventLog\Security'
			TargetType = 'ComputerConfiguration'
			ValueName = 'MaxSize'
			ValueType = 'Dword'
		}

    # UserRightsAssignment "CCE-36860-5: Configure 'Enable computer and user accounts to be trusted for delegation'"
		# {
		# 	Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
		# 	Force = $True
		# 	Identity = @()
		# }

		# UserRightsAssignment "CCE-36495-0: Ensure 'Lock pages in memory' is set to 'No One'"
		# {
		# 	Policy = 'Lock_pages_in_memory'
		# 	Force = $True
		# 	Identity = @()
		# }
		
		# UserRightsAssignment "CCE-36054-5: Ensure 'Modify an object label' is set to 'No One'"
		# {
		# 	Policy = 'Modify_an_object_label'
		# 	Force = $True
		# 	Identity = @()
		# }
    
		# UserRightsAssignment "CCE-36861-3: Ensure 'Create a token object' is set to 'No One'"
		# {
		# 	Policy = 'Create_a_token_object'
		# 	Force = $True
		# 	Identity = @()
		# }

		# UserRightsAssignment "CCE-36532-0: Ensure 'Create permanent shared objects' is set to 'No One'"
		# {
		# 	Policy = 'Create_permanent_shared_objects'
		# 	Force = $True
		# 	Identity = @()
		# }

		# UserRightsAssignment "CCE-37056-9: Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
		# {
		# 	Policy = 'Access_Credential_Manager_as_a_trusted_caller'
		# 	Force = $True
		# 	Identity = @()
		# }

		# UserRightsAssignment "CCE-36876-1: Ensure 'Act as part of the operating system' is set to 'No One'"
		# {
		# 	Policy = 'Act_as_part_of_the_operating_system'
		# 	Force = $True
		# 	Identity = @()
		# }

	}
}
SecurityBaselineConfig
Start-DscConfiguration -Path .\SecurityBaselineConfig\ -force -verbose
