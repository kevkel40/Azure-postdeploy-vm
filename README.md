# Azure-postdeploy-vm
Group Policy Settings for stand alone Windows Server 2022 Datacenter 
Expand the contents of the GroupPolicy.zip file into the path C:\Windows\System32\GroupPolicy, overwriting the content and reboot the vm.

Scripts to run on Azure VM's post deployment to set security settings

Can be executed in PowerShell direct from web using format below:


Mostly silent, no prompts:
* IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/LeighdePaor/Azure-postdeploy-vm/main/short_az_bastion_secure.ps1')

* IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/LeighdePaor/Azure-postdeploy-vm/main/Bastion-SW-Install.ps1')

* IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/LeighdePaor/Azure-postdeploy-vm/main/Install-PostmanWin64.ps1')
