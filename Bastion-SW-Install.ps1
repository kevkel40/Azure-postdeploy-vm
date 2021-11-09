<#
    .SYNOPSIS
    Install required software from internet on bastion vm's

    .DESCRIPTION
    Gets latest version number of PowerShell from internet, downloads & installs
    Uses list of required software based on machine name - datavm/webvm/qavm
    Downloads & installs required software
    
    .OUTPUTS
    Screen as collection of tabulated text

    .EXAMPLE
    PS> .\Bastion-SW-Install.ps1
    
#>

##### - PowerShell Core - #####
function get-powershelllatest ($realTagUrl, $version){
	$fileName = "PowerShell-$($version)-win-x64.msi"
	$Outfile = "$($env:TEMP)\$($fileName)"
	$realDownloadUrl = "$($realTagUrl.Replace('tag', 'download'))/$($fileName)"

	Write-Host "Downloading $($fileName) from github..." -Foregroundcolor Yellow
	Invoke-WebRequest -Uri $realDownloadUrl -OutFile $Outfile
	if(Test-Path $env:TEMP/$fileName){
		Write-Host "Installing $($fileName)..." -Foregroundcolor Yellow
		$arguments = "/i `"$($Outfile)`" /passive"
		Start-Process msiexec.exe -ArgumentList $arguments -Wait
	}
}

##### - PowerShell Core - #####
#Check latest version of PowerShell Core from github
$url = 'https://github.com/PowerShell/PowerShell/releases/latest'
$realTagUrl = (([System.Net.WebRequest]::Create($url)).GetResponse()).ResponseUri.OriginalString
$version = $realTagUrl.split('/')[-1].Trim('v')
Write-Host "Latest PowerShell version on github: $($version)" -Foregroundcolor Yellow

#Check version of PowerShell Core installed
try{
	Get-Item -path "HKLM:\SOFTWARE\Microsoft\PowerShellCore\InstalledVersions\31ab5147-9a97-4452-8443-d9709f0516e1" -erroraction stop
	if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShellCore\InstalledVersions\31ab5147-9a97-4452-8443-d9709f0516e1" -Name "SemanticVersion")."SemanticVersion" -match $version){
		Write-Host "PowerShell version $($version) is already installed, no further action required."
	}else{
		Write-Host "PowerShell version $($version) is currently installed, update required."
		get-powershelllatest $realTagUrl $version
	}
}catch{
	Write-Host "PowerShell Core install not detected, preparing to download from github"
	get-powershelllatest $realTagUrl $version
}

##### - Git Win - #####

function get-gitwinlatest ($realTagUrl, $version){
	$fileName = "git-$($version)-64-bit.exe"
	$Outfile = "$($env:TEMP)\$($fileName)"
	$realDownloadUrl = "$($realTagUrl.Replace('tag', 'download'))/$($fileName)"
	Write-Host "Downloading $($fileName) from github..." -Foregroundcolor Yellow
	Invoke-WebRequest -Uri $realDownloadUrl -OutFile $Outfile
	if(Test-Path $env:TEMP/$fileName){
		Write-Host "Installing $($fileName)..." -Foregroundcolor Yellow
		$arguments = @("/VERYSILENT","/NORESTART","/CURRENTUSER")
		Start-Process $Outfile -ArgumentList $arguments -Wait
	}
}

##### - Git Win - #####
#Check latest version of Git win from github
$url = 'https://github.com/git-for-windows/git/releases/latest'
$realTagUrl = (([System.Net.WebRequest]::Create($url)).GetResponse()).ResponseUri.OriginalString
$version = $realTagUrl.split('/')[-1].Trim('v').replace('.windows.1','')
#todo check if already installed

#Check version of Git win installed
try{
	Get-Item -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Git_is1" -erroraction stop
	if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Git_is1" -Name "DisplayVersion")."DisplayVersion" -match $version){
		Write-Host "Git Windows version $($version) is already installed, no further action required."
	}else{
		Write-Host "Git Windows version $($version) is currently installed, update required."
		get-gitwinlatest $realTagUrl $version
	}
}catch{
	Write-Host "Git Windows install not detected, preparing to download from github"
	get-gitwinlatest $realTagUrl $version
}

##### - Postman Win - #####
$url = 'https://dl.pstmn.io/download/latest/win64'
$fileName = "Postman-win64-Setup.exe"
$Outfile = "$($env:TEMP)\$($fileName)"
Invoke-WebRequest -Uri $url -Outfile $Outfile
if(Test-Path $env:TEMP/$fileName){
  Write-Host "Installing $($fileName)..." -Foregroundcolor Yellow
  $arguments = @("/s") #??
  Start-Process $Outfile -ArgumentList $arguments -Wait
}
##################################

function DownloadAndRunExeMSI($url, $arguments){
	Write-Host "Downloading $($url)" -Foregroundcolor Yellow
	#get output filename from URL
	$OutPutFile = $url.Split("/")[-1]
	Invoke-WebRequest -Uri $url -OutFile "$($env:TEMP)\$($OutPutFile)" -timeoutsec 1200
	switch($arguments){
		{$_ -match "MSI"}{
			Write-Host "Attempting to install $($url) with silent MSI arguments" -Foregroundcolor Yellow
			Start-Process -filepath MsiExec.exe -wait -ArgumentList ("/i","$($env:TEMP)\$($OutPutFile)","/qn")
			break
		}
		{$_ -match "/"} {
			Write-Host "Attempting to install $($url) with arguments" -Foregroundcolor Yellow
			Start-Process -filepath "$($env:TEMP)\$($OutPutFile)" -wait -ArgumentList $arguments		
			break
		}
		{($_ -like "") -or ($_ -like $null)}{
			Write-Host "Attempting to install $($url) with no arguments" -Foregroundcolor Yellow
			Start-Process -filepath "$($env:TEMP)\$($OutPutFile)" -wait 			
			break
		}
	}
}

$urls = @()

switch( hostname ){
	{$_ -match "datavm"}{
		#data team software
		write-host "datavm detected, selecting software" -Foregroundcolor Green
		$urls += @{
			"url" = 'https://sqlopsbuilds.azureedge.net/stable/4a45ba7cf20dd4129f1a08e5e776dfb33e3d1d1e/azuredatastudio-windows-setup-1.32.0.exe'
			"arguments" = @("/VERYSILENT","/NORESTART","/CURRENTUSER","/MERGETASKS=!runcode")
		}
		$urls += @{
			"url" = 'https://download.microsoft.com/download/A/E/3/AE32C485-B62B-4437-92F7-8B6B2C48CB40/StorageExplorer.exe'
			"arguments" = @("/VERYSILENT","/NORESTART","/CURRENTUSER","/MERGETASKS=!runcode","/SP-")
		}
		$urls += @{
			"url" = 'https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B993F11EB-8372-361A-18C9-9B64A947F988%7D%26lang%3Den%26browser%3D4%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dtrue%26ap%3Dx64-stable-statsdef_0%26brand%3DGCEA/dl/chrome/install/googlechromestandaloneenterprise64.msi'
			"arguments" = @("MSI")
		}
		$urls += @{
			"url" = 'https://cfhcable.dl.sourceforge.net/project/sevenzip/7-Zip/19.00/7z1900.exe'
			"arguments" = @("/S")
		}
		$urls += @{
			"url" = 'https://az764295.vo.msecnd.net/stable/6cba118ac49a1b88332f312a8f67186f7f3c1643/VSCodeUserSetup-x64-1.61.2.exe'
			"arguments" = @("/VERYSILENT","/NORESTART","/CURRENTUSER","/MERGETASKS=!runcode")
		}
	}
	{$_ -match "qavm"}{
		write-host "qavm detected, selecting software" -Foregroundcolor Green
		#QA team software
		$urls += @{
			"url" = 'https://sqlopsbuilds.azureedge.net/stable/4a45ba7cf20dd4129f1a08e5e776dfb33e3d1d1e/azuredatastudio-windows-setup-1.32.0.exe'
			"arguments" = @("/VERYSILENT","/NORESTART","/CURRENTUSER","/MERGETASKS=!runcode")
		}
		$urls += @{
			"url" = 'https://download.microsoft.com/download/A/E/3/AE32C485-B62B-4437-92F7-8B6B2C48CB40/StorageExplorer.exe'
			"arguments" = @("/VERYSILENT","/NORESTART","/CURRENTUSER","/MERGETASKS=!runcode","/SP-")
		}
		$urls += @{
			"url" = 'https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B993F11EB-8372-361A-18C9-9B64A947F988%7D%26lang%3Den%26browser%3D4%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dtrue%26ap%3Dx64-stable-statsdef_0%26brand%3DGCEA/dl/chrome/install/googlechromestandaloneenterprise64.msi'
			"arguments" = @("MSI")
		}
		$urls += @{
			"url" = 'https://cfhcable.dl.sourceforge.net/project/sevenzip/7-Zip/19.00/7z1900.exe'
			"arguments" = @("/S")
		}
		$urls += @{
			"url" = 'https://az764295.vo.msecnd.net/stable/6cba118ac49a1b88332f312a8f67186f7f3c1643/VSCodeUserSetup-x64-1.61.2.exe'
			"arguments" = @("/VERYSILENT","/NORESTART","/CURRENTUSER","/MERGETASKS=!runcode")
		}
		$urls += @{
			"url" = 'https://dbvis.com/product_download/dbvis-12.1.4/media/dbvis_windows-x64_12_1_4_jre.exe'
			"arguments" = "-q"
		}
		#intellij
		$configfile = "$($env:TEMP)\silent.config"
		Invoke-WebRequest -Uri 'https://download.jetbrains.com/idea/silent.config' -OutFile $configfile
			#doesn't work "arguments" = @("/S","/CONFIG=$($configfile)","/D=C:\Program Files\IntelliJ IDEA 2021")
		$urls += @{
			"url" = 'https://download-cdn.jetbrains.com/idea/ideaIC-2021.2.3.exe'
			"arguments" = ""
		}
		$urls += @{
			"url" = 'https://ninite.com/eclipse-filezilla-notepadplusplus-putty-sumatrapdf-winscp/ninite.exe'
			"arguments" = ""
		}
		#add routine to install maven 3.8.3
		Write-Host "Downloading Maven 3.8.3"
		Invoke-WebRequest -Uri 'https://dlcdn.apache.org/maven/maven-3/3.8.3/binaries/apache-maven-3.8.3-bin.zip' -OutFile "$($env:TEMP)\apache-maven-3.8.3-bin.zip"
		Write-Host "Expanding Maven 3.8.3"
		Expand-Archive -Path "$($env:TEMP)\apache-maven-3.8.3-bin.zip" -DestinationPath "$($env:APPDATA)"
		Write-Host "Setting Maven environment variables"
		[System.Environment]::SetEnvironmentVariable('MAVEN_HOME',"$($env:APPDATA)\apache-maven-3.8.3", 'Machine')
		[System.Environment]::SetEnvironmentVariable('M2_HOME',"$($env:APPDATA)\apache-maven-3.8.3", 'Machine')
		if(!($env:path -match "apache-maven-3.8.3")){
			[System.Environment]::SetEnvironmentVariable('PATH',"$($env:PATH);$($env:APPDATA)\apache-maven-3.8.3\bin", 'Machine')
		}
	}
	{$_ -match "webvm"}{
		write-host "webvm detected, selecting software" -Foregroundcolor Green
		#Web/API team software
		$urls += @{
			"url" = 'https://sqlopsbuilds.azureedge.net/stable/4a45ba7cf20dd4129f1a08e5e776dfb33e3d1d1e/azuredatastudio-windows-setup-1.32.0.exe'
			"arguments" = @("/VERYSILENT","/NORESTART","/CURRENTUSER","/MERGETASKS=!runcode")
		}
		$urls += @{
			"url" = 'https://download.microsoft.com/download/A/E/3/AE32C485-B62B-4437-92F7-8B6B2C48CB40/StorageExplorer.exe'
			"arguments" = @("/VERYSILENT","/NORESTART","/CURRENTUSER","/MERGETASKS=!runcode","/SP-")
		}
		$urls += @{
			"url" = 'https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B993F11EB-8372-361A-18C9-9B64A947F988%7D%26lang%3Den%26browser%3D4%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dtrue%26ap%3Dx64-stable-statsdef_0%26brand%3DGCEA/dl/chrome/install/googlechromestandaloneenterprise64.msi'
			"arguments" = @("MSI")
		}
		$urls += @{
			"url" = 'https://cfhcable.dl.sourceforge.net/project/sevenzip/7-Zip/19.00/7z1900.exe'
			"arguments" = @("/S")
		}
		$urls += @{
			"url" = 'https://az764295.vo.msecnd.net/stable/6cba118ac49a1b88332f312a8f67186f7f3c1643/VSCodeUserSetup-x64-1.61.2.exe'
			"arguments" = @("/VERYSILENT","/NORESTART","/CURRENTUSER","/MERGETASKS=!runcode")
		}
		$urls += @{
			"url" = 'https://ninite.com/filezilla-notepadplusplus-putty-sumatrapdf-winscp/ninite.exe'
			"arguments" = ""
		}
	}
	{$_ -match "infravm"}{
		write-host "Infravm detected, selecting software" -Foregroundcolor Green
		#Web/API team software
		$urls += @{
			"url" = 'https://sqlopsbuilds.azureedge.net/stable/4a45ba7cf20dd4129f1a08e5e776dfb33e3d1d1e/azuredatastudio-windows-setup-1.32.0.exe'
			"arguments" = @("/VERYSILENT","/NORESTART","/CURRENTUSER","/MERGETASKS=!runcode")
		}
		$urls += @{
			"url" = 'https://download.microsoft.com/download/A/E/3/AE32C485-B62B-4437-92F7-8B6B2C48CB40/StorageExplorer.exe'
			"arguments" = @("/VERYSILENT","/NORESTART","/CURRENTUSER","/MERGETASKS=!runcode","/SP-")
		}
		$urls += @{
			"url" = 'https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B993F11EB-8372-361A-18C9-9B64A947F988%7D%26lang%3Den%26browser%3D4%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dtrue%26ap%3Dx64-stable-statsdef_0%26brand%3DGCEA/dl/chrome/install/googlechromestandaloneenterprise64.msi'
			"arguments" = @("MSI")
		}
		$urls += @{
			"url" = 'https://cfhcable.dl.sourceforge.net/project/sevenzip/7-Zip/19.00/7z1900.exe'
			"arguments" = @("/S")
		}
		$urls += @{
			"url" = 'https://az764295.vo.msecnd.net/stable/6cba118ac49a1b88332f312a8f67186f7f3c1643/VSCodeUserSetup-x64-1.61.2.exe'
			"arguments" = @("/VERYSILENT","/NORESTART","/CURRENTUSER","/MERGETASKS=!runcode")
		}
		$urls += @{
			"url" = 'https://ninite.com/filezilla-notepadplusplus-putty-sumatrapdf-winscp/ninite.exe'
			"arguments" = ""
		}
	}
}

foreach($item in $urls){
	DownloadAndRunExeMSI $item.url $item.arguments
}
