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

#Install latest version of PowerShell
$url = 'https://github.com/PowerShell/PowerShell/releases/latest'
#$request = [System.Net.WebRequest]::Create($url)
#$response = ([System.Net.WebRequest]::Create($url)).GetResponse()
$realTagUrl = (([System.Net.WebRequest]::Create($url)).GetResponse()).ResponseUri.OriginalString

$version = $realTagUrl.split('/')[-1].Trim('v')
Write-Host "Latest PowerShell version on github: $($version)" -Foregroundcolor Yellow

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

##################################

function DownloadAndRunExe($url, $arguments){
	Write-Host "Downloading $($url)" -Foregroundcolor Yellow
	Invoke-WebRequest -Uri $url -OutFile "$($env:TEMP)\install.exe"
	if($arguments -notlike ""){
		Write-Host "Attempting to install $($url) with arguments" -Foregroundcolor Yellow
		Start-Process -filepath "$($env:TEMP)\install.exe" -wait -ArgumentList $arguments
	}else{
		Write-Host "Attempting to install $($url) with no arguments" -Foregroundcolor Yellow
		Start-Process -filepath "$($env:TEMP)\install.exe" -wait 
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
			"url" = 'https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7BCB508FFA-6B4E-A202-A703-3711137C171D%7D%26lang%3Den%26browser%3D4%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable-statsdef_1%26installdataindex%3Dempty/update2/installers/ChromeSetup.exe'
			#"url" = 'https://ninite.com/7zip-chrome-filezilla-putty-sumatrapdf-vscode-winscp/ninite.exe'
			"arguments" = ""
		}
	}
	{$_ -match "qavm"}{
		write-host "qavm detected, selecting software" -Foregroundcolor Green
		#QA team software
		$urls += @{
			"url" = 'https://sqlopsbuilds.azureedge.net/stable/4a45ba7cf20dd4129f1a08e5e776dfb33e3d1d1e/azuredatastudio-windows-setup-1.32.0.exe'
			"arguments" = "/VERYSILENT /NORESTART /CURRENTUSERS"
		}
		$urls += @{
			"url" = 'https://download.microsoft.com/download/A/E/3/AE32C485-B62B-4437-92F7-8B6B2C48CB40/StorageExplorer.exe'
			"arguments" = "/VERYSILENT /NORESTART /CURRENTUSERS"
		}
		$urls += @{
			"url" = 'https://ninite.com/7zip-chrome-eclipse-filezilla-notepadplusplus-putty-sumatrapdf-vscode-winscp/ninite.exe'
			"arguments" = ""
		}
	}
	{$_ -match "webvm"}{
		write-host "webvm detected, selecting software" -Foregroundcolor Green
		#Web/API team software
		$urls += @{
			"url" = 'https://download.microsoft.com/download/A/E/3/AE32C485-B62B-4437-92F7-8B6B2C48CB40/StorageExplorer.exe'
			"arguments" = "/VERYSILENT /NORESTART /CURRENTUSERS"
		}
		$urls += @{
			"url" = 'https://ninite.com/7zip-chrome-filezilla-notepadplusplus-putty-sumatrapdf-vscode-winscp/ninite.exe'
			"arguments" = ""
		}
	}
}

foreach($item in $urls){
	DownloadAndRunExe $item.url $item.arguments
}
