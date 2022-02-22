<#
    .SYNOPSIS
    Install required software from internet on bastion vm's for Web

    .DESCRIPTION
    Gets latest version number of IntelliJ and Eclipse from internet, downloads & installs
    
    .OUTPUTS
    Screen as collection of tabulated text

    .EXAMPLE
    PS> .\QA-Bastion-SW-Install.ps1
    
#>
trap
{
  $Err = ( get-error -newest 1 )
  Write-Host ($Err.Exception.Message).ToString() -foregroundcolor red
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


#Ninite installs require interaction
$urls += @{
	"url" = 'https://ninite.com/filezilla-notepadplusplus-putty-sumatrapdf-winscp/ninite.exe'
	"arguments" = ""
}

switch( hostname ){
	{$_ -match "datavm"}{
		#data team software
		write-host "Data vm detected, not installing software" -Foregroundcolor Red
	}
	{$_ -match "qavm"}{
		write-host "QA vm detected, not installing software" -Foregroundcolor Red
	}
	{$_ -match "webvm"}{
		write-host "Web vm detected, selecting software" -Foregroundcolor Green
		#Web/API team software
		#redis cli
		$url = "https://github.com/microsoftarchive/redis/releases/download/win-3.2.100/Redis-x64-3.2.100.msi"
		$fileName = $url.split("/")[-1]
		$Outfile = "$($env:TEMP)\$($fileName)"
		Write-Host "Downloading $($fileName)..." -Foregroundcolor Yellow
		Invoke-WebRequest -Uri $url -Outfile $Outfile
		if(Test-Path $Outfile){
		  Write-Host "Installing $($fileName)..." -Foregroundcolor Yellow
		 $arguments = @("/I $($Outfile)", "/quiet")
		  Start-Process msiexec.exe -ArgumentList $arguments -Wait
		}

		#install stunnel
		$url = "https://www.stunnel.org/downloads.html"
		$fileName = ((Invoke-WebRequest -uri $url).links |Where-Object{$_.href -like "*win64-installer.exe"}|Where-Object{$_.href -notlike "*/beta/*"}).href.split("/")[-1]
		$url = "https://www.stunnel.org/$(((Invoke-WebRequest -uri $url).links |Where-Object{$_.href -like '*win64-installer.exe'}|Where-Object{$_.href -notlike '*/beta/*'}).href)"
		$Outfile = "$($env:TEMP)\$($fileName)"
		Write-Host "Downloading $($fileName)..." -Foregroundcolor Yellow
		Invoke-WebRequest -Uri $url -Outfile $Outfile
		if(Test-Path $Outfile){
		  Write-Host "Installing $($fileName)..." -Foregroundcolor Yellow
		  $arguments = @("/AllUsers", "/S")
		  Start-Process $Outfile -ArgumentList $arguments -Wait
		}
		#need to configure stunnel
	}
	{$_ -match "infravm"}{
		write-host "Infravm detected, selecting software" -Foregroundcolor Green
		#Infra team software
	}
}

foreach($item in $urls){
	DownloadAndRunExeMSI $item.url $item.arguments
}
Exit 0