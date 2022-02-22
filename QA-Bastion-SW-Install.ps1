<#
    .SYNOPSIS
    Install required software from internet on bastion vm's for QA

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

switch( hostname ){
	{$_ -match "datavm"}{
		#data team software
		write-host "Data vm detected, not installing software" -Foregroundcolor Red
	}
	{$_ -match "qavm"}{
		write-host "QA vm detected, selecting software" -Foregroundcolor Green
		#QA team software
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
		Write-Host "Checking latest stable version of Maven available"
		$url = "https://dlcdn.apache.org/maven/maven-3/"
		$maven_versions = ((Invoke-WebRequest -Uri $url).links.href -match '\d.\d.\d').replace("/","")
		#get highest major version 
		$Major_version = @()
		foreach($version in $maven_versions){
			$Major_version += [int]$version.split(".")[0]
		}
		$Highest_Version = ($Major_version | Sort-Object | get-unique)[-1]
		$Current_Majors = @($maven_versions | where-object{$_ -like "$($Highest_Version).*"})
		if($Current_Majors.count -gt 1){
			#get highest minor version 
			$Minor_version = @()
			foreach($version in $Current_Majors){
				$Minor_version += [int]$version.split(".")[1]
			}
			$Highest_MinVersion = ($Minor_version | Sort-Object | get-unique)[-1]
			$Current_Minors = @($maven_versions | where-object{$_ -like "$($Highest_Version).$($Highest_MinVersion).*"})
			
			if($Current_Minors.count -gt 1){
				#get highest sub version 
				$Sub_version = @()
				foreach($version in $Current_Minors){
					$Sub_version += [int]$version.split(".")[-1]
				}
				$Highest_SubVersion = ($Sub_version | Sort-Object | get-unique)[-1]
			$desired_version = $maven_versions | where-object{$_ -like "$($Highest_Version).$($Highest_MinVersion).$($Highest_SubVersion)"}
			}else{
				$desired_version = $Current_Minors 
			}
		}else{
			$desired_version = $Current_Majors[0]
		}
		#build url for desired version
		$desiredurl = "$($url)$desired_version/binaries/apache-maven-$($desired_version)-bin.zip"
		Write-Host "Downloading Maven version $($desired_version)"
		Invoke-WebRequest -Uri $desiredurl -OutFile "$($env:TEMP)\apache-maven-$($desired_version)-bin.zip"
		Write-Host "Expanding Maven version $($desired_version)"
		Expand-Archive -Path "$($env:TEMP)\apache-maven-$($desired_version)-bin.zip" -DestinationPath "$($env:APPDATA)"
		Write-Host "Setting Maven environment variables"
		[System.Environment]::SetEnvironmentVariable('MAVEN_HOME',"$($env:APPDATA)\apache-maven-$($desired_version)", 'Machine')
		[System.Environment]::SetEnvironmentVariable('M2_HOME',"$($env:APPDATA)\apache-maven-$($desired_version)", 'Machine')
		if(!($env:path -match "apache-maven-$($desired_version)")){
			[System.Environment]::SetEnvironmentVariable('PATH',"$($env:PATH);$($env:APPDATA)\apache-maven-$($desired_version)\bin", 'Machine')
		}
		
		$urls += @{
			"url" = 'https://ninite.com/eclipse-filezilla-notepadplusplus-putty-sumatrapdf-winscp/ninite.exe'
			"arguments" = ""
		}
	}
	{$_ -match "webvm"}{
		write-host "Web vm detected, not installing software" -Foregroundcolor Red
	}
}
foreach($item in $urls){
	DownloadAndRunExeMSI $item.url $item.arguments
}
Exit 0