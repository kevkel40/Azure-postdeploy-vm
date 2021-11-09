##### - Postman Win - #####
$url = 'https://dl.pstmn.io/download/latest/win64'
$fileName = "Postman-win64-Setup.exe"
$Outfile = "$($env:TEMP)\$($fileName)"
Invoke-WebRequest -Uri $url -Outfile $Outfile -timeoutsec 600
if(Test-Path "$($env:TEMP)\$($fileName)"){
  Write-Host "Installing $($fileName)..." -Foregroundcolor Yellow
  $arguments = @("/s") #??
  Start-Process $Outfile -ArgumentList $arguments -Wait -verbose
}else{Write-Host "unable to find $($env:TEMP)\$($fileName)..." -Foregroundcolor red}
##################################
