trap
{
  $Err = ( get-error -newest 1 )
  Write-Host ($Err.Exception.Message).ToString() -foregroundcolor red
}
try{Get-WindowsUpdate -Install -confirm:$false -forceinstall -acceptall -IgnoreRebootRequired -IgnoreUserInput -verbose -erroraction stop}catch{exit 1}