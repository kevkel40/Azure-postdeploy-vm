trap
{
  $Err = ( get-error -newest 1 )
  Write-Host ($Err.Exception.Message).ToString() -foregroundcolor red
}
$arguments = "ADD HKLM\SOFTWARE\Qualys\QualysAgent\ScanOnDemand\Vulnerability /v ScanOnDemand /t REG_DWORD /d 1 /f"
try{Start-Process reg.exe -ArgumentList $arguments -Wait -ErrorAction stop}catch{exit 1}