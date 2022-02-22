Param(
  #Parameter that can be modified to control which resource groups this runs against
  [Parameter(
      Mandatory=$true,
      ValueFromPipeline=$true,
      HelpMessage="Azure resource group name containing vm's top operate on."    
      )
  ]
  [String]
  $ResourceGroupName = $null,
  
  #Parameter that can be modified to control which Azure subscription is used
  [Parameter(
    Mandatory=$false,
    ValueFromPipeline=$false,
    HelpMessage="Name or part name of subscription to use"
    )
  ]
  [String]
  $Subscription = "netflix", #default is Pharma Data Portal non-prod subscription

  #Parameter that can be modified to control which Azure subscription is used
  [Parameter(
    Mandatory=$true,
    ValueFromPipeline=$false,
    HelpMessage="Path to powershell script to run on azure vm including name of file"
    )
  ]
  [String]
  $scriptname
)

trap
{
  $Err = ( get-error -newest 1 )
  Write-Host ($Err.Exception.Message).ToString() -foregroundcolor red
}

Clear-Host
#Check if script exists
if(!(Test-Path -Path $$scriptname -PathType Leaf -erroraction silentlycontinue)){throw "File not found: $($scriptname)"}


#check if Azure session already established, connect if not
try{
    $ActiveSubscription = (Get-AzContext).Subscription.Name -erroraction stop
    Write-Host "Active Azure session detected: $($ActiveSubscription)"
    if($ActiveSubscription -match $Subscription){
        Write-Host "Active Azure session $($ActiveSubscription) matches supplied $($Subscription)" -ForegroundColor Green
    }else{
        Write-Host "Active Azure session $($ActiveSubscription) does not match supplied $($Subscription), switching context." -ForegroundColor Red
        Set-AzContext -Subscription (Get-AzSubscription | Where-Object {$_.Name -match $Subscription}).id | Out-Null
    }
}catch{
    Write-Host "Active Azure session not detected - launching session connection in browser"
    try{
        Connect-AzAccount | Out-Null
        #context is currently setting to Genomics subscription using filter "ectgen3dcnonprod"
        Set-AzContext -Subscription (Get-AzSubscription | Where-Object {$_.Name -match $Subscription}).id | Out-Null
    }catch{Write-host "Unable to connect to connect of set Azure context to a subscription matching $($Subscription)" -ForegroundColor Red
        break
    }
}

#Get AZ VM objects
$AZVMs = Get-Azvm -status -ResourceGroupName $ResourceGroupName
#ensure vm's are powered on
Write-Host "Starting $($AZVMs.count) VMs"
$AZVMs|Where-Object{$_.powerstate -notlike "VM running"}|Start-AzVM -nowait
Write-Host "Checking status of starting VMs"

$VMsToMonitor = @()
foreach($AZVM in $AZVMs){
	Write-Host "Getting Status of VM $($AZVM.Name)" -foregroundcolor Yellow
	$DisplayStatus = ($AZVM | Get-Azvm -status).Statuses[1].DisplayStatus
	switch($DisplayStatus){
	  {$_ -notlike "VM running"} {
		  Write-Host "$($AZVM.Name): status $($DisplayStatus)" -foregroundcolor Red
		  $VMsToMonitor += $AZVM
	  }
	}
}

$Monitoring = $VMsToMonitor.count
$OverWatch = [System.Diagnostics.Stopwatch]::StartNew()
DO{
	foreach($AZVM in $VMsToMonitor){
		Write-Host "Getting Status of VM $($AZVM.Name)" -foregroundcolor Yellow
		$DisplayStatus = ($AZVM | Get-Azvm -status).Statuses[1].DisplayStatus
		switch($DisplayStatus){
		  {$_ -notlike "VM running"} {
			  Write-Host "$($AZVM.Name): status $($DisplayStatus)" -foregroundcolor Red
		  }
		  "VM running" {
			  Write-Host "$($AZVM.Name): status $($DisplayStatus)" -foregroundcolor Green
			  $Monitoring = ($Monitoring - 1)
		  }
		}
	}
  Write-Host "Wait 10 seconds" -foregroundcolor Yellow
	start-sleep -seconds 10
}While($Monitoring -gt 0)

#report on vm start duration
$OverWatchTimeTaken = $OverWatch.Elapsed.TotalMinutes
$OverWatch.Stop()
Write-Host "Completed checking start of $($VMsToMonitor.count) Azure VM's, time taken (mins): $($OverWatchTimeTaken)"


$OverWatch = [System.Diagnostics.Stopwatch]::StartNew()
#run local script on selected AZ running VM's
$AZVMs|ForEach-Object -Parallel {
  $out = Invoke-AzVMRunCommand -ResourceGroupName $_.ResourceGroupName -Name $_.Name -CommandId 'RunPowerShellScript' -ScriptPath $scriptname -asjob
}
#check scripts complete
$VMsToMonitor = @()
foreach($AZVM in $AZVMs){
	Write-Host "Getting Status of VM $($AZVM.Name)" -foregroundcolor Yellow
	$DisplayStatus = ($AZVM | Get-Azvm -status).Statuses[0].DisplayStatus
	switch($DisplayStatus){
	"Updating" {
		Write-Host "$($AZVM.Name): status $($DisplayStatus)" -foregroundcolor Red
		$VMsToMonitor += $AZVM
	}
	"Provisioning succeeded" {Write-Host "$($AZVM.Name): status $($DisplayStatus)" -foregroundcolor Green}
	default {Write-Host "$($AZVM.Name): status $($DisplayStatus)" -foregroundcolor Yellow}
	}
}


$Monitoring = $VMsToMonitor.count
#Track events
$TrackEvents = @()
DO{
	foreach($AZVM in $VMsToMonitor){
		Write-Host "Getting Status of VM $($AZVM.Name)" -foregroundcolor Yellow
		$DisplayStatus = ($AZVM | Get-Azvm -status).Statuses[0].DisplayStatus
		switch($DisplayStatus){
		"Updating" {
			Write-Host "$($AZVM.Name): status $($DisplayStatus)" -foregroundcolor Red
		}
		"Provisioning succeeded" {
			Write-Host "$($AZVM.Name): status $($DisplayStatus)" -foregroundcolor Green
			$Monitoring = ($Monitoring - 1)
		}
		default {Write-Host "$($AZVM.Name): status $($DisplayStatus)" -foregroundcolor Yellow}
		}
	}
	start-sleep -seconds 10
}While($Monitoring -gt 0)


#report on script run duration
$OverWatchTimeTaken = $OverWatch.Elapsed.TotalMinutes
$OverWatch.Stop()
Write-Host "Completed checking running of script $($scriptname) on $($VMsToMonitor.count) Azure VM's, time taken (mins): $($OverWatchTimeTaken)"