############## Reading the Values from the JSON file ###########################
$TMAzRebootTime = Get-Content -Path Trimble_Azvm_Server_LastReboot_TimeStamp.json | ConvertFrom-Json
$TenantID = $TMAzRebootTime.TenantID
$SubscriptionID = $TMAzRebootTime.SubscriptionID
$SubscriptionName = $TMAzRebootTime.SubscriptionName
$AzResourceGroupName = $TMAzRebootTime.ResourceGroupName
$AzVmInstances = $TMAzRebootTime.AzVmInstances

$UptimeReport = @()
$AzVmNames = $AzVmInstances.Split(",")
$Folder = 'AzVmLastBootUptimeReport'
if (Test-Path -Path $Folder) {
    Write-Host "AzVmLastBootUptimeReport Folder exists!"
}
else {
    New-Item -Path 'AzVmLastBootUptimeReport' -ItemType Directory -Force
}
# Get the details from each virtual machine
foreach ($AzVm in $AzVmNames) {
    #Get the Last boot Timestamp and instance Details
    $VmBootDetails = @()
    $VmLastRebootDetails = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $AzVm -CommandId 'RunPowerShellScript' `
        -ScriptPath ".\CommonMethods\LastRebootTime.ps1" -Verbose
    #Checking the Output message  
    $VmBootDetails = $VmLastRebootDetails.Value[0].Message
    $VmBootDetails
    if ($VmBootDetails) {
        # $UptimeData =  $VmBootDetails #| Select-Object CSName, LastBootUpTime   
        $UptimeData =  $VmBootDetails | Format-Table
        $UptimeReport += $UptimeData
    }
}

$UptimeReport | Out-File -FilePath "AzVmLastBootUptimeReport\AzVm-LastBootUpTime-$((Get-Date).ToUniversalTime().ToString(‘yyyyMMddTHHmmss’)).txt"