##############################################################################
# Script Name   : Trimble_AzVm_App01_Post_Migration.ps1
# Author        : Naresh Vanamala
# Created Date  : 15th Dec 2022
# Version       : 1.0
# Description   : Script is useful for performing the Post migration Configuration
#                 Activities on Customer Application Server
# Example       : .\Trimble_AzVm_App01_Post_Migration.ps1 .\<CustName*>_App01_Post_Migration.csv
##############################################################################

############## Reading the Values from the CSV file ###########################
Param(
    [parameter(Mandatory = $true)]
    $CsvFilePath
)

$ErrorActionPreference = "stop"
##$ErrorActionPreference = "SilentlyContinue"

$scriptsPath = $PSScriptRoot
if ($PSScriptRoot -eq "") {
    $scriptsPath = "."
}

. "$scriptsPath\Trimble_AzVm_CommonMethods\TrimbleMigrateAutomation_Logger.ps1"
. "$scriptsPath\Trimble_AzVm_CommonMethods\TrimbleMigrateAutomation_CSV_Processor.ps1"

Function ProcessItemImpl($processor, $csvItem, $reportItem) {
    
    $reportItem | Add-Member NoteProperty "AdditionalInformation" $null
 try {   
    $AzTenantID = $csvItem.AZURE_TENANT_ID.Trim()
    if ([string]::IsNullOrEmpty($AzTenantID)) {
        $processor.Logger.LogError("AZURE_TENANT_ID is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_TENANT_ID is not mentioned in the csv file" 
        return
    }
    $AzSubscriptionID = $csvItem.AZURE_SUBSCRIPTION_ID.Trim()
    if ([string]::IsNullOrEmpty($AzSubscriptionID)) {
        $processor.Logger.LogError("AZURE_SUBSCRIPTION_ID is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_SUBSCRIPTION_ID is not mentioned in the csv file" 
        return
    }
    $AzLocation = $csvItem.AZURE_LOCATION.Trim()
    if ([string]::IsNullOrEmpty($AzLocation)) {
        $processor.Logger.LogError("AZURE_LOCATION is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_LOCATION is not mentioned in the csv file" 
        return
    }
    $AzResourceGroupName = $csvItem.AZURE_PROJ_RESOURCE_GROUP_NAME.Trim()
    if ([string]::IsNullOrEmpty($AzResourceGroupName)) {
        $processor.Logger.LogError("AZURE_PROJ_RESOURCE_GROUP_NAME is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_PROJ_RESOURCE_GROUP_NAME is not mentioned in the csv file" 
        return
    }
    $AzVMMachineName = $csvItem.SOURCE_MACHINE_NAME.Trim()
    if ([string]::IsNullOrEmpty($AzVMMachineName)) {
        $processor.Logger.LogError("SOURCE_MACHINE_NAME is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "SOURCE_MACHINE_NAME is not mentioned in the csv file" 
        return
    }
    $AzStorageAccountName = $csvItem.AZURE_STORAGE_ACCOUNT_NAME.Trim()
    if ([string]::IsNullOrEmpty($AzStorageAccountName)) {
        $processor.Logger.LogError("AZURE_STORAGE_ACCOUNT_NAME is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_STORAGE_ACCOUNT_NAME is not mentioned in the csv file" 
        return
    }
    $AzVmDiagnosticsConfigFile = $csvItem.AZURE_VM_DIAGNOSTICS_CONFIG_FILE_PATH.Trim()
    if ([string]::IsNullOrEmpty($AzVmDiagnosticsConfigFile)) {
        $processor.Logger.LogError("AZURE_VM_DIAGNOSTICS_CONFIG_FILE_PATH is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_VM_DIAGNOSTICS_CONFIG_FILE_PATH is not mentioned in the csv file" 
        return
    }
    $AzVmNewOSDiskSize = $csvItem.AZURE_VM_NEW_OS_DISK_SIZE.Trim()
    if ([string]::IsNullOrEmpty($AzVmNewOSDiskSize)) {
        $processor.Logger.LogError("AZURE_VM_NEW_OS_DISK_SIZE is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_VM_NEW_OS_DISK_SIZE is not mentioned in the csv file" 
        return
    } 
   
    $AzDCIPAddress = $csvItem.DC_IP_ADDRESS.Trim()
    if ([string]::IsNullOrEmpty($AzDCIPAddress)) {
        $processor.Logger.LogError("DC_IP_ADDRESS is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "DC_IP_ADDRESS is not mentioned in the csv file" 
        return
    }
    $AzStorageAccountKey = $csvItem.AZURE_STORAGE_ACCOUNT_KEY.Trim()
    $processor.Logger.LogTrace("AZURE_STORAGE_ACCOUNT_KEY"+ " "+ $AzStorageAccountKey)
        if ([string]::IsNullOrEmpty($AzStorageAccountKey)) {
            $processor.Logger.LogError("AZURE_STORAGE_ACCOUNT_KEY is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_STORAGE_ACCOUNT_KEY is not mentioned in the csv file" 
            return
        }
    }
    catch {
        $processor.Logger.LogTrace("Input Values are not provided properly in the csv file ")
    }
    ############## Get Az Virtual Machines from the resource group ###################
    $AzResourceGroupName
    $AzVMMachineName
    $processor.Logger.LogTrace("Going to start Enable Guest Level monitoring on Azure VM")
    $VirtualMachine = Get-AzVM -ResourceGroupName $AzResourceGroupName -Name $AzVMMachineName
    Write-Host 'This is new line' + $VirtualMachine.VmId +' Storage Account Name'+ $AzStorageAccountName
 try {
    ############## Enable Guest Level monitoring on Azure VM ###################
    $AzStorageAccount = Get-AzStorageAccount -ResourceGroupName $AzResourceGroupName -Name $AzStorageAccountName
    $AzVmDiagnosticsConfigFile
    $AzVmDiagnosticsConfigFilePath = "$ScriptsPath\Trimble_AzVm_CommonMethods\" + $AzVmDiagnosticsConfigFile
    
    $AzVmDiagnosticConfig = Get-Content $AzVmDiagnosticsConfigFilePath -raw | ConvertFrom-Json
    $AzVmDiagnosticConfig.update | ForEach-Object { if ($_.StorageAccount -ne $AzStorageAccount.Name) { $_.StorageAccount = $AzStorageAccount.Name } }
    $AzVmDiagnosticConfig | ConvertTo-Json -depth 32 | set-content $AzVmDiagnosticsConfigFilePath
    $processor.Logger.LogTrace("Started Enable Guest Level monitoring on Azure VM")
    ##$AzStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $AzResourceGroupName -Name $AzStorageAccount.StorageAccountName)[0].Value
    Set-AzVMDiagnosticsExtension -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -DiagnosticsConfigurationPath $AzVmDiagnosticsConfigFilePath -StorageAccountName $AzStorageAccount.StorageAccountName -StorageAccountKey $AzStorageAccountKey
    $processor.Logger.LogTrace("Going to update the virtual machine for storage account to reflect in Diagnostics settings")
    Update-AzVM -VM $VirtualMachine -ResourceGroupName $AzResourceGroupName
    $processor.Logger.LogTrace("Updated the virtual machine after Enable Guest Level monitoring on Azure VM is enabled")
    $processor.Logger.LogTrace("Enable Guest Level monitoring on Azure VM - Completed")
    ############## Configuring Microsoft.Insights.VMDiagnosticsSettings ###################
  
         $processor.Logger.LogTrace("Going to Stop the VM")
         Stop-AzVM -ResourceGroupName $AzResourceGroupName -Name $VirtualMachine.Name -Force
         $processor.Logger.LogTrace("VM Stopped")
        
         ######################Disk Resize for OS disk ###########################
         $processor.Logger.LogTrace("Going to start the OS Disk Resize in Azure")
    if ($AzVmNewOSDiskSize -gt $VirtualMachine.StorageProfile.OsDisk.DiskSizeGB) {
        $processor.Logger.LogTrace($VirtualMachine.StorageProfile.OsDisk.Name)
        $AzVmOSDisk = Get-AzDisk -ResourceGroupName $AzResourceGroupName -DiskName $VirtualMachine.StorageProfile.OsDisk.Name
        $AzVmOSDisk.DiskSizeGB = $AzVmNewOSDiskSize
        $processor.Logger.LogTrace("OS Disk Resize in Azure completed")
        Update-AzDisk -ResourceGroupName $AzResourceGroupName -Disk $AzVmOSDisk -DiskName $AzVmOSDisk.Name
        $processor.Logger.LogTrace("Update-AzDisk - Completed")
        
    }      
         ####################### Setting the Boot diagnostics update for the VM ######################
         $processor.Logger.LogTrace("Setting the Boot diagnostics update for the VM")
         $VM = Get-AzVM -ResourceGroupName $AzResourceGroupName -Name $AzVMMachineName
         Set-AzVMBootDiagnostic -VM $VM -Enable -ResourceGroupName $AzResourceGroupName -StorageAccountName $AzStorageAccount.StorageAccountName
         $processor.Logger.LogTrace("Completed Boot diagnostics update for the VM" + " " + $VirtualMachine.Name +" "+"Storgage Accounh"+" "+ $AzStorageAccount.StorageAccountName)
        #################### Update the virtual machine###################
         ####Update-AzVM -ResourceGroupName $AzResourceGroupName -VM $VirtualMachine
         Update-AzVM -VM $VM -ResourceGroupName $AzResourceGroupName
         $processor.Logger.LogTrace("Updated the virtual machine after Boot diagnostics on Azure VM is completed")


    ############################### Update the DNS entry of Azure VM ########################
    $processor.Logger.LogTrace("Going to Update DNS entry of Azure VM")
    $AzVmNICId = $VirtualMachine.NetworkProfile.NetworkInterfaces.Id
    $Lastposition = $AzVmNICId.LastIndexOf("/") + 1
    $AzVmNICIdLength = $AzVmNICId.Length

    $AzVmNICName = $AzVmNICId.Substring($Lastposition, $AzVmNICIdLength - $Lastposition)
    
    $AzVmNIC = Get-AzNetworkInterface -ResourceGroupName $AzResourceGroupName -Name $AzVmNICName
    $AzDCIPAddressValues = @()
    $AzDCIPAddressValues = $AzDCIPAddress.Split(",")
    
    foreach ($AzDCIPAddr in $AzDCIPAddressValues) {
        $AzVmNIC.DnsSettings.DnsServers.Add($AzDCIPAddr.Trim())
    }

    $AzVmNIC | Set-AzNetworkInterface
    $processor.Logger.LogTrace("Completed adding DNS ip's to VM NIC card")
    ####################### Start the VM after setting the DNS entry ######################
    $processor.Logger.LogTrace("going to start the VM" +" "+"$AzVMMachineName "+" "+$AzResourceGroupName)
    if($AzResourceGroupName -eq "null" -Or $AzVMMachineName -eq "null")
    {
        $AzResourceGroupNames = $csvItem.AZURE_PROJ_RESOURCE_GROUP_NAME.Trim()
        $AzVMMachineNames = $csvItem.SOURCE_MACHINE_NAME.Trim()
        $processor.Logger.LogTrace("going to start the VM from inside if condition" +" "+"$AzVMMachineNames "+" "+$AzResourceGroupNames)
        Start-AzVM -ResourceGroupName $AzResourceGroupNames -Name $AzVMMachineNames
    }
    else{
        $processor.Logger.LogTrace("going to start the VM from inside else condition" +" "+"$AzVMMachineName "+" "+$AzResourceGroupName)
        Start-AzVM -ResourceGroupName $AzResourceGroupName -Name $AzVMMachineName
    }   
    
    $processor.Logger.LogTrace("VM started")
    
 }
 catch {
        $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Available-Softwares-List not able to fetch from the $($VirtualMachine.Name)")
 }
############################## AzVm OS Disk Drive Expansion ###########################################
    try {
        
        $processor.Logger.LogTrace("Vm OS Disk Drive Expansion going to start")
        $VmExtendedDiskDriveOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' -ScriptPath "$scriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVm_Extend_Disk_Drive.ps1" -Parameter @{DriveId = "C" } -Verbose
    
        $processor.Logger.LogTrace($VmExtendedDiskDriveOut)
        $processor.Logger.LogTrace($VmExtendedDiskDriveOut.Value[0].Message)
        $processor.Logger.LogTrace("Vm OS Disk Drive Expansion completed")
    }
    catch {
        $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the Extended Disk Drive for $DriveId on $($VirtualMachine.Name) machine")
    }
    ################### AzVm Validating Automatic Services ###############################################
    try {
        $processor.Logger.LogTrace("Vm Validating Automatic Services going to start")
        $AutoServicesOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' -ScriptPath "$ScriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVm_AutoServices_Start.ps1" -Verbose
    
        $processor.Logger.LogTrace($AutoServicesOut)
        $processor.Logger.LogTrace($AutoServicesOut.Value[0].Message)
        $processor.Logger.LogTrace("Vm Validating Automatic Services completed")
    }
    catch {
        $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the Automated Services Start on $($VirtualMachine.Name) machine")
    }
    ################### AzVm Removing Old Host entries ###############################################
    try {
        $processor.Logger.LogTrace("Removing Old Host entries going to start")
        $AzVmRemovingHostEntriesOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' -ScriptPath "$ScriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVm_Clear_Host_Entries.ps1" -Verbose
    
        $processor.Logger.LogTrace($AzVmRemovingHostEntriesOut)
        $processor.Logger.LogTrace($AzVmRemovingHostEntriesOut.Value[0].Message)
        $processor.Logger.LogTrace("Removing Old Host entries completed")
    }
    catch {
        $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the Host Entries Detail on $($VirtualMachine.Name) machine")
    }

    ################### AzVm IP Configuration Lists ###############################################
#  try {
#     $processor.Logger.LogTrace("IP Configuration Lists for DNS names resolved going to start")
#     $IpConfigFolder = "IPConfigOutput"
#     if (Test-Path -Path $IpConfigFolder) {
#         $processor.Logger.LogTrace("IP COnfiguration Output Folder exists!")
#     }
#     else {
#         New-Item -Path 'IPConfigOutput' -ItemType Directory -Force
#     }

#     $AzIPConfigsListOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
#         -ScriptString "ipconfig /all" -Verbose
#     $processor.Logger.LogTrace($AzIPConfigsListOut.Value[0].Message)
#     $AzIPConfigsListOutFile = $AzIPConfigsListOut.Value[0].Message
#     $AzIPConfigsListOutFile | Out-File -FilePath "IPConfigOutput\$($VirtualMachine.Name)-DNS$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmss')).txt"

#     $processor.Logger.LogTrace("IP Configuration Lists for DNS names resolved completed")
#  }
#  catch {
#     $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the IP Config List on $($VirtualMachine.Name) machine")
#  }

    ####################### Manual Steps Execution Prompt ###############################       
    Write-Host
    Do {
        $ManualStepsPrompt = Read-Host -Prompt `
            "Perform the below steps Manually on $VirtualMachine.Name
            1. Update Citrix License server to Azure citrix license server in all APP Servers
            2. Enable session reliability in citrix studio
            Once you are done with the Steps, then Press Enter to process...!"
    
        If ($ManualStepsPrompt -notmatch "[yY]") {
            Write-Host "You did not enter a valid responce. Try again?"
        }
    }
    Until ($ManualStepsPrompt -match "[yY]") 


    ####################### Enabling Backup for Azure VM######################
    $AzRecoveryVault = Get-AzRecoveryServicesVault -ResourceGroupName $AzResourceGroupName
    If (-not $AzRecoveryVault) {
        $processor.Logger.LogTrace("No Recovery Services Vault Found in Resource Group.  This must be created before deploying VMs.")
        Return
    }

    $processor.Logger.LogTrace("Enabling Backups using the Azure Recovery Vault")
    Set-AzRecoveryServicesAsrVaultContext -Vault $AzRecoveryVault
    $BackupPolicy = Get-AzRecoveryServicesBackupProtectionPolicy -Name "DefaultPolicy" -VaultId $AzRecoveryVault.ID 
    Enable-AzRecoveryServicesBackupProtection -ResourceGroupName $AzResourceGroupName -Name $AzVMMachineName -Policy $BackupPolicy -VaultId $AzRecoveryVault.ID
    $processor.Logger.LogTrace("Enabling Backups using the Azure Recovery Vault completed")
}

Function ProcessItem($processor, $csvItem, $reportItem) {
    try {
        ProcessItemImpl $processor $csvItem $reportItem
    }
    catch {
        $exceptionMessage = $_ | Out-String
        $reportItem.Exception = $exceptionMessage
        $processor.Logger.LogErrorAndThrow($exceptionMessage)        
    }
}

$logger = New-TrimbleAutomation_LoggerInstance -CommandPath $PSCommandPath
$processor = New-CsvProcessorInstance -logger $logger -processItemFunction $function:ProcessItem
$processor.ProcessFile($CsvFilePath)

################ Verify Azure PowerShell Modules are installed #####################
If (Get-Module -ListAvailable -Name Az.*) {
    Write-Host "Azure Powershell Module Installed"
    Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"
}
Else {
    Write-Host "Azure Powershell Module Not Installed"
    Write-Host "Must install Azure Powershell Module"
    Write-Host "Run this command in powershell to install the module:"
    Write-Host
    Write-Host "Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force"
    write-host
    Read-Host -Prompt "Press Enter to quit..."
    Return
}

# ############# Check if this PowerShell session is already authentiated to Azure############
# $newAzSession = $false
# $azAccessToken = Get-AzAccessToken -ErrorAction SilentlyContinue
# Start-Sleep -Seconds 1
# If (-not $azAccessToken) {
#     $newAzSession = $true
# }
# ElseIf ((Get-Date).ToUniversalTime() -ge $azAccessToken.ExpiresOn.UtcDateTime) {
#     $newAzSession = $true
# }

# ############# Connect to Azure Subscription Account######################################33
# If ($newAzSession -eq $true) {
#     Write-Host "Authenticating to Azure Subscription"

#     Try {
#         Connect-AzAccount -Tenant $TenantID -SubscriptionID $SubscriptionID -ErrorAction Stop | Out-Null
#     }
#     Catch {
#         Write-Warning "Unable to connect to Azure, please close the script and run it again."
#         Read-Host -Prompt "Press ENTER to quit..."
#         Return
#     }
# }

# ################## Set Azure User Login Context ###########################################
# $azSubscription = Get-AzSubscription -TenantId $TenantID | Where-Object { $_.Name -Like "Devops*" } | Sort-Object Name
# If (-not $azSubscription) {
#     Write-Host
#     Write-Warning "Unable to query a list of Subscriptions in Azure"
#     Write-Host "Please close the script and try to run it again."
#     Read-Host -Prompt "Press ENTER to quit..."
#     Return
# } 
# If ($azSubscription) {
#     $azSubscription | Add-Member -NotePropertyName "Number" -NotePropertyValue 1
#     $azSubscription | Format-Table -Property Number, Name, Id, State
#     if ($azSubscription.length -gt 1) {
#         Do {
#             Write-Host
#             $subscriptionPrompt = Read-Host -Prompt "Enter the corresponding number next to the Subscription you'd like to work in."
#         }
#         Until ($subscriptionPrompt -In $azSubscription.Number)
#         $context = $azSubscription | Where-Object { $_.Number -eq $subscriptionPrompt }
#         Try {
#             Set-AzContext -Tenant $TenantID -Subscription $context.Id -ErrorAction Stop | Out-Null
#         }
#         Catch {
#             Write-Host
#             Write-Warning "Unable to Set Context to the $($context.Name) Subscription"
#             Write-Host "Please close the script and try to run it again."
#             Read-Host -Prompt "Press ENTER to quit..."
#             Return
#         }
#     }
# }

# $azContext = Get-AzContext
# If ($azContext) {
#     Write-Host
#     $processor.Logger. "Connected to Azure Subscription: $($azContext.Subscription.Name)"
# }
# ElseIf (-not $azContext) {
#     Write-Host
#     Write-Warning "Unable to verify connection to Azure Subscription"
#     Write-Host "Please close the script and try to run it again."
#     Read-Host -Prompt "Press ENTER to quit..."
#     Return
# }

############### Set Azure Location ###########################################
$azContext = Get-AzContext
If ($azContext) {
    If ($azContext.Subscription.Name -eq $SubscriptionName) {
        $Azlocation = $azLocationName
        Write-Host
        Write-Host "Location for Azure Resources is set to "+ $Azlocation
    }
}