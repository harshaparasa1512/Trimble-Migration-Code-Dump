##############################################################################
# File Name: Trimble_AzVm_PUBWEB_Post_Migration.ps1
# Author: Naresh Vanamala
# Date: 29th Dec 2022
# Version: 1.0
# Notes : Script is useful for performing the Post migration Configuration
#         Activities on Pubweb Server
##############################################################################

############## Reading the Values from the CSV file ###########################
Param(
    [parameter(Mandatory = $true)]
    $CsvFilePath
)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$ErrorActionPreference = "Continue"

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
        $AzVnetName = $csvItem.AZURE_VNET_NAME.Trim()
        if ([string]::IsNullOrEmpty($AzVnetName)) {
            $processor.Logger.LogError("AZURE_VNET_NAME is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_VNET_NAME is not mentioned in the csv file" 
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
    }
    catch {
        $processor.Logger.LogTrace("Input Values are not provided in the csv file ")
    }
    ############## Get Az Virtual Machines from the resource group ###################
    $AzResourceGroupName
    $AzVMMachineName

    $VirtualMachine = Get-AzVM -ResourceGroupName $AzResourceGroupName -Name $AzVMMachineName
    Write-Host 'The Virtual Machine Id: ' + $VirtualMachine.VmId +' Storage Account Name: '+ $AzStorageAccountName

    ############## Enable Guest Level monitoring on Azure VM ###################
    $AzStorageAccount = Get-AzStorageAccount -ResourceGroupName $AzResourceGroupName -Name $AzStorageAccountName
    $AzVmDiagnosticsConfigFile
    $AzVmDiagnosticsConfigFilePath = "$scriptsPath\Trimble_AzVm_CommonMethods\" + $AzVmDiagnosticsConfigFile
    $AzVmDiagnosticsConfigFilePath
    Set-AzVMDiagnosticsExtension -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -DiagnosticsConfigurationPath $AzVmDiagnosticsConfigFilePath `
        -StorageAccountName $AzStorageAccount.StorageAccountName

    ##################### Update the virtual machine###################
    Update-AzVM -ResourceGroupName $AzResourceGroupName -VM $VirtualMachine

    ###################### Disk Resize for OS disk ###########################
    if ($AzVmNewOSDiskSize -gt $VirtualMachine.StorageProfile.OsDisk.DiskSizeGB) {

        ####################### Stop the VM before resizing the disk ######################
        Stop-AzVM -ResourceGroupName $AzResourceGroupName -Name $VirtualMachine.Name -Force
        $processor.Logger.LogTrace($VirtualMachine.StorageProfile.OsDisk.Name)
        $AzVmOSDisk = Get-AzDisk -ResourceGroupName $AzResourceGroupName -DiskName $VirtualMachine.StorageProfile.OsDisk.Name
        $AzVmOSDisk.DiskSizeGB = $AzVmNewOSDiskSize
        Update-AzDisk -ResourceGroupName $AzResourceGroupName -Disk $AzVmOSDisk -DiskName $AzVmOSDisk.Name
    }
    elseif ($AzVmNewOSDiskSize -ge $VirtualMachine.StorageProfile.OsDisk.DiskSizeGB) {
        ####################### Stop the VM before resizing the disk ######################
        Stop-AzVM -ResourceGroupName $AzResourceGroupName -Name $VirtualMachine.Name -Force   
    }

    ####################### Start the VM after resizing the OS disk ######################
    # Start-AzVM -ResourceGroupName $AzResourceGroupName -Name $VirtualMachine.Name

    ####################### Setting the Boot diagnostics update for the VM ######################
    Set-AzVMBootDiagnostic -VM $VirtualMachine -ResourceGroupName $AzResourceGroupName -StorageAccountName $AzStorageAccount.StorageAccountName -Enable

    ##################### Update the virtual machine###################
    Update-AzVM -ResourceGroupName $AzResourceGroupName -VM $VirtualMachine

    ############################### Update the DNS entry of Azure VM ########################
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

    ####################### Start the VM after DNS entry of Azure VM######################
    Start-AzVM -ResourceGroupName $AzResourceGroupName -Name $VirtualMachine.Name
    
    try {
        ############################### Software Program Uninstallation Check ###########################################
        $SoftwareUninstallCheck = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
            -ScriptPath "$ScriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVm_SoftwareUninstallCheck.ps1" -Verbose
    
        ######################Verify the Output message ###############################
        $INSTALLED = $SoftwareUninstallCheck.Value[0].Message  
        $Folder = 'Available-Softwares-List'
        if (Test-Path -Path $Folder) {
            Write-Host "Available-Softwares-List Folder exists!"
        }
        else {
            New-Item -Path 'Available-Softwares-List' -ItemType Directory -Force
        }
        $INSTALLED | Out-File -FilePath "Available-Softwares-List\$($VirtualMachine.Name)-Available-Softwares-$((Get-Date).ToUniversalTime().ToString(‘yyyyMMddTHHmmss’)).txt"
    }
    catch {
        $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Available-Softwares-List not able to fetch from the $($VirtualMachine.Name)")
    }
    try {
        If ($INSTALLED.Contains("VMware Tools")) {
            # ############################## VMWare Program Uninstallation ###########################################
            $VMWareUninstallationOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
                -ScriptPath "$ScriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVM_Programs_VMWareUninstallation.ps1" -Verbose
            $processor.Logger.LogTrace($VMWareUninstallationOut.Value[0].Message)
        }
        else {
            $processor.Logger.LogTrace("VMWARE Tools is not available on Server")
        }
    }
    catch {
        $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the VMWARE Tools Software Availability on $($VirtualMachine.Name) machine")
    }
    try {
        If ($INSTALLED.Contains("Commvault ContentStore")) {
            # ############################## CommVault Program Uninstallation ###########################################
            $CommVaultUninstallationOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
                -ScriptPath "$ScriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVM_Programs_CommVaultUninstallation.ps1" -Verbose
            $processor.Logger.LogTrace($CommVaultUninstallationOut.Value[0].Message)
        }
        else {
            $processor.Logger.LogTrace("Commvault ContentStore is not available on Server")
        }
    }
    catch {
        $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the Commvault ContentStore Software Availability on $($VirtualMachine.Name) machine")
    }

    try {
        If ($INSTALLED.Contains("TeamViewer")) {
            # ############################## Team Viewer Program Uninstallation ###########################################
            $TeamViewerUninstallationOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
                -ScriptPath "$ScriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVm_Programs_TeamViewer_Uninstallation.ps1" -Verbose
            $processor.Logger.LogTrace($TeamViewerUninstallationOut.Value[0].Message)
        }
        else {
            $processor.Logger.LogTrace("Team Viewer is not available on Server")
        }
    }
    catch {
        $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the Team Viewer Software Availability on $($VirtualMachine.Name) machine")
    }
    if ($null -eq $INSTALLED) {
        $processor.Logger.LogTrace("VMWARE TOOL or Commvault ContentStore or Team Viewer is not available on Server")
    }

    ############################## AzVm OS Disk Drive Expansion ###########################################
    try {
        $VmExtendedDiskDriveOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
            -ScriptPath "$scriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVm_Extend_Disk_Drive.ps1" -Parameter @{DriveId = "C" } -Verbose

        $processor.Logger.LogTrace($VmExtendedDiskDriveOut)
        $processor.Logger.LogTrace($VmExtendedDiskDriveOut.Value[0].Message)
    }
    catch {
        $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the Extended Disk Drive for $DriveId on $($VirtualMachine.Name) machine")
    }
    ################### AzVm Validating Automatic Services ###############################################
    try {
        $AutoServicesOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
            -ScriptPath "$scriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVm_AutoServices_Start.ps1" -Verbose

        $processor.Logger.LogTrace = $AutoServicesOut.Value[0].Message
    }
    catch {
        $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the Automated Services Start on $($VirtualMachine.Name) machine")
    }
    ################### AzVm Removing Old Host entries ###############################################
    try {
        $AzVmRemovingHostEntriesOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
            -ScriptPath "$scriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVm_Clear_Host_Entries.ps1" -Verbose

        $processor.Logger.LogTrace = $AzVmRemovingHostEntriesOut.Value[0].Message
    }
    catch {
        $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the Host Entries Detail on $($VirtualMachine.Name) machine")
    }
    ################### AzVm IP Configuration Lists ###############################################
    try {
        $IpConfigFolder = "IPConfigOutput"
        if (Test-Path -Path $IpConfigFolder) {
            $processor.Logger.LogTrace("IP COnfiguration Output Folder exists!")
        }
        else {
            New-Item -Path 'IPConfigOutput' -ItemType Directory -Force
        }
    
        $AzIPConfigsListOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
            -ScriptString "ipconfig /all" -Verbose
        $processor.Logger.LogTrace($AzIPConfigsListOut.Value[0].Message)
        $AzIPConfigsListOutFile = $AzIPConfigsListOut.Value[0].Message
        $AzIPConfigsListOutFile | Out-File -FilePath "IPConfigOutput\$($VirtualMachine.Name)-DNS$((Get-Date).ToUniversalTime().ToString(‘yyyyMMddTHHmmss’)).txt"
    
    }
    catch {
        $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the IP Config List on $($VirtualMachine.Name) machine")
    }

    ####################### Enabling Backup for Azure VM######################
    try {
        $AzRecoveryVault = Get-AzRecoveryServicesVault -ResourceGroupName $AzResourceGroupName
        If (-not $AzRecoveryVault) {
            $processor.Logger.LogTrace("No Azure Recovery Services Vault Found in the Resource Group. This must be created before deploying VMs.")
            Return
        }
    
        $processor.Logger.LogTrace("Enabling Backups using the Azure Recovery Vault")
        Set-AzRecoveryServicesAsrVaultContext -Vault $AzRecoveryVault
        $BackupPolicy = Get-AzRecoveryServicesBackupProtectionPolicy -Name "DefaultPolicy" -VaultId $AzRecoveryVault.ID
        Enable-AzRecoveryServicesBackupProtection -ResourceGroupName $AzResourceGroupName -Name $VirtualMachine.Name -Policy $BackupPolicy -VaultId $AzRecoveryVault.ID
    }
    
    catch {
        $processor.Logger.LogTrace("No Azure Recovery Services Vault Found in the Resource Group.")
    }
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
    $processor.Logger.LogTrace("Azure Powershell Module Installed")
    Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"
}
Else {
    $processor.Logger.LogTrace("Azure Powershell Module Not Installed")
    $processor.Logger.LogTrace("Must install Azure Powershell Module")
    $processor.Logger.LogTrace("Run this command in powershell to install the module:")
    $processor.Logger.LogTrace("Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force")
    Write-Host "Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force"
    write-host
    Read-Host -Prompt "Install the Azure PowerShell Module, then press Enter to quit..."
    Return
}

############### Set Azure Location ###########################################
$azContext = Get-AzContext
If ($azContext) {
    If ($azContext.Subscription.Name -eq $SubscriptionName) {
        $Azlocation = $azLocationName
        Write-Host
        $processor.Logger.LogTrace("Location for Azure Resources is set to " + $Azlocation)
    }
}