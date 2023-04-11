##############################################################################
# Script Name   : Trimble_AzVm_SQL01_Post_Migration.ps1
# Author        : BalaGanapathi refered document SQL script
# Created Date  : 13th Mar 2023
# Version       : 1.0
# Description   : Script is useful for performing the Post migration Configuration
#                 Activities on MS SQL Server
# Example       : .\Trimble_AzVm_DB2-Bala_Post_Migration.ps1 .\<CustName*>_DB2-Bala_Post_Migration.csv
##############################################################################

############## Reading Values from the CSV file ###########################
Param(
    [parameter(Mandatory = $true)]
    $CsvFilePath
)

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$ErrorActionPreference = "Continue"

$ScriptsPath = $PSScriptRoot
if ($PSScriptRoot -eq "") {
    $ScriptsPath = "."
}
. "$ScriptsPath\Trimble_AzVm_CommonMethods\TrimbleMigrateAutomation_Logger.ps1"
. "$ScriptsPath\Trimble_AzVm_CommonMethods\TrimbleMigrateAutomation_CSV_Processor.ps1"

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
        $AzVmDataDiskSize = $csvItem.AZURE_VM_DATA_DISK_SIZE.Trim()
        if ([string]::IsNullOrEmpty($AzVmDataDiskSize)) {
            $processor.Logger.LogError("AZURE_VM_DATA_DISK_SIZE is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_VM_DATA_DISK_SIZE is not mentioned in the csv file" 
            return
        }
        $AzVmDiskDriveId = $csvItem.AZURE_VM_DISK_DRIVE_ID.Trim()
        if ([string]::IsNullOrEmpty($AzVmDiskDriveId)) {
            $processor.Logger.LogError("AZURE_VM_DISK_DRIVE_ID is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_VM_DISK_DRIVE_ID is not mentioned in the csv file" 
            return
        }
        $AzDCIPAddress = $csvItem.AZURE_DC_IP_ADDRESS.Trim()
        if ([string]::IsNullOrEmpty($AzDCIPAddress)) {
            $processor.Logger.LogError("AZURE_DC_IP_ADDRESS is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_DC_IP_ADDRESS is not mentioned in the csv file" 
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
        $processor.Logger.LogError("Input Values are not provided in the csv file ")
    }
    ############## Get Az Virtual Machines from the resource group ###################
    $AzResourceGroupName
    $AzVMMachineName

    try {
        $VirtualMachine = Get-AzVM -ResourceGroupName $AzResourceGroupName -Name $AzVMMachineName
        $ResourceGroup = Get-AzResourceGroup -Name $AzResourceGroupName
        Write-Host 'Virtual Machine Name: ' $VirtualMachine.Name ' and ID: ' $VirtualMachine.VmId  ' Storage Account Name: ' $AzStorageAccountName
        $processor.Logger.LogTrace('Resource Group Name' + $ResourceGroup + ' and ID' + $VirtualMachine.VmId)
        $processor.Logger.LogTrace('Virtual Machine Name' + $VirtualMachine.Name + ' and ID' + $VirtualMachine.VmId + ' Storage Account Name' + $AzStorageAccountName)

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
    	
  
    	}
    catch {
     	$processor.Logger.LogTrace("Updated the virtual machine after Enable Guest Level monitoring on Azure VM $($VirtualMachine.Name) is enabled")
    	$processor.Logger.LogTrace("Enable Guest Level monitoring on Azure VM$($VirtualMachine.Name)- Completed")
    }

####################### Stop the VM  ######################
$processor.Logger.LogTrace("Stopping the VM $($VirtualMachine.Name)")
    Stop-AzVM -ResourceGroupName $AzResourceGroupName -Name $VirtualMachine.Name -Force
    try {
        ###################### Disk Resize for OS disk ###########################
        if ($AzVmNewOSDiskSize -gt $VirtualMachine.StorageProfile.OsDisk.DiskSizeGB) {        
            $processor.Logger.LogTrace($VirtualMachine.StorageProfile.OsDisk.Name)
            $AzVmOSDisk = Get-AzDisk -ResourceGroupName $AzResourceGroupName -DiskName $VirtualMachine.StorageProfile.OsDisk.Name
            $AzVmOSDisk.DiskSizeGB = $AzVmNewOSDiskSize

            Update-AzDisk -ResourceGroupName $AzResourceGroupName -Disk $AzVmOSDisk -DiskName $AzVmOSDisk.Name

            ##################### Update the virtual machine###################
            Update-AzVM -ResourceGroupName $AzResourceGroupName -VM $VirtualMachine
        }
        elseif ($AzVmNewOSDiskSize -eq $VirtualMachine.StorageProfile.OsDisk.DiskSizeGB) { 
            $processor.Logger.LogTrace("The Virtual Machine:$($VirtualMachine.Name) OS disk size is equal to the requested VM OS disk Size")
        }
    }
    catch {
        $processor.Logger.LogTrace("Verify the Os Disk Configuratoin on Azure VM: $($VirtualMachine.Name)")
    }
    try {
        ###################### Disk Resize for AzVm Data Disks ###########################
        $AzVmDataDiskSize = $AzVmDataDiskSize.split(",")
        for ($i = 1; $i -le $VirtualMachine.StorageProfile.DataDisks.Count; $i++) {
            $AzDataDisk = $VirtualMachine.StorageProfile.DataDisks[$i - 1]
            if($null -eq $AzVmDataDiskSize[$i - 1] -or $AzVmDataDiskSize[$i - 1] -eq ''){$AzVmDataDiskSize[$i - 1] = 0}
            $processor.Logger.LogTrace("The Virtual Machine :$($VirtualMachine.Name) Data Disk: $($AzDataDisk.Name) to be modified")
            $AzVmDataDisk = Get-AzDisk -ResourceGroupName $AzResourceGroupName -DiskName $VirtualMachine.StorageProfile.DataDisks[$i - 1].Name
            if ($AzVmDataDiskSize[$i - 1] -gt $AzVmDataDisk.DiskSizeGB) {
                $AzVmDataDisk.DiskSizeGB = $AzVmDataDiskSize[$i - 1]
                Update-AzDisk -ResourceGroupName $AzResourceGroupName -Disk $AzVmDataDisk -DiskName $AzVmDataDisk.Name
                            }
            elseif ($AzVmDataDiskSize[$i - 1] -ge $AzVmDataDisk.DiskSizeGB) { 
                $processor.Logger.LogTrace("The Virtual Machine:$($VirtualMachine.Name) Data disk size is equal to the requested Data disk Size")
            }
        }
    }
    catch {
        $processor.Logger.LogTrace("Verify the Data Disk Configuratoin on Azure VM: $($VirtualMachine.Name)")
    }

########################### update Datadisk Host caching as Readonly ##################

$processor.Logger.LogTrace("Updating the Datadisk Host caching as Readonly Azure VM $($VirtualMachine.StorageProfile.DataDisks.Name) is started")
Set-AzVMDataDisk -VM $VirtualMachine -Name $VirtualMachine.StorageProfile.DataDisks.Name -Caching ReadOnly  | Update-AzVM
    
     if($VirtualMachine.StorageProfile.DataDisks.length -ge 1){
      for($i=0;$i-lt$VirtualMachine.StorageProfile.DataDisks.length;$i++){
           if(!($VirtualMachine.StorageProfile.DataDisks[$i].Caching -match "ReadOnly")){
                set-DataDisk-caching -disknameentry $VirtualMachine.StorageProfile.DataDisks[$i].name
                 if(!($global:result.IsSuccessStatusCode -contains "true")){
                    set-DataDisk-caching -disknameentry $VirtualMachine.StorageProfile.DataDisks[$i].name
                 }
            }
       }
    }

 $processor.Logger.LogTrace("Updating the Datadisk Host caching as Readonly Azure VM $($VirtualMachine.StorageProfile.DataDisks.Name) is completed")



  

    ####################### Setting the Boot diagnostics update for the VM ######################
    $processor.Logger.LogTrace("Setting the Boot diagnostics update for the VM")
    $VM = Get-AzVM -ResourceGroupName $AzResourceGroupName -Name $AzVMMachineName
    Set-AzVMBootDiagnostic -VM $VM -Enable -ResourceGroupName $AzResourceGroupName -StorageAccountName $AzStorageAccount.StorageAccountName
    $processor.Logger.LogTrace("Completed Boot diagnostics update for the VM" + " " + $VirtualMachine.Name +" "+"Storage Account"+" "+ $AzStorageAccount.StorageAccountName)
    #################### Update the virtual machine###################
    ####Update-AzVM -ResourceGroupName $AzResourceGroupName -VM $VirtualMachine
    Update-AzVM -VM $VM -ResourceGroupName $AzResourceGroupName
    $processor.Logger.LogTrace("Updated the virtual machine after Boot diagnostics on Azure VM is completed")


    ################### Finding Storage Account #############################
    Write-Host "Finding Storage Account..."
    $processor.Logger.LogTrace("Finding Storage Account...")
    $AzStorageAccount = Get-AzStorageAccount -ResourceGroupName $AzResourceGroupName

    $AzPublicIP = (Invoke-WebRequest -uri "http://ifconfig.me/ip").Content
    If (-Not $AzPublicIP) {
        Write-Host
        $processor.Logger.LogTrace("Unable to acquire your Public IP Address")
        $processor.Logger.LogTrace("Open your prefered Web Browser and go to `"https://whatsmyip.org/`" on the same machine you're running this script from.")
    }
    If ($AzPublicIP -Match "^([0-9]{1,3}\.){3}[0-9]{1,3}$") {
        $processor.Logger.LogTrace("THe Public IP Address is valid")
    }

    $storageAcctIPRules = (Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $AzStorageAccount.ResourceGroupName -AccountName $AzStorageAccount.StorageAccountName).IpRules
    If ($storageAcctIPRules.IPAddressOrRange -NotContains $AzPublicIP) {
        $processor.Logger.LogTrace("Adding your Public IP Address ($AzPublicIP) to the Storage Account IP Range Allow List...")
        Add-AzStorageAccountNetworkRule -ResourceGroupName $AzStorageAccount.ResourceGroupName -AccountName $AzStorageAccount.StorageAccountName -IPAddressOrRange $AzPublicIP -AsJob | Wait-Job | Out-Null
        Start-Sleep -Seconds 5
        $storageAcctIPRules2 = (Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $AzStorageAccount.ResourceGroupName -AccountName $AzStorageAccount.StorageAccountName).IpRules
        If ($storageAcctIPRules2.IPAddressOrRange -NotContains $AzPublicIP) {
            $processor.Logger.LogTrace("Unable to add your Public IP address ($AzPublicIP) to the Storage Account ($($AzStorageAccount.StorageAccountName)) > Networking > Firewall > IP Range Allow List")
            $processor.Logger.LogTrace("Reccomend Manually setting this on the Azure Portal site and then return to this script.")
        }
    }

    # ####################### Restart the VM after setting the DNS entry ######################
    # Restart-AzVM -ResourceGroupName $AzResourceGroupName -Name $VirtualMachine.Name
    # Start-Sleep -Seconds 90

    

    ###################### Update the DNS entry of Azure VM ########################
    $AzVmNICId = $VirtualMachine.NetworkProfile.NetworkInterfaces.Id
    $Lastposition = $AzVmNICId.LastIndexOf("/") + 1
    $AzVmNICIdLength = $AzVmNICId.Length

    $AzVmNICName = $AzVmNICId.Substring($Lastposition, $AzVmNICIdLength - $Lastposition)
    $AzVmNIC = Get-AzNetworkInterface -ResourceGroupName $AzResourceGroupName -Name $AzVmNICName

    $AzDCIPAddressValues = @()
    $AzDCIPAddressValues = $AzDCIPAddress.Split(",")
    if ($AzDCIPAddressValues.count -gt 1) {
        foreach ($AzDCIPAddr in $AzDCIPAddressValues) {
            $AzVmNIC.DnsSettings.DnsServers.Add($AzDCIPAddr.Trim())
        }
    }
    else {
        $AzVmNIC.DnsSettings.DnsServers.Add($AzDCIPAddress.Trim())
    }
    $AzVmNIC | Set-AzNetworkInterface


    ####################### Start the VM ######################
Start-AzVM -ResourceGroupName $AzResourceGroupName -Name $VirtualMachine.Name
$processor.Logger.LogTrace("Started  the VM $($VirtualMachine.Name)")

    

    ############################## AzVm Disk Drives Expansion ###########################################
    $AzVmDiskIds = $AzVmDiskDriveId.Split(",")
    foreach ($DiskId in $AzVmDiskIds) {
        try {
            $VmExtendedDiskDriveOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
                -ScriptPath "$scriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVm_Extend_Disk_Drive.ps1" -Parameter @{DriveId = $DiskId } -Verbose

            $processor.Logger.LogTrace($VmExtendedDiskDriveOut)
            $processor.Logger.LogTrace($VmExtendedDiskDriveOut.Value[0].Message)
        }
        catch {
            $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the Extended Disk Drive for $DiskId on $($VirtualMachine.Name) machine")
        }
    }

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
    ####################### Restart the VM after setting the DNS entry ######################
    Restart-AzVM -ResourceGroupName $AzResourceGroupName -Name $VirtualMachine.Name
    $processor.Logger.LogTrace("Restart the VM after setting the DNS entry")
    Start-Sleep -Seconds 60

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
    
        $AzIPConfigsListOutFile = $processor.Logger.LogTrace($AzIPConfigsListOut.Value[0].Message)
        $AzIPConfigsListOutFile | Out-File -FilePath "IPConfigOutput\$($VirtualMachine.Name)-DNS$((Get-Date).ToUniversalTime().ToString(‘yyyyMMddTHHmmss’)).txt"
    }
    catch {
        $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the IP Config List on $($VirtualMachine.Name) machine")
    }
    ####################### Enabling Backup for Azure VM######################
    try {
        $AzRecoveryVault = Get-AzRecoveryServicesVault -ResourceGroupName $AzResourceGroupName
        If (-not $AzRecoveryVault) {
            $processor.Logger.LogTrace("No Recovery Services Vault Found in Resource Group $AzResourceGroupName.  Recovery Services Vault must be created before deploying VMs.")
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
    # Read-Host -Prompt "Install the Azure PowerShell Module, then press Enter to quit...!"
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