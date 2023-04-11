##############################################################################
# Script Name   : Trimble_AzVm_DC01_Post_Migration.ps1
# Author        : Naresh Vanamala
# Created Date  : 18th Dec 2022
# Version       : 1.0
# Description   : Script is useful for performing the Post migration Configuration
#                 Activities on Customer Domain Controller Server
# Example       : .\Trimble_AzVm_DC01_Post_Migration.ps1 .\<CustName*>_DC01_Post_Migration.csv
##############################################################################

############## Reading Values from the CSV file ###########################
Param(
    [parameter(Mandatory = $true)]
    $CsvFilePath
)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
##$ErrorActionPreference = "Stop"
$ErrorActionPreference = "SilentlyContinue"

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
        $processor.Logger.LogTrace("Input Values are not provided properly in the csv file ")
    }
    ############## Get Az Virtual Machines from the resource group ###################
    $processor.Logger.LogTrace("Get Az Virtual Machines from the resource group")
    $AzResourceGroupName
    $AzVMMachineName

    
try {

     ############## Enable Guest Level monitoring on Azure VM ###################
     $processor.Logger.LogTrace("Enable Guest Level monitoring on Azure VM - Started")
     $VirtualMachine = Get-AzVM -ResourceGroupName $AzResourceGroupName -Name $AzVMMachineName
     $AzStorageAccount = Get-AzStorageAccount -ResourceGroupName $AzResourceGroupName -Name $AzStorageAccountName
     $AzVmDiagnosticsConfigFile
     $AzVmDiagnosticsConfigFilePath = "$ScriptsPath\Trimble_AzVm_CommonMethods\" + $AzVmDiagnosticsConfigFile
    
     $AzVmDiagnosticConfig = Get-Content $AzVmDiagnosticsConfigFilePath -raw | ConvertFrom-Json
     $AzVmDiagnosticConfig.update | ForEach-Object { if ($_.StorageAccount -ne $AzStorageAccount.Name) { $_.StorageAccount = $AzStorageAccount.Name } }
     $AzVmDiagnosticConfig | ConvertTo-Json -depth 32 | set-content $AzVmDiagnosticsConfigFilePath
     ##$AzStorageAccountKey ="++SFZGgUy8vkevU57z8jCrT9QNlhSRF+VU7m6rqWLnRodmJzybNauv5EtX1wClU/aK1crAOtO4Pm+AStZqJPbA=="
     Set-AzVMDiagnosticsExtension -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -DiagnosticsConfigurationPath $AzVmDiagnosticsConfigFilePath -StorageAccountName $AzStorageAccount.StorageAccountName -StorageAccountKey $AzStorageAccountKey
     ##################### Update the virtual machine###################
     $processor.Logger.LogTrace("Going to update the virtual machine")
     Update-AzVM -ResourceGroupName $AzResourceGroupName -VM $VirtualMachine
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
        Update-AzDisk -ResourceGroupName $AzResourceGroupName -Disk $AzVmOSDisk -DiskName $AzVmOSDisk.Name
        $processor.Logger.LogTrace("Disk Resize for OS disk - Completed")
        
     }      
         ####################### Setting the Boot diagnostics update for the VM ######################
         $processor.Logger.LogTrace("Setting the Boot diagnostics update for the VM")
         $VM = Get-AzVM -ResourceGroupName $AzResourceGroupName -Name $AzVMMachineName
         Set-AzVMBootDiagnostic -VM $VM -Enable -ResourceGroupName $AzResourceGroupName -StorageAccountName $AzStorageAccount.StorageAccountName
         $processor.Logger.LogTrace("Completed Boot diagnostics update for the VM" + " " + $VirtualMachine.Name +" "+"Storgage Accounh"+" "+ $AzStorageAccount.StorageAccountName)
        #################### Update the virtual machine###################
         ####Update-AzVM -ResourceGroupName $AzResourceGroupName -VM $VirtualMachine
         Update-AzVM -VM $VM -ResourceGroupName $AzResourceGroupName
         $processor.Logger.LogTrace("Updated the Azure VM")
           
         ############################### Associate the DC DNS entry to Azure VM NIC ########################
         $processor.Logger.LogTrace("Adding DNS ip's to VM NIC card")
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
         $processor.Logger.LogTrace("Completed adding DNS ip's to VM NIC card")

         ####################### Start the VM after setting the DNS entry ######################
          ##$processor.Logger.LogTrace("Going to start the VM")
          #######Start-AzVM -ResourceGroupName $AzResourceGroupName -Name $VirtualMachine.Name
         ##Start-AzVM -ResourceGroupName $AzResourceGroupName -Name $AzVMMachineName
          ##$processor.Logger.LogTrace("VM started")
          ##$vmname = Get-AzVM -Name $AzVMMachineName
          ##$processor.Logger.LogTrace("Guest Level monitoring of Azure VM Diagnostics Value " + " " + $vmname.DiagnosticsProfile.BootDiagnostics)
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



               
    #   $processor.Logger.LogTrace("Going to Invoke-AzVMRunCommand") 
    #  Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $AzVMMachineName -CommandId RunPowerShellScript  -ScriptString {
    
    #     ######### Update the conditional forwarders DNS ##########################
    #     $processor.Logger.LogTrace("Going to start Updating the conditional forwarders in DNS")
    #     if(set-dnsserverforwarder -IPAddress 10.150.11.10,10.150.11.11){Write-Host "DNS Server forwarder added"}
    #     $processor.Logger.LogTrace("Added ip's 10.150.11.10,10.150.11.11 in DNS Server forwarder")
    #     $existingforwarder = (Get-DnsServerForwarder).IPAddress.IPAddressToString
    #     foreach($eachforwarder in $existingforwarder){
    #         if ($eachforwarder -like "10.12.*" ){
    #             $processor.Logger.LogTrace("Removing the ip's that with 10.12.*")    
    #         Remove-DnsServerForwarder -IPAddress $eachforwarder -confirm:$false
    #         write-host "DNSServer Forwarder starting with 10.12.. is removed from list"
    #         }
    #         else{
    #             write-host "no such 10.12.. DNS forwarder is found"
    #         }
    #     }
    #     #### DNS Client Cache #############################
    #     Write-Host "DNS Client cache is cleared"
    #     Clear-DnsClientCache
    #     $processor.Logger.LogTrace("DNS Client cache is cleared") 

    

    #     ### Create a User and add in group ####
    #     $processor.Logger.LogTrace("Adding the test user for testing the Citrix notepad")
    #     New-ADUser `
    #     -Name 'innomindsHRT' `
    #     -GivenName innomindsHRT `
    #     -Path 'OU=Users,OU=TMWCloud,DC=HRT,DC=LOCAL' `
    #     -ChangePasswordAtLogon $false `
    #     -AccountPassword (Read-Host -AsSecureString "Input User Password") `
    #     -Enabled $True
    #     Add-ADGroupMember -Identity CTX_Notepad -Members innomindsFFE
    #     $processor.Logger.LogTrace("Added test user and Added test user to the CTX_Notepad group")
    #  }

    
      ####################### Manual Steps Execution Prompt ###############################
     Write-Host
     Do {
        $ManualStepsPrompt = Read-Host -Prompt `
            "Perform the below steps Manually on $VirtualMachine.Name
                1. Ping DC server
                2. MS DNS Update
                3. #Update the conditional forwarders DNS.
                4. #Enable trust detection.
                5. Update the Group Policy
                6. Rename WSUS 
                7. #Create user in Active Directory. 
                8. #Users and Computers.        
                Once you are done with the Steps, Please press enter (Y or y) to process...!"    
        If ($ManualStepsPrompt -notmatch "[yY]") {
            Write-Host "You did not enter a valid responce. Try again?"
        }
    }
    Until ($ManualStepsPrompt -match "[yY]") 

    ####################### Restart the VM  ######################
    $processor.Logger.LogTrace("Restarting the VM ")
    Restart-AzVM -ResourceGroupName $AzResourceGroupName -Name $VirtualMachine.Name
    # Start-Sleep -Seconds 1
    $processor.Logger.LogTrace("Restarting the VM completed")

    

         ############################### Software Program Uninstallation Check ###########################################
         $processor.Logger.LogTrace("Software Program Uninstallation Check -Started")
         $SoftwareUninstallCheck = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
         -ScriptPath "$ScriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVm_SoftwareUninstallCheck.ps1" -Verbose
         $INSTALLED = $SoftwareUninstallCheck.Value[0].Message  #Checking the Output message
         $SoftwareFolder = 'Available-Softwares-List'
    if (Test-Path -Path $SoftwareFolder) {
          Write-Host "Available-Softwares-List Folder exists!"
          $processor.Logger.LogTrace("Available-Softwares-List Folder exists!")
    }
    else {
          New-Item -Path 'Available-Softwares-List' -ItemType Directory -Force
          $processor.Logger.LogTrace("Available-Softwares-List Folder Created! - $((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmss'))")
    }

          $INSTALLED | Out-File -FilePath "Available-Softwares-List\$($VirtualMachine.Name)-Available-Softwares-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmss')).txt"
}
catch {
        ## $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Available-Softwares-List not able to fetch from the $($VirtualMachine.Name)")
}

try {
    If ($INSTALLED.Contains("VMware Tools")) {
        # ############################## VMWare Program Uninstallation ###########################################
          $VMWareUninstallationOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
          -ScriptPath "$ScriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVM_Programs_VMWareUninstallation.ps1" -Verbose
          $processor.Logger.LogTrace("Uninstalling VMware Tools")
          $processor.Logger.LogTrace($VMWareUninstallationOut.Value[0].Message)
    }
    else {
          $processor.Logger.LogTrace("VMWARE TOOL is not available on Server")
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
            $processor.Logger.LogTrace("Uninstalling Commvault ContentStore")
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
    $processor.Logger.LogTrace("VMWARE TOOL and Commvault ContentStore is not available on Server")
}
$processor.Logger.LogTrace("Software Program Uninstallation Check- Completed")

############################## AzVm OS Disk Drive Expansion ###########################################
try {
    $processor.Logger.LogTrace("Vm OS Disk Drive Expansion going to start")
    $VmExtendedDiskDriveOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
        -ScriptPath "$scriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVm_Extend_Disk_Drive.ps1" -Parameter @{DriveId = "C" } -Verbose

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
    $AutoServicesOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
        -ScriptPath "$ScriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVm_AutoServices_Start.ps1" -Verbose

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
    $AzVmRemovingHostEntriesOut = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
        -ScriptPath "$ScriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVm_Clear_Host_Entries.ps1" -Verbose

    $processor.Logger.LogTrace($AzVmRemovingHostEntriesOut)
    $processor.Logger.LogTrace($AzVmRemovingHostEntriesOut.Value[0].Message)
    $processor.Logger.LogTrace("Removing Old Host entries completed")
}
catch {
    $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the Host Entries Detail on $($VirtualMachine.Name) machine")
}
################### AzVm IP Configuration Lists ###############################################
try {
    $processor.Logger.LogTrace("IP Configuration Lists for DNS names resolved going to start")
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
    $AzIPConfigsListOutFile | Out-File -FilePath "IPConfigOutput\$($VirtualMachine.Name)-DNS$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmss')).txt"

    $processor.Logger.LogTrace("IP Configuration Lists for DNS names resolved completed")
}
catch {
    $processor.Logger.LogTrace("Invoke-AzVMRunCommand: Check the IP Config List on $($VirtualMachine.Name) machine")
}


  #################### Read the MinimumTlsVersion property ###################
  $processor.Logger.LogTrace("configuring Storage account values")
    $CurrentStorageAccountTlsValue = (Get-AzStorageAccount -ResourceGroupName $AzResourceGroupName -Name $AzStorageAccountName).MinimumTlsVersion
    $processor.Logger.LogTrace($CurrentStorageAccountTlsValue)

    #################### Update the MinimumTlsVersion version for the storage account to TLS 1.2.###################
    Set-AzStorageAccount -ResourceGroupName $AzResourceGroupName -Name $AzStorageAccountName -MinimumTlsVersion TLS1_2

    #################### Read the MinimumTlsVersion property.###################
    $UpdatedStorageAccountTlsValue = (Get-AzStorageAccount -ResourceGroupName $AzResourceGroupName -Name $AzStorageAccountName).MinimumTlsVersion
    $processor.Logger.LogTrace($UpdatedStorageAccountTlsValue)
    
    #################### Update the Azure Storage Blob Delete Retention Policy###################
    Enable-AzStorageBlobDeleteRetentionPolicy -ResourceGroupName $AzResourceGroupName -StorageAccountName $AzStorageAccountName `
        -RetentionDays 7

    #################### Update the Azure Storage Container Delete Retention Policy###################
    Enable-AzStorageContainerDeleteRetentionPolicy -ResourceGroupName $AzResourceGroupName `
        -StorageAccountName $AzStorageAccountName -RetentionDays 7

    #################### Configure a Microsoft endpoint in storage account ###################
    Set-AzStorageAccount -ResourceGroupName $AzResourceGroupName -AccountName $AzStorageAccountName `
        -PublishMicrosoftEndpoint $true

    ##################### Change the storage account tier to Cool ####################
    Set-AzStorageAccount -ResourceGroupName $AzResourceGroupName -Name $AzStorageAccountName -AccessTier Cool -Force
    $processor.Logger.LogTrace("Completed configuring Storage account values")
    
    

        ####################### Restart the VM  ######################
        $processor.Logger.LogTrace("Restarting the VM after all configurations")
        Restart-AzVM -ResourceGroupName $AzResourceGroupName -Name $VirtualMachine.Name
        # Start-Sleep -Seconds 1
        $processor.Logger.LogTrace("Restarted the VM after all configurations")
        
        ###################### Enabling Backup for Azure VM######################
    try {
        $AzRecoveryVault = Get-AzRecoveryServicesVault -ResourceGroupName $AzResourceGroupName
        If (-not $AzRecoveryVault) {
            $processor.Logger.LogTrace("No Recovery Services Vault Found in Resource Group.  This must be created before deploying VMs.")
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
    
    ###################### Update the conditional forwarders DNS  #########################
    # $AzVnetDnsServerIP = @{}
    # $AzVnetDnsValues = $AzVnetDnsServers.Split(",")
    # $i = 0
    # foreach ($AzVnetDnsServerAddr in $AzVnetDnsValues) {
    #     $DnsServerIPText = "AzVnetDnsServerIP"
    #     $i += 1
    #     $AzVnetDnsServerIP.Add($DnsServerIPText + $i, $AzVnetDnsServerAddr.Trim())
    # }

    # $VmConditionalForwardersDNS = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $VirtualMachine.Name -CommandId 'RunPowerShellScript' `
    #     -ScriptPath "$scriptsPath\Trimble_AzVm_CommonMethods\Trimble_AzVm_DNSConditionalForwarders.ps1" -Parameter $AzVnetDnsServerIP

    # $processor.Logger.LogTrace($VmConditionalForwardersDNS.Value[0].Message)  

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
