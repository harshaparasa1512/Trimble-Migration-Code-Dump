##############################################################################
# File Name: Trimble_AzNetwork_Setup.ps1
# Author: Naresh Vanamala
# Date: 17th Dec 2022
# Version: 1.0
# Notes : Script is useful for Deploying the Network resources before starting 
#         the Migration Activities on Trimble Servers
##############################################################################

############## Reading the Values from the CSV file ###########################
Param(
    [parameter(Mandatory = $true)]
    $CsvFilePath
)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$ErrorActionPreference = "Stop"

$scriptsPath = $PSScriptRoot
if ($PSScriptRoot -eq "") {
    $scriptsPath = "."
}

. "$scriptsPath\Trimble_AzVm_CommonMethods\TrimbleMigrateAutomation_Logger.ps1"
. "$scriptsPath\Trimble_AzVm_CommonMethods\TrimbleMigrateAutomation_CSV_Processor.ps1"

Function ProcessItemImpl($processor, $csvItem, $reportItem) {
    
    $reportItem | Add-Member NoteProperty "AdditionalInformation" $null
    
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
    $AzCustomerName = $csvItem.AZURE_PROJ_CUSTOMER_NAME.Trim()
    if ([string]::IsNullOrEmpty($AzCustomerName)) {
        $processor.Logger.LogError("AZURE_PROJ_CUSTOMER_NAME is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_PROJ_CUSTOMER_NAME is not mentioned in the csv file" 
        return
    }
    $AzResourceGroupName = $csvItem.AZURE_PROJ_RESOURCE_GROUP_NAME.Trim()
    if ([string]::IsNullOrEmpty($AzResourceGroupName)) {
        $processor.Logger.LogError("AZURE_PROJ_RESOURCE_GROUP_NAME is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_PROJ_RESOURCE_GROUP_NAME is not mentioned in the csv file" 
        return
    }
    $AzVNetName = $csvItem.AZURE_VNET_NAME.Trim()
    if ([string]::IsNullOrEmpty($AzVNetName)) {
        $processor.Logger.LogError("AZURE_VNET_NAME is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_VNET_NAME is not mentioned in the csv file" 
        return
    }
    $AzVNetAddressSpace = $csvItem.AZURE_VNET_ADDRESS.Trim()
    if ([string]::IsNullOrEmpty($AzVNetAddressSpace)) {
        $processor.Logger.LogError("AZURE_VNET_ADDRESS is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_VNET_ADDRESS is not mentioned in the csv file" 
        return
    }
    $AzFrontendSubnetName = $csvItem.AZURE_FRONTEND_SUBNET_NAME.Trim()
    if ([string]::IsNullOrEmpty($AzFrontendSubnetName)) {
        $processor.Logger.LogError("AZURE_FRONTEND_SUBNET_NAME is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_FRONTEND_SUBNET_NAME is not mentioned in the csv file" 
        return
    }
    $AzSubnetAddress = $csvItem.AZURE_SUBNET_ADDRESS.Trim()
    if ([string]::IsNullOrEmpty($AzSubnetAddress)) {
        $processor.Logger.LogError("AZURE_SUBNET_ADDRESS is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_SUBNET_ADDRESS is not mentioned in the csv file" 
        return
    }
    $AzFrontendIP1 = $csvItem.AZURE_FRONTEND_IP_1.Trim()
    if ([string]::IsNullOrEmpty($AzFrontendIP1)) {
        $processor.Logger.LogError("AZURE_FRONTEND_IP_1 is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_FRONTEND_IP_1 is not mentioned in the csv file" 
        return
    }
    $AzFrontendIP2 = $csvItem.AZURE_FRONTEND_IP_2.Trim()
    if ([string]::IsNullOrEmpty($AzFrontendIP2)) {
        $processor.Logger.LogError("AZURE_FRONTEND_IP_2 is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_FRONTEND_IP_2 is not mentioned in the csv file" 
        return
    }
    $AzNSGFrontendIP = $csvItem.AZURE_NSG_FRONTEND_IP.Trim()
    if ([string]::IsNullOrEmpty($AzNSGFrontendIP)) {
        $processor.Logger.LogError("AZURE_NSG_FRONTEND_IP is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_NSG_FRONTEND_IP is not mentioned in the csv file" 
        return
    }
    $AzSFFrontendIP = $csvItem.AZURE_SF_FRONTEND_IP.Trim()
    if ([string]::IsNullOrEmpty($AzSFFrontendIP)) {
        $processor.Logger.LogError("AZURE_SF_FRONTEND_IP is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_SF_FRONTEND_IP is not mentioned in the csv file" 
        return
    }
    $AzSFFrontendIP = $csvItem.AZURE_SF_FRONTEND_IP.Trim()
    if ([string]::IsNullOrEmpty($AzSFFrontendIP)) {
        $processor.Logger.LogError("AZURE_SF_FRONTEND_IP is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_SF_FRONTEND_IP is not mentioned in the csv file" 
        return
    }
    $AzVNetPeering = $csvItem.AZURE_VNET_PEERING.Trim()
    if ([string]::IsNullOrEmpty($AzVNetPeering)) {
        $processor.Logger.LogError("AZURE_VNET_PEERING is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_VNET_PEERING is not mentioned in the csv file" 
        return
    }
    $AzNSGFrontEnd = $csvItem.AZURE_NSG_FRONTEND.Trim()
    if ([string]::IsNullOrEmpty($AzNSGFrontEnd)) {
        $processor.Logger.LogError("AZURE_NSG_FRONTEND is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_NSG_FRONTEND is not mentioned in the csv file" 
        return
    }
    $AzSFFrontEnd = $csvItem.AZURE_SF_FRONTEND.Trim()
    if ([string]::IsNullOrEmpty($AzSFFrontEnd)) {
        $processor.Logger.LogError("AZURE_SF_FRONTEND is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_SF_FRONTEND is not mentioned in the csv file" 
        return
    }
    $AzLBRule = $csvItem.AZURE_LB_RULE.Trim()
    if ([string]::IsNullOrEmpty($AzLBRule)) {
        $processor.Logger.LogError("AZURE_LB_RULE is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_LB_RULE is not mentioned in the csv file" 
        return
    }
    $AzFWPublicIP = $csvItem.AZURE_FIREWALL_PUBLIC_IP.Trim()
    if ([string]::IsNullOrEmpty($AzFWPublicIP)) {
        $processor.Logger.LogError("AZURE_FIREWALL_PUBLIC_IP is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_FIREWALL_PUBLIC_IP is not mentioned in the csv file" 
        return
    }
    $AzStorageAccountName = $csvItem.AZURE_STORAGE_ACCOUNT_NAME.Trim()
    if ([string]::IsNullOrEmpty($AzStorageAccountName)) {
        $processor.Logger.LogError("AZURE_STORAGE_ACCOUNT_NAME is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_STORAGE_ACCOUNT_NAME is not mentioned in the csv file" 
        return  
    }
    $AzBackupVaultName = $csvItem.AZURE_BACKUP_VAULT_NAME.Trim()
    if ([string]::IsNullOrEmpty($AzBackupVaultName)) {
        $processor.Logger.LogError("AZURE_BACKUP_VAULT_NAME is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_BACKUP_VAULT_NAME is not mentioned in the csv file" 
        return  
    }
    $AzIPAddress = $csvItem.AZURE_IP_ADDRESS.Trim()
    if ([string]::IsNullOrEmpty($AzIPAddress)) {
        $processor.Logger.LogError("AZURE_IP_ADDRESS is not mentioned in the csv file")
        $reportItem.AdditionalInformation = "AZURE_IP_ADDRESS is not mentioned in the csv file" 
        return
    }
    ############## Get Details of Azure resource group ###################
    $AzResourceGroupName
    $AzVMMachineName

    ############## Creating a Azure Resource Group ###################
    New-AzResourceGroup -Name $AzResourceGroupName -Location $AzLocation

    ############## Creating the Subnet for Virtual Network ##############
    $AzSubnet = New-AzVirtualNetworkSubnetConfig -Name $AzSubnetName -AddressPrefix $AzSubnetAddress

    ############### Creating the Virtual Network##############
    $AzVirtualNetwork = New-AzVirtualNetwork -Name $AzVNetName -ResourceGroupName $AzResourceGroupName `
        -Location $AzLocation -AddressPrefix $AzVNetAddressSpace -Subnet $AzSubnet

    $AzVirtualNetwork | Set-AzVirtualNetwork

    $AzSubnet = Get-AzVirtualNetworkSubnetConfig -Name $AzSubnetName -VirtualNetwork $AzVirtualNetwork

    ############### Create Peering between Virtual Networks ###############
    $AzVNetPeeringValues = $AzVNetPeering.Split(",")
    
    foreach ($AzVNet in $AzVNetPeeringValues) {
        Add-AzVirtualNetworkPeering -Name $AzVirtualNetwork.Name+'To'+$AzVNet.Name `
            -VirtualNetwork $AzVirtualNetwork -RemoteVirtualNetworkId $AzVNet.Id
    }

    ############### Creating Network Security Group ###############

    $AzNetworkSecurityRule1 = New-AzNetworkSecurityRuleConfig -Name "rdp-rule" -Description "Allow RDP" `
        -Access Allow -Protocol Tcp -Direction Inbound -Priority 100 -SourceAddressPrefix `
        Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 3389

    $AzNetworkSecurityRule2 = New-AzNetworkSecurityRuleConfig -Name "web-rule" -Description "Allow HTTP" `
        -Access Allow -Protocol Tcp -Direction Inbound -Priority 101 -SourceAddressPrefix `
        Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 80

    $AzNetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName TestRG -Location westus `
        -Name "NSG-FrontEnd" -SecurityRules $AzNetworkSecurityRule1, $AzNetworkSecurityRule2

    ############### Creating athe Public IP address ###############
    $AzPublicIPAddressName = "Trimble-App-PublicIP"

    $AzPublicIPAddress = New-AzPublicIpAddress -Name $AzPublicIPAddressName -ResourceGroupName $ResourceGroupName `
        -Location $Location -Sku "Standard" -AllocationMethod "Static"

    # $publicIp = New-AzPublicIpAddress -Name $publicIpName -ResourceGroupName $rgName -AllocationMethod Static `
    # -Location $location -IpAddress 0.0.0.0 -PublicIpPrefix $publicIpPrefix -Sku Standard

    ############### Creating a Storage Account #####################
    New-AzStorageAccount -Name $AzStorageAccountName -ResourceGroupName $AzResourceGroupName `
        -Location $AzLocation
    
    ############### Creating a Recovery Service Backup Vault #####################
    New-AzRecoveryServicesVault -ResourceGroupName $AzResourceGroupName -Name $AzBackupVaultName `
        -Location $AzLocation

    Get-AzRecoveryServicesVault -Name $AzBackupVaultName | Set-AzRecoveryServicesVaultContext    
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

##################################################################################################