##############################################################################
# File Name: Azure_RG_Tags_Update.ps1
# Author: Naresh Vanamala
# Date: 25th Jan 2022
# Version: 1.0
# Notes : Script is useful for updating the Tags in Trimble project Resource Group 
#         once after the configuration activity
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
    try {
        $AzTenantID = $csvItem.AZURE_TENANT_ID.Trim()
        if ($AzTenantID -eq '') {
            $processor.Logger.LogError("AZURE_TENANT_ID is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_TENANT_ID is not mentioned in the csv file" 
            return
        }
        $AzSubscriptionID = $csvItem.AZURE_SUBSCRIPTION_ID.Trim()
        if ($AzSubscriptionID -eq '') {
            $processor.Logger.LogError("AZURE_SUBSCRIPTION_ID is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_SUBSCRIPTION_ID is not mentioned in the csv file" 
            return
        }
        $AzSubscriptionName = $csvItem.AZURE_SUBSCRIPTION_NAME.Trim()
        if ($AzSubscriptionName -eq '') {
            $processor.Logger.LogError("AZURE_SUBSCRIPTION_NAME is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_SUBSCRIPTION_NAME is not mentioned in the csv file" 
            return
        }
        $AzLocation = $csvItem.AZURE_LOCATION.Trim()
        if ($AzLocation -eq '') {
            $processor.Logger.LogError("AZURE_LOCATION is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_LOCATION is not mentioned in the csv file" 
            return
        }
        $AzResourceGroupName = $csvItem.AZURE_PROJ_RESOURCE_GROUP_NAME.Trim()
        if ($AzResourceGroupName -eq '') {
            $processor.Logger.LogError("AZURE_PROJ_RESOURCE_GROUP_NAME is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_PROJ_RESOURCE_GROUP_NAME is not mentioned in the csv file" 
            return
        }
        $AzProductName = $csvItem.AZURE_PRODUCT_NAME.Trim()
        if ($AzProductName -eq '') {
            $processor.Logger.LogError("AZURE_PRODUCT_NAME is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_PRODUCT_NAME is not mentioned in the csv file" 
            return
        }
        $AzBusinessUnit = $csvItem.AZURE_BUSINESS_UNIT.Trim()
        if ($AzBusinessUnit -eq '') {
            $processor.Logger.LogError("AZURE_BUSINESS_UNIT is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_BUSINESS_UNIT is not mentioned in the csv file" 
            return
        }
        $AzProdTeam = $csvItem.AZURE_PROD_TEAM.Trim()
        if ($AzProdTeam -eq '') {
            $processor.Logger.LogError("AZURE_PROD_TEAM is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_PROD_TEAM is not mentioned in the csv file" 
            return
        }
        $AzBilling = $csvItem.AZURE_BILLING.Trim()
        if ($AzBilling -eq '') {
            $processor.Logger.LogError("AZURE_BILLING is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_BILLING is not mentioned in the csv file" 
            return
        }
        $AzEnvironment = $csvItem.AZURE_ENVIRONMENT.Trim()
        if ($AzEnvironment -eq '') {
            $processor.Logger.LogError("AZURE_ENVIRONMENT is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_ENVIRONMENT is not mentioned in the csv file" 
            return
        }
        $AzContactEmail = $csvItem.AZURE_CONTACT_EMAIL.Trim()
        if ($AzContactEmail -eq '') {
            $processor.Logger.LogError("AZURE_CONTACT_EMAIL is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_CONTACT_EMAIL is not mentioned in the csv file" 
            return
        }
        $AzContactName = $csvItem.AZURE_CONTACT_NAME.Trim()
        if ($AzContactName -eq '') {
            $processor.Logger.LogError("AZURE_CONTACT_NAME is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_CONTACT_NAME is not mentioned in the csv file" 
            return
        }
        $AzAutomationOptIn = $csvItem.AZURE_AUTOMATION_OPT_IN.Trim()
        if ($AzAutomationOptIn -eq '') {
            $processor.Logger.LogError("AZURE_AUTOMATION_OPT_IN is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_AUTOMATION_OPT_IN is not mentioned in the csv file" 
            return
        }
        $AzCustSalesforceId = $csvItem.AZURE_CUST_SALESFORCE_ID.Trim()
        if ($AzCustSalesforceId -eq '') {
            $processor.Logger.LogError("AZURE_CUST_SALESFORCE_ID is not mentioned in the csv file")
            $reportItem.AdditionalInformation = "AZURE_CUST_SALESFORCE_ID is not mentioned in the csv file" 
            return
        }
    }
    catch {
        $processor.Logger.LogTrace("Input Values are missing in the csv file ")
    }

    # Verify Azure PowerShell Modules are installed
    $processor.Logger.LogTrace("Verify Azure PowerShell Modules are installed")
    If (Get-Module -ListAvailable -Name Az.*) {
        $processor.Logger.LogTrace("Azure Powershell Module Installed")
        Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"
    }
    Else {
        $processor.Logger.LogTrace("Azure Powershell Module Not Installed")
        Return
    }

    # Check if this PowerShell session is already authentiated to Azure
    $processor.Logger.LogTrace("Check if this PowerShell session is already authentiated to Azure")
    $newAzSession = $false
    $AzAccessToken = Get-AzAccessToken -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    If (-not $AzAccessToken) {
        $newAzSession = $true
    }
    ElseIf ((Get-Date).ToUniversalTime() -ge $AzAccessToken.ExpiresOn.UtcDateTime) {
        $newAzSession = $true
    }

    #Connect to Azure
    $processor.Logger.LogTrace("Setting the Azure Context")
    $AzContext = Get-AzContext
    If ($AzContext) {
        If ($AzContext.Subscription.Name -eq $AzSubscriptionName) {
            $processor.Logger.LogTrace("Location for Azure Resources is set to " + $AzLocation)
        }
    }


    # Get Customer Resources
    $processor.Logger.LogTrace("Get Customer Resources")
    $AzResources = $null
    $ResourceGroup = $null

    $ResourceGroup = Get-AzResourceGroup -Name $AzResourceGroupName -ErrorAction SilentlyContinue
    If (-not $ResourceGroup) {
        Write-Host
        $processor.Logger.LogTrace("This Resource Group does not exist in the $($AzContext.Subscription.Name) Subscription. Please try again...")
    }
    $AzResources = Get-AzResource -ResourceGroupName $AzResourceGroupName
    $processor.Logger.LogTrace("Setting Tags for the following Azure Resources:")
    $AzResources | Format-Table -Property Name, ResourceType, Tags


    $processor.Logger.LogTrace("The details about the tags for the Azure resources")
    $AzTags = $null
    $AzTags = @{}
    
    $AzTags += @{'product | product-name' = $AzProductName }
    $AzTags += @{'business-unit' = $AzBusinessUnit }
    $AzTags += @{'team' = $AzProdTeam }
    $AzTags += @{'billing' = $AzBilling }
    $AzTags += @{'environment' = $AzEnvironment }
    $AzTags += @{'primary-contact-email' = $AzContactEmail }
    $AzTags += @{'primary-contact-name' = $AzContactName }
    $AzTags += @{'automation-opt-in' = $AzAutomationOptIn }

    If ($AzCustSalesforceId -ne '') {
        $AzTags += @{'customer | customer-name' = $AzCustSalesforceId }
    }

    Set-AzResourceGroup -Name $ResourceGroup.ResourceGroupName -Tag $AzTags
    foreach ($AzResource in $AzResources) {
        $AzResTags = @{}
        $AzResTags = $AzResource.Tags
        foreach ($AzRsTag in $AzResource.Tags.Keys) {
            foreach ($AzTag in $AzTags.keys) {
                if ($AzRsTag -eq $AzTag) {
                    $AzResTags.Remove($AzRsTag) | Out-Null
                }
            }
        }
        $AzResourceTags = $AzResTags + $AzTags
        Update-AzTag -ResourceId $AzResource.Id -Tag $AzResourceTags -Operation Replace
    }
    $processor.Logger.LogTrace("Completed Tags have been updated on resources in Resource Group Name:$($ResourceGroup.ResourceGroupName)")
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