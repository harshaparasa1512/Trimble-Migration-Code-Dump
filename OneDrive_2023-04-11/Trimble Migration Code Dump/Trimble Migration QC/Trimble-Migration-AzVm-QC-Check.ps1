##############################################################################
# Script Name   : Trimble-Migration-AZVM-QC-CHECK.ps1
# Author        : Naresh Vanamala
# Created Date  : 26th Dec 2022
# Version       : 1.0
# Description   : PowerShell Script is useful for performing the Trimble    
#                  Migration QC Check for Post-Migration Configuration
# Example       : 
##############################################################################

# Below parameters are needed by the script
# [CmdletBinding()]
# Param (
#     # The subscription name
#     [Parameter(Mandatory = $true)]
#     [string] $InputFolderPath,
    
#     # FOlder path where the output CSVs will be created
#     [Parameter(Mandatory = $true)]
#     [string] $OutputFolderPath,

#     # Name of the subscription where validation needs to be performed
#     [Parameter(Mandatory = $true)]
#     [string] $SubscriptionName,

#     # Name of the subscription where validation needs to be performed
#     [Parameter(Mandatory = $true)]
#     [string] $AzResourceGroupName,

#     # Name of the subscription where validation needs to be performed
#     [Parameter(Mandatory = $true)]
#     [string] $AzStorageAccountName
# )
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
# Assigning the values from the Input json file 
$TMAzQC = Get-Content -Path Trimble-Migration-AzVm-QC-Check.json | ConvertFrom-Json
$InputFolderPath = $TMAzQC.InputFolderPath
$OutputFolderPath = $TMAzQC.OutputFolderPath
$AzTenantID = $TMAzQC.AzTenantID
$SubscriptionName = $TMAzQC.SubscriptionName
$AzResourceGroupName = $TMAzQC.AzResourceGroupName
$AzStorageAccountName = $TMAzQC.AzStorageAccountName

Function Get-DC-QC {
    [hashtable]$VMCheckData = @{}

    #DNS Entry Check
    $AzVM = Get-AzVM -Name $ResourceName -ResourceGroupName $AzResourceGroupName
    $AzVmNICId = $AzVM.NetworkProfile.NetworkInterfaces.Id
    $Lastposition = $AzVmNICId.LastIndexOf("/") + 1
    $AzVmNICIdLength = $AzVmNICId.Length

    $AzVmNICName = $AzVmNICId.Substring($Lastposition, $AzVmNICIdLength - $Lastposition)
    $AzVmNIC = Get-AzNetworkInterface -ResourceGroupName $AzResourceGroupName -Name $AzVmNICName
    $AzDCIPAddressValues = @()
    $AzDCIPAddressValues = $AzVmNIC.DnsSettings.AppliedDnsServers
    
    # Add values to hash table
    if ($null -eq $AzDCIPAddressValues[1]) {
        $VMCheckData.Add("DNS_FORWARDERS", $AzDCIPAddressValues[0])
    }
    else {
        $VMCheckData.Add("DNS_FORWARDERS", $AzDCIPAddressValues[0] + "," + $AzDCIPAddressValues[1])
    }

    # Software Uninstallation Check
    $SoftwareUninstallCheck = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $AzVM.Name -CommandId 'RunPowerShellScript' `
        -ScriptPath ".\CommonMethods\SoftwareUninstallCheck.ps1" -Verbose

    $INSTALLED = $SoftwareUninstallCheck.Value[0].Message  #Checking the Output message
    $Folder = 'Available-Softwares-List'
    if (Test-Path -Path $Folder) {
        Write-Host "Available-Softwares-List Folder exists!"
    }
    else {
        New-Item -Path 'Available-Softwares-List' -ItemType Directory -Force
    }
    
    $INSTALLED | Out-File -FilePath "Available-Softwares-List\$($AzVM.Name)-Available-Softwares-$((Get-Date).ToUniversalTime().ToString(‘yyyyMMddTHHmmss’)).txt"

    If ($INSTALLED.Contains("VMware Tools")) {
        $VMCheckData.Add("UNISTALL_VMWARE_TOOL", "Still Available")
    }
    else {
        $VMCheckData.Add("UNISTALL_VMWARE_TOOL", "Uninstalled")
    }
    If ($INSTALLED.Contains("Commvault ContentStore")) {
        $VMCheckData.Add("UNISTALL_COMMVAULT_TOOL", "Still Available")
    }
    else {
        $VMCheckData.Add("UNISTALL_COMMVAULT_TOOL", "Uninstalled")
    }


    # C Drive Expansion Check 
    $DriveExpansionCheck = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $AzVM.Name -CommandId 'RunPowerShellScript' `
        -ScriptPath ".\CommonMethods\DriveExpansionCheck.ps1" -Parameter @{DriveId = "C:" } -Verbose    
    $DriveExpandedSize = $DriveExpansionCheck.Value[0].Message  #Checking the Output message
    $VMCheckData.Add("C_DRIVE_EXPANDED_SIZE", $DriveExpandedSize)

    # Window Services Running statsus Check
    $ServiceStopCheck = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $AzVM.Name -CommandId 'RunPowerShellScript' `
        -ScriptPath ".\CommonMethods\WindowsAutoServicesCheck.ps1" -Verbose
    $AutoServiceCheck = $ServiceStopCheck.Value[0].Message  #Checking the Output message
    $VMCheckData.Add("NO_OF_AUTOMATIC_SERVICES", $AutoServiceCheck)

    # Host File statsus Check
    $HostFileCheck = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $AzVM.Name -CommandId 'RunPowerShellScript' `
        -ScriptPath ".\CommonMethods\HostFileCheck.ps1" -Verbose
    $HostFileData = $HostFileCheck.Value[0].Message  #Checking the Output message
    Write-Host "$HostFileData"
    if ($HostFileData -eq "") {
        $VMCheckData.Add("HOSTS_ENTRIES_PRESENCE", "Removed")
    }
    elseif (($HostFileData -ne "")) {
        $VMCheckData.Add("HOSTS_ENTRIES_PRESENCE", "Present")
    }

    # DNS Names Check
    $DNSNamesCheck = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $AzVM.Name -CommandId 'RunPowerShellScript' `
        -ScriptPath ".\CommonMethods\DNSServersIPCheck.ps1" -Verbose
    $DNSValues = $DNSNamesCheck.Value[0].Message #Checking the Output message
    # $DNSFile | Out-File -FilePath "$OutputFolderPath\$($AzVM.Name)-DNS.txt"
    if ($null -eq (-split $DNSValues)[1]) {
        $VMCheckData.Add("DNS_SERVERS_CHECK", (-split $DNSValues)[0])
    }
    else {
        $VMCheckData.Add("DNS_SERVERS_CHECK", (-split $DNSValues)[0] + "," + (-split $DNSValues)[1])
    }

    if ($AzVM.Name -match "SQL") {
        # Container Creation Check
        $AzStorageAccountkey = (Get-AzStorageAccountKey -ResourceGroupName $AzResourceGroupName -Name $AzStorageAccountName)[0].Value
        $AzStorageContext = New-AzStorageContext -StorageAccountName $AzStorageAccountName -StorageAccountKey $AzStorageAccountkey
        
        if ($AzStorageContext) {
            $AzStorageContainer = Get-AzStorageContainer -Name "backupcontainer" -Context $AzStorageContext            
            $VMCheckData.Add("STORAGE_CONTAINER_CHECK", $AzStorageContainer.Name)
        }
        else {
            $VMCheckData.Add("STORAGE_CONTAINER_CHECK", "Unavailable")
        }
    
        # Storage Account IP configuration Check
        $AzStorageAccountNetworkrule = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $AzResourceGroupName -Name $AzStorageAccountName    
        $AzStorageAccountNetworkruleCheck = $AzStorageAccountNetworkrule.IpRules.IPAddressOrRange
        if ((-split $AzStorageAccountNetworkruleCheck)[0]) {
            $VMCheckData.Add("STORAGE_ACCOUNT_NETWORK_CHECK", $AzStorageAccountNetworkruleCheck[0])
        }
        else {
            $VMCheckData.Add("STORAGE_ACCOUNT_NETWORK_CHECK", $null)
        }

        # G Drive Expansion Check 
        $DriveExpansionCheck = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $AzVM.Name -CommandId 'RunPowerShellScript' `
            -ScriptPath ".\CommonMethods\DriveExpansionCheck.ps1" -Parameter @{DriveId = "G:" } -Verbose    
        $DriveExpandedSize = $DriveExpansionCheck.Value[0].Message  #Checking the Output message
        $VMCheckData.Add("G_DRIVE_EXPANDED_SIZE", $DriveExpandedSize)

        # F Drive Expansion Check 
        $DriveExpansionCheck = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $AzVM.Name -CommandId 'RunPowerShellScript' `
            -ScriptPath ".\CommonMethods\DriveExpansionCheck.ps1" -Parameter @{DriveId = "F:" } -Verbose    
        $DriveExpandedSize = $DriveExpansionCheck.Value[0].Message  #Checking the Output message
        $VMCheckData.Add("F_DRIVE_EXPANDED_SIZE", $DriveExpandedSize)

        # D Drive Full access Check
        $DDriveFullAccessCheck = Invoke-AzVMRunCommand -ResourceGroupName $AzResourceGroupName -VMName $AzVM.Name -CommandId 'RunPowerShellScript' `
            -ScriptPath ".\CommonMethods\SQLDdriveAccessCheck.ps1" -Verbose  
        $DDriveFullAccessCheck = $DDriveFullAccessCheck.Value[0].Message  #Checking the Output message
        $VMCheckData.Add("D_DRIVE_FULL_ACCESS", $DDriveFullAccessCheck)           
    }
    elseif ($AzVM.Name -match "AGT") {
        #  Nic IP Check
        $AzVMNetworkProfile = $AzVM.NetworkProfile.NetworkInterfaces.Id.Split("/") | Select-Object -Last 1
        $AzVmNICIPConfig = Get-AzNetworkInterface -Name $AzVMNetworkProfile
        $AzVmNICIPAddress = $AzVmNICIPConfig.IpConfigurations.PrivateIpAddress

        if ($AzVmNICIPAddress) {
            $VMCheckData.Add("AGT_VM_NIC_IP_CHECK", $AzVmNICIPAddress)
        }
        else {
            $VMCheckData.Add("AGT_VM_NIC_IP_CHECK", "Unavailable")
        }
    }
    return $VMCheckData
}

# Compare the expected and actual values
Function ValidateValues() {
    $Result = @();
    FOREACH ($Item in $ExpectedValues.GetEnumerator()) {
        IF ($($Item.ExpectedValue) -ne 'NA') {
            $Obj = New-Object PSObject
            $Obj | Add-Member -Name Parameter -MemberType NoteProperty -Value $($Item.Parameter)
            $Obj | Add-Member -Name ExpectedValue -MemberType NoteProperty -Value $($Item.ExpectedValue)
            $Obj | Add-Member -Name ActualValue -MemberType NoteProperty -Value $VMCheckData.Get_Item($($Item.Parameter))
            $Obj | Add-Member -Name Result -MemberType NoteProperty -Value "$(if ($($Item.ExpectedValue) -eq $VMCheckData.Get_Item($($Item.Parameter))) { 'Pass' } else { 'Fail' })";    
            $Obj | Add-Member -Name PerformedAt -MemberType NoteProperty -Value $([System.DateTime]::UtcNow)
            $Result += $Obj            
        }
        ELSEIF ($($Item.ExpectedValue) -eq 'NA' -or $($Item.ExpectedValue) -eq '') {
            $Obj = New-Object PSObject
            $Obj | Add-Member -Name Parameter -MemberType NoteProperty -Value $($Item.Parameter)
            $Obj | Add-Member -Name ExpectedValue -MemberType NoteProperty -Value $($Item.ExpectedValue)
            $Obj | Add-Member -Name ActualValue -MemberType NoteProperty -Value $VMCheckData.Get_Item($($Item.Parameter))
            $Obj | Add-Member -Name Result -MemberType NoteProperty -Value "$(if ($($Item.ExpectedValue) -eq $VMCheckData.Get_Item($($Item.Parameter))) { '' } else { '' })";    
            $Obj | Add-Member -Name PerformedAt -MemberType NoteProperty -Value $([System.DateTime]::UtcNow)
            $Result += $Obj         
        }

    }

    IF ($Result.Result -contains 'Fail') {
        Write-Host "$($ResourceName): QC validation failed"
    }
    return $Result
}

#
# Send Email
#
Function SendEmail([string] $attachmentPath) {
    $From = ""
    $To = ""
    $Attachment = $attachmentPath
    $Subject = "$($ResourceName) : QC validation result"
    $Body = "Insert body text here"
    $SMTPServer = "smtp.live.com"
    $SMTPPort = "587"
    Send-MailMessage -From $From -to $To -Subject $Subject `
        -Body $Body -SmtpServer $SMTPServer -port $SMTPPort -UseSsl `
        -Credential (Get-Credential) -Attachments $Attachment
}

Clear-Host
# Connect-AzAccount -Subscription $SubscriptionName -TenantId 65911ec9-c247-4e7f-b3e5-239b468be687

# Connect-AzAccount -Subscription 'CSS'
$AzSubscription = Get-AzSubscription -SubscriptionName $SubscriptionName
If (-not $AzSubscription) {
    Write-Host("Unable to get the Subscription details")
    Write-Host("Please verify the input values and try to run it again.")
    Set-AzContext -Name $SubscriptionName -TenantId $AzTenantID -ErrorAction Stop | Out-Null
    Return
}

# Get a list of all files in the folder
Get-ChildItem $InputFolderPath -Filter '*.csv' -Name | ForEach-Object { 
    # Combines source folder path and file name
    $FilePath = "$($InputFolderPath)\$($_)"
    $File = Get-Item $FilePath
    $ResourceName = $File.Basename
    $OutputPath = "$($OutputFolderPath)\$($ResourceName)-$((Get-Date).ToUniversalTime().ToString(‘yyyyMMddTHHmmss’)).csv"

    # Imports CSV file
    $ExpectedValues = Import-Csv -Path $FilePath | Select-Object 'Parameter', 'ExpectedValue'

    Write-Host "$($ResourceName): Validation started!!" "`r`n"
    $VMCheckData = Get-DC-QC

    $Result = ValidateValues
    $Result | Export-Csv $OutputPath -NoTypeInformation
    if ($SendEmail) {
        SendEmail($OutputPath)
        Write-Host "Email sent for $($ResourceName)" "`r`n"
    }

    Write-Host "$($ResourceName): Validation completed!!" "`r`n"
}