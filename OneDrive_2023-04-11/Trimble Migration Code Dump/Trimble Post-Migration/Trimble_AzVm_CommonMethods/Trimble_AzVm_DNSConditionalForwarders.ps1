$AzVnetDnsServersVal = $AzVnetDnsServers
# $AzVnetDnsServers = @()
$AzVnetDnsValues = $AzVnetDnsServers.Count
$CompName = $env:COMPUTERNAME 
$i = 0

foreach ($AzVnetDnsIPAddr in $($AzVnetDnsServersVal.Values)[$AzVnetDnsValues-$i]) {
    $i += 1
    $AzVnetDnsIPAddr.Trim()
    Add-DnsServerConditionalForwarderZone -MasterServers $AzVnetDnsIPAddr
    Set-DnsServerForwarder -IPAddress $AzVnetDnsIPAddr -EnableReordering $true -PassThru
}

Clear-DnsServerCache -ComputerName $CompName -Force