$DNSValue= ""
$DNSValue = Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceAlias Ethernet 
$DNSValues = $DNSValue.ServerAddresses
$DNSValues