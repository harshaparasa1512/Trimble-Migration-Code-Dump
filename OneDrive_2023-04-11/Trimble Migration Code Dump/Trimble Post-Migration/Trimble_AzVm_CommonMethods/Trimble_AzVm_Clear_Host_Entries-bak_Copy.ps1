# Get the Host File Content Details
$hostFilePath = "c:\windows\System32\drivers\etc\hosts"
Get-Content $hostFilePath | Where-Object{$_ -notmatch "^#" }

$hostfile = Get-Content $hostFilePath | Where-Object {$_ -notmatch "^#" }

# Clear the Host File Content Details
Get-Content $hostFilePath | Where-Object {$_ -notmatch "^#" }`
| Set-Content $hostFilePath -Force -ErrorAction Stop
 
# Add the host File Content Details
Add-Content $hostFilePath $hostfile -Force -ErrorAction Stop