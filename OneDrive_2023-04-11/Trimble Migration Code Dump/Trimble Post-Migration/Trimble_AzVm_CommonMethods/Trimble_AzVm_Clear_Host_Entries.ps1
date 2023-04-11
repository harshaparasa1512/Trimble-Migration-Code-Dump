# Start-Process -Verb RunAs

# Get the Host File Content Details
$HostFilePath = $env:windir + "\System32\drivers\etc\hosts"
$HostFilePathFolder = $env:windir + "\System32\drivers\etc"
$DesktopPathFolder = [Environment]::GetFolderPath("Desktop")
$DesktopFile = $DesktopPathFolder +"\hosts"
Remove-Item $DesktopFile -Force

Copy-Item -Path $HostFilePath -Destination $DesktopPathFolder -Force

$HostFileContent = Get-Content $DesktopFile | Where-Object{$_ -match "^#" }

# Delete and create the new host file
Remove-Item $DesktopFile -Force
New-Item $DesktopFile -Force
 
# Add the host File Content Details
Add-Content -Path $DesktopFile -Value $HostFileContent

Copy-Item -Path $DesktopFile -Destination $HostFilePathFolder -Force

Remove-Item $DesktopFile -Force