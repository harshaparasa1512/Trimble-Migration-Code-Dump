# Get the CommVault exe File Content Details
$CVaultSetupPath = "C:\Program Files\Commvault\installer"
$CVaultFolder = "C:\Program Files\Commvault"

# Changing directory to file Path
Set-Location $CVaultSetupPath

# Get the CommVault Application details
$ComVaultApp = .\Setup.exe /uninstall /silent

Set-Location -Path "C:\Program Files\"

# Unistall the VMWare Application
$ComVaultApp

#Commvault Folder Deletion
Remove-Item $CVaultFolder -Recurse -Force