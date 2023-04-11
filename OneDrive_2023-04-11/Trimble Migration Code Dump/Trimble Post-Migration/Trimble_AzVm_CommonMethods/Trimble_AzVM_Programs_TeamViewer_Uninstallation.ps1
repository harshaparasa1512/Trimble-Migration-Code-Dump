################################ TeamViewer UNINSTALLATION ##############################

$uninstallString = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName -like "TeamViewer*" }).UninstallString

if ($uninstallString) {
    & cmd.exe /c $uninstallString /S Write-Host "TeamViewer has been uninstalled."
} 
else { 
    Write-Host "TeamViewer is not installed on this computer."
}

################################ POST-UNINSTALLATION ##############################
# [string]$installPhase = 'Post-Uninstallation'