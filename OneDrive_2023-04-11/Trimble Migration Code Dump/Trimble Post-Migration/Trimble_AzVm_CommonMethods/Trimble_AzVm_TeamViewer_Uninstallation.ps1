############################## PRE-UNINSTALLATION ######################################
[string]$installTitle = 'TeamViewer'

## Show Welcome Message, Close TeamViewer With a 60 Second Countdown Before Automatically Closing
Show-InstallationWelcome -CloseApps 'TeamViewer' -CloseAppsCountdown 60

## Show Progress Message (With a Message to Indicate the Application is Being Uninstalled)
Show-InstallationProgress -StatusMessage "Uninstalling Application $installTitle. Please Wait..."

################################ UNINSTALLATION ##############################

## Remove Any Existing Versions of TeamViewer (MSI)
Remove-MSIApplications "TeamViewer"

## Remove Any Existing Versions of TeamViewer (EXE)
$AppList = Get-InstalledApplication -Name 'TeamViewer'
        
ForEach ($App in $AppList) {
    If ($App.UninstallString) {
        $UninstPath = $App.UninstallString -replace '"', ''
        
        If (Test-Path -Path $UninstPath) {
            Write-log -Message "Found $($App.DisplayName) ($($App.DisplayVersion)) and a valid uninstall string, now attempting to uninstall."

            Execute-Process -Path $UninstPath -Parameters '/S'
            Start-Sleep -Seconds 5
        }
    }
}

################################ POST-UNINSTALLATION ##############################
# [string]$installPhase = 'Post-Uninstallation'