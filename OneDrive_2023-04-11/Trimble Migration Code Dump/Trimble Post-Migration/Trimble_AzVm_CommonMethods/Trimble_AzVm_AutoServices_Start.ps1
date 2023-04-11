$ComputerName = (Get-Item env:\Computername).Value

# #Start all non-running Auto services
# Get-WmiObject win32_service -ComputerName $computer -Filter "startmode = 'auto' AND state != 'running'" | Invoke-WmiMethod -Name StartService

# #Output any services still not running
# $stoppedServices = Get-WmiObject win32_service -ComputerName $computer -Filter "startmode = 'auto' AND state != 'running'" | Select-Object -expand Name

# Write-Host "$env:ComputerName : Stopped Services: $stoppedServices"

$Services = Get-Service

#get status of Auto services which are not running
$stoppedServices = $Services | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" } | Select-Object -expand DisplayName

Write-Host "$ComputerName : Stopped Services: $stoppedServices"

# $stoppedServicesCount = ($Services | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" } | Measure-Object).Count

$ServiceNames = @()
$ServiceNames = $stoppedServices
foreach ($ServiceId in $ServiceNames) {
    Start-Service -Name $ServiceId
}

$stoppedServices