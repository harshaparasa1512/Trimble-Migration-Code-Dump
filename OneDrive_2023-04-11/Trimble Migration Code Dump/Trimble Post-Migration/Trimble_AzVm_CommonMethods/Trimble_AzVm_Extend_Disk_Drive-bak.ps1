$DriveIds = @()
$DriveIds = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne '' } | Select-Object Name

foreach ($DriveId in $DriveIds) {
    # Variable specifying the drive you want to extend
    $drive_letter = $DriveId.Name
    # Script to get the partition sizes and then resize the volume
    $size = (Get-PartitionSupportedSize -DriveLetter $drive_letter)
    #Resize-Partition of the OS drive
    Resize-Partition -DriveLetter $drive_letter -Size $size.SizeMax
}