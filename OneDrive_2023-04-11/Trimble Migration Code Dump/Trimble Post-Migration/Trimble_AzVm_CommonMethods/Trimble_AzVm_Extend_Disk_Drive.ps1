Param(
    [parameter(Mandatory = $true)]$DriveId
)

# Variable specifying the drive you want to extend
$drive_letter = $DriveId
    
# Script to get the partition sizes and then resize the volume
$size = (Get-PartitionSupportedSize -DriveLetter $drive_letter)

#Resize-Partition of the OS drive
Resize-Partition -DriveLetter $drive_letter -Size $size.SizeMax