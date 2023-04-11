$AzVmSQLDDrive = "D:\"
$acl = Get-Acl "$AzVmSQLDDrive"
$user = "NT Service\MSSQLSERVER"
$Permission = "FullControl"
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($user, $Permission, `
        "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($AccessRule)
$acl | Set-Acl $AzVmSQLDDrive

$SQLService = "SQL Server (MSSQLSERVER)"
$SQLAgentService = "SQL Server Agent (MSSQLSERVER)"
Start-Service $SQLService
Start-Service $SQLAgentService