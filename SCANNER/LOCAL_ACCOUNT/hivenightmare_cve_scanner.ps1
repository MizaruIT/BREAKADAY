Write-Host -ForegroundColor Green "==== HiveNightmare Checker and Workaround ===="

# Checking current hive files access rights
# inspiration for method of checking from https://github.com/pyonghe/HiveNightmareChecker/blob/main/hnmchecker.ps1
$samAccess = @((Get-Item -LiteralPath C:\Windows\System32\config\SAM).GetAccessControl().AccessToString)
$systemAccess = @((Get-Item -LiteralPath C:\Windows\System32\config\SYSTEM).GetAccessControl().AccessToString)
$securityAccess = @((Get-Item -LiteralPath C:\Windows\System32\config\SECURITY).GetAccessControl().AccessToString)

# ACL to look for that is dangerous
$userACL = "*BUILTIN\Users Allow*"

# if any of the hive files match the dangerous ACL alert the user
If ($samAccess -like $userACL -And $systemAccess -like $userACL -And $securityAccess -like $userACL) {
    Write-Host -ForegroundColor red "[!] " -NoNewline ; Write-Host "Vulnerable ACL rights on hive files"
    # Ask if they would like to reset the file
    $confirmACL = Read-Host -Prompt "Do you want to change the permissions? [y] [n]"
    if ($confirmACL -eq 'y') {
        # Set permissions according to Microsoft (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934)
        icacls C:\Windows\system32\config\*.* /inheritance:e
        Write-Host -ForegroundColor Green "[*] " -NoNewline; Write-Host "ACLs have been updated"
    }
} else {
    Write-Host -ForegroundColor Green "[*] " -NoNewline ; Write-Host "No vulnerable hive files found."
}


# Checking shadows to see if vulnerable copies are present
$shadowBase = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy"
$shadowIDs = @()

foreach ($i in 1..100) {
    $samPath = $shadowBase + $i + "\Windows\System32\config\SAM"
    $sam = Get-Item -LiteralPath $samPath
    If ($sam.Exists) {
        $samACLs = @($sam.GetAccessControl().AccessToString)
        if ($samACLs -like $userACL) {
            Write-Host -ForegroundColor red "[!] " -NoNewline ; Write-Host "Vulnerable ACL rights Found in Shadow copy: " $shadowBase$i
            # Query for shadow IDs and add to list
            $shadowIDs += @((Get-WmiObject Win32_ShadowCopy |Where-Object {$_.deviceobject -eq $shadowBase+$i}).id)
        } else {
            Write-Host -ForegroundColor Green "[*] " -NoNewline ; Write-Host "No vulnerable shadow files found."
        }
    }
}