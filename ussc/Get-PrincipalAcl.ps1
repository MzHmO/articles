param(
    [String]$group,
    [String]$file
)

if (-not $group) {
    throw "Аргумент -group не был указан. Укажите имя группы для продолжения."
}

$results = Get-ADObject -Filter * -Properties * | ForEach-Object {
    $currentObject = $_
    $acl = Get-Acl -Path ("AD:\$($_.DistinguishedName)")

    foreach ($access in $acl.Access) {
        if ($access.IdentityReference -like "*$group*") {
            [PSCustomObject]@{
                Object = $currentObject.Name
                Path = $currentObject.DistinguishedName
                AccessType = $access.AccessControlType
                Rights = $access.ActiveDirectoryRights
                Identity = $access.IdentityReference
            }
        }
    }
}

if ($file) {
    $results | Format-Table -AutoSize -Wrap  | Out-File -FilePath $file -Width 512 -Encoding UTF8
    Write-Host "Результаты записаны в файл: $file"
} else {
    $results | Format-Table -AutoSize -Wrap | Out-Default
}