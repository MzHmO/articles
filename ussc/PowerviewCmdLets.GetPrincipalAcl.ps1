# Powerview v2
	Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "домен\юзер"}
	#Пример
	Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"} | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_}

# Powerview v3
	Get-DomainObjectAcl -ResolveGUIDs | ? {_.SecurityIdentifier -eq "SID объекта"}
	# Пример
	Get-DomainObjectAcl -ResolveGUIDs | ? {_.SecurityIdentifier -eq "S-1-5-21-3167813660-1240564177-918740779-3102"}
	# Поиск объектов, на которые группа managers имеет права
	Get-DomainObjectAcl -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match 'managers'}
	
	# Найти пользователей домена, на которых у текущей учетки есть права GenericAll
	Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | % {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | % {if ($_.Identity -eq $("$env:UserDomain\$env:UserName")) {$_}} ? {$_.ActiveDirectoryRights -like "*GenericAll*"}
	# Найти группы, на которые у текущего пользователя есть права GenericAll
	Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | % {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | % {if ($_.Identity -eq $("$env:UserDomain\$env:UserName")) {$_}} ? {$_.ActiveDirectoryRights -like "*GenericAll*"}
	# Найти объекты, на которое у данной учетки есть права GenericAll
	Get-DomainObjectAcl -ResolveGUIDs | % {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | % {if ($_.Identity -eq $("$env:UserDomain\$env:UserName")) {$_}} ? {$_.ActiveDirectoryRights -like "*GenericAll*"}
