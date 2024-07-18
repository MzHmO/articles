# Powerview v2
	Get-ObjectACL -Samaccountname Guest -ResolveGUIDs
	Get-ObjectACL -ADSprefix 'CN=Administrator,CN=Users' -Verbose
	
	# Получить ACL, связанные с определённым объектом, указываемым в LDAP формате
		Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose
	
	# На группу users
		Get-ObjectAcl -SamAccountName "users" -ResolveGUIDs -Verbose

# Powerview v3
	Get-DomainObjectACL -Identity student1 -ResolveGUIDs
	Get-DomainObjectACL -Identity "Domain Admins" -ResolveGUIDs -Verbose
	Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}
	
	# Получить ACL, связанные с указанным путём
		Get-PathAcl -Path "\\us-dc\sysvol"
	
	# Получить ACL, связанные с определённым объектом, указываемым в LDAP формате
		Get-DomainObjectAcl -Searchbase "LDAP://CN=DomainAdmins,CN=Users,DC=us,DC=techcorp,DC=local" -ResolveGUIDs -Verbose
	
#Using AD Module: (не будет резолвить GUIDs)
	(Get-Acl -Path 'AD:\CN=Administrator,CN=Users,DC=sec,DC=corp,DC=local').Access
	(Get-ACL -Path "AD:$((Get-ADUser j.doe).distinguishedName)").access
	# Обнаружить, кто имеет права GenericAll/AllExtendedRights на пользователя j.doe
		(Get-ACL -Path "AD:$((Get-ADUser j.doe).distinguishedName)").access | ? {$_.ActiveDirectoryRights -match "GenericAll|AllExtendedRights"} | select IdentityReference,ActiveDirectoryRights -Unique | ft -W