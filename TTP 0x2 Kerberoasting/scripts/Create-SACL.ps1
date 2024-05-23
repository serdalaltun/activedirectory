function Create-SACL {

<#
.SYNOPSIS

Creates property-based SACL (System Access Control List) on objects, based on given property GUID to log Active Directory access and changes

Author: Serdal Tarkan Altun
License: MIT License
Required Dependencies: None

.DESCRIPTION

Finds requested Active Directory object with Get-ADObject cmdlet and samAccountName property and 
creates System.Security.Principal.SecurityIdentifier object with given SID value and  
ActiveDirectoryAuditRule object with given parameters (SID, Right, Flag, GUID, Inheritance) to build up SACL. 
Adds SACL into the object's SACL list and saves.

This function is useful for creating SACLs on hidden properties (e.g. serviceprincipalname) that can't be seen on the Active Directory Users and Computers (dsa.msc) or other tools.

You can find necessary GUID values by Microsoft schema documentation.
e.g. https://docs.microsoft.com/en-us/windows/win32/adschema/a-serviceprincipalname

.PARAMETER $SID

The SID (Security Identifier) of the source object of operation
Default: S-1-1-0 (Everyone)

.PARAMETER $Right

The name of the operation to be logged 
e.g. WriteProperty, ReadProperty
# https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=dotnet-plat-ext-6.0

.PARAMETER $Flag

The result of the operation to be logged
e.g. Success, Fail
Default: Success
https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.auditflags?view=net-6.0

.PARAMETER $GUID

The GUID value of the attribute 

.PARAMETER $Inheritance

The Inheritance setting of the SACL
Default: None
https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance?view=dotnet-plat-ext-6.0

.PARAMETER $DistinguishedName

The DistinguishedName of the object which SACL will be created

.EXAMPLE

Create-SACL -SID S-1-1-0 -Right ReadProperty -Flag Success -GUID bf967a68-0de6-11d0-a285-00aa003049e2 -Inheritance None -DistinguishedName "CN=Scott Barlow,CN=Users,DC=windomain,DC=local"

Creates SACL from Everyone to Scott Barlow for Successfull Read actions on UserAccountControl attribute without inheritance (Event ID 4662)
Ref: https://docs.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol

.EXAMPLE

Create-SACL -SID S-1-1-0 -Right WriteProperty -Flag Success -GUID 20119867-1d04-4ab7-9371-cfc3d5df0afd -Inheritance None -DistinguishedName "CN=Scott Barlow,CN=Users,DC=windomain,DC=local"

Create SACL from Everyone to Scott Barlow for Successfull Write actinos on ms-DS-Support-Encrypted-Type attribute without inheritance (Event ID 5136)
Ref: https://docs.microsoft.com/en-us/windows/win32/adschema/a-msds-supportedencryptiontypes

.EXAMPLE

Create-SACL -SID S-1-1-0 -Right WriteProperty -Flag Success -GUID f3a64788-5306-11d1-a9c5-0000f80367c1 -Inheritance Children -DistinguishedName "CN=Scott Barlow,CN=Users,DC=windomain,DC=local"

Create SACL from Everyone to Scott Barlow for Successfull Write actinos on servicePrincipalName attribute, inherited to descendant objects (Event ID 5136)
Ref: https://docs.microsoft.com/en-us/windows/win32/adschema/a-serviceprincipalname

#>
    [CmdletBinding()]
    Param(  
        [Parameter(Mandatory = $False)]
        [String]
        $SID = "S-1-1-0",

        [Parameter(Mandatory = $True)]
        [System.DirectoryServices.ActiveDirectoryRights]
        $Right,

        [Parameter(Mandatory = $False)]
        [System.Security.AccessControl.AuditFlags]
        $Flag = [System.Security.AccessControl.AuditFlags]::Success,

        [Parameter(Mandatory = $True)]
        [String]
        $GUID,

        [Parameter(Mandatory = $False)]
        [DirectoryServices.ActiveDirectorySecurityInheritance]
        $Inheritance = [DirectoryServices.ActiveDirectorySecurityInheritance]::None,

        [Parameter(Mandatory = $True)]
        [String]
        $DistinguishedName
    )

    # Verifying the given DistinguishedName with Get-ADObject cmdlet
    $dest_object = "AD:" + (Get-ADObject -Identity $DistinguishedName).distinguishedname;

    # Retrieving SACL's of dest_object with Audit flag
    $sacls = Get-Acl -Path $dest_object -Audit;

    # Creating SecurityIdentifier object with given SID string
    # https://docs.microsoft.com/en-us/dotnet/api/system.security.principal.securityidentifier?view=net-6.0
    $source_sid = New-Object System.Security.Principal.SecurityIdentifier($SID);

    # Creating ActiveDirectoryAuditRule object with given parameters
    # https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryauditrule?view=dotnet-plat-ext-6.0
    $sacl = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($source_sid, $Right, $Flag, $GUID, $Inheritance);

    # Adding new sacl to sacl list
    $sacls.addauditrule($sacl);

    # Update object sacls with new list
    Set-Acl -AclObject $sacls -Path $dest_object;
}
