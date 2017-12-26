# Fix-AdminGroupMembership
# This script get all members of local admin group, removes disallowed users. It can create and add to admin group new admin account with password.
# "Administrator", "Administrators" is language specific strings
# Kosarev Albert, 2017

$OutputDir = "\\computer\folder"
$AdminPassword = "adminpassword"
$Computer = $env:ComputerName

# Windows Language specific name
$BuiltinAdminName = "Administrator"

# Windows Language specific name
$LocalGroupName = "Administrators"

# "Admin" - allowed non-builtin administrator
$AllowedAdmins = @("Admin", $BuiltinAdminName)

$OutputFile = Join-Path $OutputDir "AdminGroupFixing.csv"
$LogString = ""
$LogString += $Computer + ";"
$SomethingFound = $false
$Domain = ""

$ADSI = [ADSI]("WinNT://$Computer")
$group = [ADSI]"WinNT://$Computer/$LocalGroupName"
$members = @($group.Invoke("Members"))
$FoundAdmins = New-Object System.Collections.ArrayList


foreach($member in $members) 
{
               $MemberName = $member.GetType().Invokemember("Name","GetProperty",$null,$member,$null)
               $MemberType = $member.GetType().Invokemember("Class","GetProperty",$null,$member,$null)
               $MemberPath = $member.GetType().Invokemember("ADSPath","GetProperty",$null,$member,$null)

               $MemberDomain = $null
                if($MemberPath -match "^Winnt\:\/\/(?<domainName>\S+)\/(?<CompName>\S+)\/") 
                {
                    if($MemberType -eq "User") 
                    {
                        $MemberType = "LocalUser"
                    } 
                    elseif($MemberType -eq "Group")
                    {
                        Continue
                        $MemberType = "LocalGroup"
                    }
                    $MemberDomain = $matches["CompName"]
                    
                } 
                elseif ($MemberPath -match "^WinNT\:\/\/(?<domainname>\S+)/") 
                {
                     $MemberDomain = $matches["domainname"]
                    
                    if ($MemberType -eq "User") 
                    {
                        $MemberType = "DomainUser"
                        # remove every domain user from admin group
                        if (!$SomethingFound) {
                            $SomethingFound = $true
                        }

                        $group.Remove(("WinNT://$MemberDomain/$MemberName"))
                        if ($?)
                        {
                            $LogString += "Successfully removed from $($LocalGroupName) $MemberName;"
                        }
                        else 
                        { 
                           $LogString += "ERROR :: $($MemberName) was not removed from $($LocalGroupName)!;"
                        }

                    } 
                    elseif ($MemberType -eq "Group")
                    {
                        $MemberType = "DomainGroup"
                    }
                   
                 } 
                
                # add local admin users to list
                if (($MemberType -eq "LocalUser")) 
                {
                   $FoundAdmins.Add($MemberName)
                }
}
 
# not allowed users
$NotAllowedUsers = $FoundAdmins | Where {$AllowedAdmins -notcontains $_}
if ($NotAllowedUsers -ne $null)
{
    $SomethingFound = $true
    $LogString += "Found not allowed users: $($NotAllowedUsers);"
    foreach ($notAllowedUser in $NotAllowedUsers) 
    {
        # remove user from admin group
        $group.Remove(("WinNT://$Computer/$notAllowedUser"))
        if ($?)
        {
            $LogString += "Successfully removed from $($LocalGroupName) $($notallowedUser);"
        }
        else 
        { 
           $LogString += "ERROR :: $($notAllowedUser) was not removed from $($LocalGroupName)!;"
        }
    }
}

# missing users in admins group
$MissingAdmins = $AllowedAdmins | Where {$FoundAdmins -notcontains $_}
if ($MissingAdmins -ne $null) 
{
    if (!$SomethingFound) {
        $SomethingFound = $true
    }
    $LogString += "Missing admins: $($MissingAdmins);"
    # adding to admins group
    foreach ($missingAdmin in $MissingAdmins) 
    {
       if ($missingAdmin -eq $BuiltinAdminName) {
           Continue
       }

        $UserExists = $ADSI.Children | Where {($_.SchemaClassName -eq "user") -and ($_.Name -eq $missingAdmin)}
        if ($UserExists -ne $null) 
        { 
            # net localgroup $LocalGroupName $missingAdmin /add 
            $group.Add(("WinNT://$Computer/$missingAdmin"))

            if ($?) 
            {
                $LogString += "$($missingAdmin) successfully added to $($LocalGroupName);"
            } 
            else 
            { 
                $LogString +=  "ERROR: $($missingAdmin) was not added to $($LocalGroupName);"
            }
        } 
        else 
        {
            #net user $missingAdmin $AdminPassword /add
            # Create new local Admin user for script purposes
            $ADSIComputer = [ADSI]"WinNT://$Computer,Computer"
            $LocalAdmin = $ADSIComputer.Create("User", $missingAdmin)
            $LocalAdmin.SetPassword($AdminPassword)
            $LocalAdmin.SetInfo()
            $LocalAdmin.UserFlags = 65536 # ADS_UF_DONT_EXPIRE_PASSWD
            $LocalAdmin.SetInfo()
            
            #net localgroup $LocalGroupName $missingAdmin /add
            $group.Add(("WinNT://$Computer/$missingAdmin"))

            if ($?) 
            {
                $LogString += "$($missingAdmin) successfully created and added to $($LocalGroupName);"
            } 
            else 
            { 
                $LogString +=  "ERROR: $($missingAdmin) was not added to $($LocalGroupName);"
            }
        }
    }
}

# write to log file if something found
if ($SomethingFound) {
    Add-Content -Path $OutputFile -Value $LogString -Encoding UTF8
}