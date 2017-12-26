function Get-AdminGroupMembers {
param(
    [string]$Computer = $env:ComputerName
)
# admins group
$LocalGroupName  = Invoke-Command -ComputerName $Computer -ScriptBlock { $Auth = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544") ; ($Auth.Translate([System.Security.Principal.NTAccount])).Value.Split("\")[1] }
$LocalGroupName

$OutputDir = "D:\temp-rw"

$OutputFile = Join-Path $OutputDir "LocalGroupMembers.csv"

$group = [ADSI]"WinNT://$Computer/$LocalGroupName,group"
$members = $group.psbase.Invoke("Members")
foreach($member in $members) {
              
                $MemberName = $member.GetType().Invokemember("Name","GetProperty",$null,$member,$null)
                $MemberType = $member.GetType().Invokemember("Class","GetProperty",$null,$member,$null)
                $MemberPath = $member.GetType().Invokemember("ADSPath","GetProperty",$null,$member,$null)
                
                $MemberDomain = $null
                if($MemberPath -match "^Winnt\:\/\/(?<domainName>\S+)\/(?<CompName>\S+)\/") {
                    if($MemberType -eq "User") {
                        $MemberType = "LocalUser"
                    } elseif($MemberType -eq "Group"){
                        Continue
                        $MemberType = "LocalGroup"
                    }
                    $MemberDomain = $matches["CompName"]
 
                } elseif($MemberPath -match "^WinNT\:\/\/(?<domainname>\S+)/") {
                    if($MemberType -eq "User") {
                        $MemberType = "DomainUser"
                    } elseif($MemberType -eq "Group"){
                        $MemberType = "DomainGroup"
                    }
                    $MemberDomain = $matches["domainname"]
 
                } 
                
                if ($MemberType -eq "DomainUser") {
                    $MemberName
                }
} 

}