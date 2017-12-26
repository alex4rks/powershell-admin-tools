Import-Module ActiveDirectory

$CsvFile = "D:\pclist.csv"
# CSV file should contain 2 columns:
# UserName, ComputerName

$ComputerList = Import-Csv -Path $CsvFile -Delimiter ','

foreach ($Computer in $ComputerList) 
{
    $ADUser =  Get-ADUser $Computer.UserName
    if ($ADUser -ne $null) 
    {
        $ADComputer = Get-ADComputer -Identity $Computer.ComputerName
        if ($ADComputer -ne $null) 
        {
            Set-ADComputer -Identity $Computer.ComputerName -ManagedBy $ADUser.SamAccountName -Description $ADUser.Name
            Write-Output "$($Computer.ComputerName) ManagedBy :: $($ADUser.SamAccountName)"
        }
    }
}