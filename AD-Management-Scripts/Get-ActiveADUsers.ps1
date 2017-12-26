$CsvFile = "D:\Active_ADUsers.csv"

Import-Module ActiveDirectory
# $SearchBase = "OU=,DC=,DC="
$time = (Get-Date).AddDays(-180)
# -Searchbase $SearchBase
Get-ADUser  -Filter {LastLogonTimeStamp -gt $time} -Properties *,LastLogonTimeStamp |
Select-Object @{Label = "Display Name";Expression = {$_.DisplayName}},
@{Label = "Logon Name";Expression = {$_.sAMAccountName}},
@{Label = "City";Expression = {$_.City}},
@{Label = "Job Title";Expression = {$_.Title}},
@{Label = "Company";Expression = {$_.Company}},
#@{Label = "Descr";Expression = {$_.Description}},
@{Label = "Department";Expression = {$_.Department}},
@{Label = "Office";Expression = {$_.OfficeName}},
@{Label = "Phone";Expression = {$_.telephoneNumber}},
@{Label = "Email";Expression = {$_.Mail}},
#@{Label = "Manager";Expression = {%{(Get-AdUser $_.Manager -server $ADServer -Properties DisplayName).DisplayName}}},
@{Label = "Account Status";Expression = {if (($_.Enabled -eq 'TRUE')  ) {'Enabled'} Else {'Disabled'}}}, # the 'if statement# replaces $_.Enabled
@{Label ="LastLogon"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp).ToString('yyyy-MM-dd_hh:mm:ss')}}  | 
Export-Csv -Path $CsvFile -NoTypeInformation  -Encoding UTF8