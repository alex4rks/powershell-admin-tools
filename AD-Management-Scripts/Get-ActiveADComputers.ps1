#$LastLogonTimeMark= (get-date) - (New-TimeSpan -days 28)

Import-Module ActiveDirectory   
$DaysInactive = 90
$time = (Get-Date).Adddays(-($DaysInactive)) 
 
 # -searchbase "OU=,DC=,DC=" 
# Get all AD computers with lastLogonTimestamp less than our time 
Get-ADComputer -Filter {LastLogonTimeStamp -gt $time} -Properties LastLogonTimeStamp, operatingSystem, operatingSystemVersion | # Output hostname and lastLogonTimestamp into CSV 
	sort-object Name | # LastLogonTimeStamp
	select-object Name, operatingSystem, operatingSystemVersion | 
	export-csv D:\pc_os.csv -notypeinformation -encoding unicode -force