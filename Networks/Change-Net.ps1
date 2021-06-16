# Network Adapter Changing Script
# Kosarev Albert © 2021


#Requires -RunAsAdministrator
#Requires -Version 4.0

Function Set-IpSettings {
	[CmdletBinding()]
	param(
		$NetAdapterInterfaceIndex, 
		$IpAddress, 
		$NetmaskBits = 24, # 255.255.255.0
		$Gateway,
		$DNSServersArray,
		[switch]$DHCPEnable = $False
	)
	
	if (-Not $DHCPEnable) {
		# remove old address
		if ((Get-NetIPConfiguration -InterfaceIndex $NetAdapterInterfaceIndex).IPv4Address.IPAddress) {
			Remove-NetIPAddress -InterfaceIndex $NetAdapterInterfaceIndex -AddressFamily $global:IPType -Confirm:$false | Out-Null
		}
		if ((Get-NetIPConfiguration -InterfaceIndex $NetAdapterInterfaceIndex).Ipv4DefaultGateway) {
			Remove-NetRoute -InterfaceIndex $NetAdapterInterfaceIndex -AddressFamily $global:IPType -Confirm:$false | Out-Null
		}
		
		# set new
		New-NetIpAddress -InterfaceIndex $NetAdapterInterfaceIndex -IPAddress $IpAddress -PrefixLength $NetmaskBits -DefaultGateway $Gateway | Out-Null
		# DNS server address can be equal to gateway address
		if ($DNSServersArray.Count -gt 0) {
			Set-DnsClientServerAddress -InterfaceIndex $NetAdapterInterfaceIndex -ServerAddresses $DNSServersArray | Out-Null
		} else {
			Set-DnsClientServerAddress -InterfaceIndex $NetAdapterInterfaceIndex -ServerAddresses $Gateway | Out-Null
		}
	} else {
		$Interface = Get-NetIPInterface -InterfaceIndex $NetAdapterInterfaceIndex -AddressFamily $global:IPType
		if ($Interface.Dhcp -eq "Disabled") {
 			# Remove existing gateway
 			if ((Get-NetIPConfiguration -InterfaceIndex $NetAdapterInterfaceIndex).Ipv4DefaultGateway) {
 				Remove-NetRoute -InterfaceIndex $NetAdapterInterfaceIndex -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
			}
 			# Enable DHCP
 			Set-NetIPInterface -InterfaceIndex $NetAdapterInterfaceIndex -DHCP Enabled | Out-Null
 			# Configure the DNS Servers automatically
			Set-DnsClientServerAddress -InterfaceIndex $NetAdapterInterfaceIndex -ResetServerAddresses | Out-Null
			Start-Sleep -Milliseconds 1500
		}
	}
}

Function Set-DefaultRoutes {
	[CmdletBinding()]
	param(
		$NetAdapterInterfaceIndex
	)
	Write-Host "Set default routes on MGMT adapter`n" -ForegroundColor Gray
	New-NetRoute -DestinationPrefix "10.0.0.0/16" -InterfaceIndex $NetAdapterInterfaceIndex -NextHop 192.168.0.1 2>$null >$null
	New-NetRoute -DestinationPrefix "172.16.0.0/24" -InterfaceIndex $NetAdapterInterfaceIndex -NextHop 192.168.3.1 2>$null >$null
	New-NetRoute -DestinationPrefix "172.16.12.0/24" -InterfaceIndex $NetAdapterInterfaceIndex -NextHop 192.168.3.1 2>$null >$null
}

Function PrintIpSettings {
	[CmdletBinding()]
	param(
		$NetAdapterInterfaceIndex
	)

	$NetAdapterConfig = Get-NetIPConfiguration -InterfaceIndex $NetAdapterInterfaceIndex
	$NetAdapter = Get-NetAdapter -InterfaceIndex $NetAdapterInterfaceIndex
	# Get DHCP state
	$NetAdapterInterface = Get-NetIPInterface -InterfaceIndex $NetAdapterInterfaceIndex -AddressFamily $global:IPType
	$DNSServers = Get-DnsClientServerAddress -InterfaceIndex $NetAdapterInterfaceIndex -AddressFamily $global:IPType
	[IPAddress] $NetMask = 0
	$NetMask.Address = ([UInt32]::MaxValue) -shl (32 - $NetAdapterConfig.IPv4Address.PrefixLength) -shr (32 - $NetAdapterConfig.IPv4Address.PrefixLength)

	if ($NetAdapterInterface.Dhcp -eq "Enabled") {
		$AdapterState = "DHCP Enabled"
	}
	foreach ($NetAddressesArray in $global:NetAddressesArrays) {
		if ($NetAddressesArray[1] -eq $NetAdapterConfig.IPv4Address.IPAddress) {
			$AdapterState = $NetAddressesArray[0]
		}
		
	}
	Write-Host "Adapter `t:  " -BackgroundColor Black -ForegroundColor Green -NoNewline
	Write-Host "$($NetAdapter.Name)" -BackgroundColor Black -ForegroundColor Magenta
	Write-Host "Current State`t:  " -BackgroundColor Black -ForegroundColor Green -NoNewline
	Write-Host "$($AdapterState)" -BackgroundColor Black -ForegroundColor Yellow
	Write-Host "DHCP `t`t: "$NetAdapterInterface.Dhcp -BackgroundColor Black -ForegroundColor Green
	Write-Host "IPv4 Address `t: "$NetAdapterConfig.IPv4Address.IPAddress -BackgroundColor Black -ForegroundColor Green
	Write-Host "IPv4 Netmask `t: "$NetMask.IPAddressToString -BackgroundColor Black -ForegroundColor Green
	Write-Host "IPv4 Gateway `t: "$NetAdapterConfig.Ipv4DefaultGateway.NextHop -BackgroundColor Black -ForegroundColor Green
	Write-Host "DNSServers `t: "$DNSServers.ServerAddresses -BackgroundColor Black -ForegroundColor Green
	Write-Host ""
}

Function Remove-Gateway {
	[CmdletBinding()]
	param(
		$NetAdapterInterfaceIndex
	)
	$Interface = Get-NetIPInterface -InterfaceIndex $NetAdapterInterfaceIndex -AddressFamily $global:IPType
	if ($Interface.Dhcp -eq "Disabled") {
		# Remove existing gateway
		$InterfaceIpConfig = Get-NetIPConfiguration -InterfaceIndex $NetAdapterInterfaceIndex
		if ($InterfaceIpConfig.Ipv4DefaultGateway) {
			Remove-NetIPAddress -InterfaceIndex $NetAdapterInterfaceIndex -AddressFamily $global:IPType -Confirm:$false | Out-Null
			
			Remove-NetRoute -InterfaceIndex $NetAdapterInterfaceIndex -Confirm:$false | Out-Null
			Write-Verbose "`nGateway removed"
			
			New-NetIPAddress -InterfaceIndex $NetAdapterInterfaceIndex -AddressFamily $global:IPType -Confirm:$false `
				-IPAddress $InterfaceIpConfig.IPv4Address.IPAddress -PrefixLength $InterfaceIpConfig.IPv4Address.PrefixLength | Out-Null
			
			Start-Sleep -Milliseconds 1000
			return 0
		} else {
			Write-Verbose "`nNo Gateway. OK"
			return 0
		}
	} elseif ($Interface.Dhcp -eq "Enabled") {
		Write-Host "`nDHCP enabled; Can't remove Gateway from $($NetAdapter.Name). Change it manually" -BackgroundColor Black -ForegroundColor Red
		return 1
	}
}


#
#
$global:IPType = "IPv4"
$global:NetAddressesArrays = @(
	# change configs here
	#
	# Profile Name; 				IP Address; 		Netmask; Gateway; 			DNS (Array)
	@("prf - default",		"10.11.16.4"; 		"24"; 	"10.11.16.1"; 		@("10.11.16.1")),
	@("prf NAT2", 	"10.11.17.4", 		"24", 	"10.11.17.1";		@("10.11.17.1")),		
	@("prf NAT3", 	"10.11.21.4", 		"24", 	"10.11.21.1";		@("10.11.10.1")),		
	@("prf NAT2", 	"10.11.11.4", 		"24", 	"10.11.11.1";		@("10.11.11.1")),		
	@("LAN (via Mgmt Eth)", 	"192.168.10.171", 	"16", 	"192.168.0.1",	@("10.0.0.1","10.0.0.2"))
)

Write-Host "`n-------------------------------------------------"
Write-Host "  Welcome to the Network Adapter Changing Script!"

$AdapterName = "Ethernet2-NAT"
$AdapterNameMgmt = "Ethernet-MGMT-DONT_TOUCH" # second management adapter

$NatAdapter = Get-NetAdapter -Name $AdapterName | Where-Object {$_.Status -eq "up"}
$MgmtAdapter = Get-NetAdapter -Name $AdapterNameMgmt | Where-Object {$_.Status -eq "up"}
foreach ($Adapter in ($NatAdapter, $MgmtAdapter)) {
	if (-Not $Adapter) {
		Write-Warning "Network adapter $($Adapter.Name) is not running`nExiting..."
		Write-host "Press any key to continue..."
		[console]::ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		Exit 1
	}
	# Write-Host "Current available Adapter: "$Adapter.Name"`n" -NoNewline
	PrintIpSettings -NetAdapter $Adapter.InterfaceIndex
}

do {
	Write-Host "Choose adapter state: " -BackgroundColor Black -ForegroundColor Yellow
	$i = 0
	foreach ($NetAddressesArray in $global:NetAddressesArrays) {
		$i++
		Write-Host "  $($i). $($NetAddressesArray[0])" -BackgroundColor Black -ForegroundColor Yellow -NoNewline
		Write-Host "`t   (IP: $($NetAddressesArray[1]); M: $($NetAddressesArray[2]); GW: $($NetAddressesArray[3]); DNS: $($NetAddressesArray[4]))" `
			-BackgroundColor Black -ForegroundColor Cyan
	}
	# uncomment if needed
	# Write-Host "  10. DHCP Enabled" -BackgroundColor Black -ForegroundColor Yellow
	Write-Host "  P. Print Configs & Routes" -BackgroundColor Black -ForegroundColor Yellow
	Write-Host "Enter the option number (q - quit): " -BackgroundColor Black -ForegroundColor Yellow -NoNewLine 
	
	$Option = Read-Host
	switch ($Option) {
		"q" { 
			Write-Host "Exiting..."
			Break #Exit 0
		}
		# number of options 
		# {"1", "2", "3", "4" -contains $_} {
		{"2", "3", "4" -contains $_} {
			$OptionIndex = $Option.ToInt32($Null) - 1
			$GatewayState = Remove-Gateway -NetAdapterInterfaceIndex $MgmtAdapter.InterfaceIndex
			if ($GatewayState -ne 0) {
				Write-Host "Can't enable $($_) profile due to $($MgmtAdapter.Name) problem config" -BackgroundColor Black -ForegroundColor Red
				break
			}
			Write-Host "`nSetting $($global:NetAddressesArrays[$OptionIndex][0]) on $($AdapterName)...`n"
			Set-IpSettings -NetAdapterInterfaceIndex $NatAdapter.InterfaceIndex -IpAddress $global:NetAddressesArrays[$OptionIndex][1] `
				-NetmaskBits $global:NetAddressesArrays[$OptionIndex][2].ToInt32($Null) `
				-Gateway $global:NetAddressesArrays[$OptionIndex][3]
				# -DNSServersArray 
			Set-DefaultRoutes -NetAdapterInterfaceIndex $MgmtAdapter.InterfaceIndex
			PrintIpSettings -NetAdapterInterfaceIndex $NatAdapter.InterfaceIndex			
		}
		# only for mgmt adapter
		"5" {
			$OptionIndex = $Option.ToInt32($Null) - 1
			$GatewayState = Remove-Gateway -NetAdapterInterfaceIndex $NatAdapter.InterfaceIndex
			if ($GatewayState -ne 0) {
				Write-Host "Can't  enable $($_) profile due to $($NatAdapter.Name) problem config" -BackgroundColor Black -ForegroundColor Red
				break
			}
			Write-Host "`nSetting $($global:NetAddressesArrays[$OptionIndex][0]) on $($AdapterNameMgmt)...`nLM Connection can reset`n"
			Set-IpSettings -NetAdapterInterfaceIndex $MgmtAdapter.InterfaceIndex -IpAddress $global:NetAddressesArrays[$OptionIndex][1] `
				-NetmaskBits $global:NetAddressesArrays[$OptionIndex][2].ToInt32($Null) `
				-Gateway $global:NetAddressesArrays[$OptionIndex][3] `
				-DNSServersArray $global:NetAddressesArrays[$OptionIndex][4]
			Set-DefaultRoutes -NetAdapterInterfaceIndex $MgmtAdapter.InterfaceIndex
			PrintIpSettings -NetAdapterInterfaceIndex $MgmtAdapter.InterfaceIndex	
			PrintIpSettings -NetAdapterInterfaceIndex $NatAdapter.InterfaceIndex	
		}
		# optional DHCP feature
		"10" { 
			$GatewayState = Remove-Gateway -NetAdapterInterfaceIndex $MgmtAdapter.InterfaceIndex
			if ($GatewayState -ne 0) {
				Write-Host "Can't  enable DHCP due to $($MgmtAdapter.Name) problem config" -BackgroundColor Black -ForegroundColor Red
				break
			}
			Write-Host "`nEnabling DHCP  on $($AdapterName)...`n"
			Set-IpSettings -NetAdapterInterfaceIndex $NatAdapter.InterfaceIndex -DHCPEnable
			PrintIpSettings -NetAdapterInterfaceIndex $NatAdapter.InterfaceIndex	
			PrintIpSettings -NetAdapterInterfaceIndex $MgmtAdapter.InterfaceIndex			
		}
		{$_ -in 'p','P'} {
			Write-Host ""
			PrintIpSettings -NetAdapterInterfaceIndex $NatAdapter.InterfaceIndex
			PrintIpSettings -NetAdapterInterfaceIndex $MgmtAdapter.InterfaceIndex
			Write-Host "Routing Table: " -NoNewline
			Get-NetRoute -AddressFamily $global:IPType | `
				Where-Object {$_.InterfaceIndex -in ($NatAdapter.InterfaceIndex, $MgmtAdapter.InterfaceIndex)} | `
				Sort-Object -Property DestinationPrefix | `
				Select-Object -Property ifIndex, InterfaceAlias, DestinationPrefix, NextHop, RouteMetric | `
				Format-Table
		}
		default {
			Write-Warning "`nNon valid input"
		}
	}
} while ($Option.ToLower() -ne "q")

