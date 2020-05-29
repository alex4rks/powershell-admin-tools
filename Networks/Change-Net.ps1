# Network Adapter Changing Script
# Kosarev Albert © 2020


#Requires -RunAsAdministrator
#Requires -Version 4.0
# Check for admin rights and start powershell as admin
<# If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {   
	$arguments = "& '" + $myinvocation.mycommand.definition + "'"
	Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments
	Break
}
#>
Function Set-IpSettings {
	[CmdletBinding()]
	param(
		$NetAdapter, 
		$IpAddress, 
		$NetmaskBits = 24, # 255.255.255.0
		$Gateway,
		[switch]$DHCPEnable = $False
	)
	
	if (-Not $DHCPEnable) {
		# remove old address
		if (($NetAdapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
			$NetAdapter | Remove-NetIPAddress -AddressFamily $global:IPType -Confirm:$false -ErrorAction SilentlyContinue
		}
		if (($NetAdapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
			$NetAdapter | Remove-NetRoute -AddressFamily $global:IPType -Confirm:$false -ErrorAction SilentlyContinue
		}

		# set new
		New-NetIpAddress -InterfaceIndex $NetAdapter.InterfaceIndex -IPAddress $IpAddress -PrefixLength $NetmaskBits -DefaultGateway $Gateway | Out-Null
		# DNS server address equal to gateway address
		Set-DnsClientServerAddress -InterfaceIndex $NetAdapter.InterfaceIndex -ServerAddresses $Gateway | Out-Null
	}
	else {
		$Interface = $NetAdapter | Get-NetIPInterface -AddressFamily $global:IPType
		if ($Interface.Dhcp -eq "Disabled") {
 			# Remove existing gateway
 			if (($Interface | Get-NetIPConfiguration).Ipv4DefaultGateway) {
 				$Interface | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
			}
 			# Enable DHCP
 			$Interface | Set-NetIPInterface -DHCP Enabled
 			# Configure the DNS Servers automatically
			$Interface | Set-DnsClientServerAddress -ResetServerAddresses
		}
	}
}

Function PrintIpSettings ($NetAdapterIndex) {
	$NetAdapterConfig = Get-NetIPConfiguration -InterfaceIndex $NetAdapterIndex
	# Get DHCP state
	$NetAdapterInterface = Get-NetIPInterface -InterfaceIndex $NetAdapterIndex -AddressFamily $global:IPType
	$DNSServers = Get-DnsClientServerAddress -InterfaceIndex $NetAdapterIndex -AddressFamily $global:IPType
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
	Write-Host "Current network settings:  " -BackgroundColor Black -ForegroundColor Green -NoNewline
	Write-Host "$($AdapterState)" -BackgroundColor Black -ForegroundColor Yellow
	Write-Host "DHCP `t`t: "$NetAdapterInterface.Dhcp -BackgroundColor Black -ForegroundColor Green
	Write-Host "IPv4 Address `t: "$NetAdapterConfig.IPv4Address.IPAddress -BackgroundColor Black -ForegroundColor Green
	Write-Host "IPv4 Netmask `t: "$NetMask.IPAddressToString -BackgroundColor Black -ForegroundColor Green
	Write-Host "IPv4 Gateway `t: "$NetAdapterConfig.Ipv4DefaultGateway.NextHop -BackgroundColor Black -ForegroundColor Green
	Write-Host "DNSServers `t: "$DNSServers.ServerAddresses -BackgroundColor Black -ForegroundColor Green
	Write-Host ""
}

#
#
$global:IPType = "IPv4"
$global:NetAddressesArrays = @(
	# Profile Name; IP Address; Netmask Bits; Gateway (= DNS)
	@("NAT2 one to many Comfortel", "10.11.116.3"; "24"; "10.11.116.1"),
	@("NAT2 one to many Impulse", "10.11.117.3", "24", "10.11.117.1"),
	@("NAT3 symmetric (pfSense)", "10.11.210.3", "24", "10.11.210.1"),
	@("NAT2 one to one Comfortel", "10.11.100.3", "24", "10.11.100.1")
)


Write-Host "`n-------------------------------------------------"
Write-Host "  Welcome to the Network Adapter Changing Script!"
Write-Host "-------------------------------------------------"
Write-Host "     Part of the Greatest Saber Network Lab        "
Write-Host "-------------------------------------------------`n"

# $AdapterName = "Ethernet2-NAT"
$AdapterName = "VMware Network Adapter VMnet8" # for tests
$NatAdapter = Get-NetAdapter -Name $AdapterName | Where-Object {$_.Status -eq "up"}
if (-Not $NatAdapter) {
	Write-Warning "Network adapter $($AdapterName) is not running`nExiting..."
	Write-host "Press any key to continue..."
	[console]::ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Exit 1
}
Write-Host "Current available Adapter: "$NatAdapter.Name"`n"
PrintIpSettings -NetAdapter $NatAdapter.InterfaceIndex


do {
	Write-Host "Choose adapter state: " -BackgroundColor Black -ForegroundColor Yellow
	$i = 0
	foreach ($NetAddressesArray in $global:NetAddressesArrays) {
		$i++
		Write-Host "  $($i). $($NetAddressesArray[0])" -BackgroundColor Black -ForegroundColor Yellow -NoNewline
		Write-Host "`t   (IP: $($NetAddressesArray[1]); Netmask: $($NetAddressesArray[2]); GW: $($NetAddressesArray[3]))" -BackgroundColor Black -ForegroundColor Cyan
	}
	Write-Host "  10. DHCP Enable (Optional)" -BackgroundColor Black -ForegroundColor Yellow
	Write-Host "Enter the option number (q - quit): " -BackgroundColor Black -ForegroundColor Yellow -NoNewLine 
	
	$Option = Read-Host
	switch ($Option) {
		"q" { 
			Write-Host "Exiting..."
			Break #Exit 0
		}
		{"1", "2", "3", "4" -contains $_} {
			$OptionIndex = $Option.ToInt32($Null) - 1
			Write-Host "`nSetting $($global:NetAddressesArrays[$OptionIndex][0])...`n"
			Set-IpSettings -NetAdapter $NatAdapter -IpAddress $global:NetAddressesArrays[$OptionIndex][1] `
				-NetmaskBits $global:NetAddressesArrays[$OptionIndex][2].ToInt32($Null) -Gateway $global:NetAddressesArrays[$OptionIndex][3]
			PrintIpSettings -NetAdapter $NatAdapter.InterfaceIndex
		}
		"10" { 
			Write-Host "`nEnabling DHCP...`n"
			Set-IpSettings -NetAdapter $NatAdapter -DHCPEnable
			PrintIpSettings -NetAdapter $NatAdapter.InterfaceIndex
		}
		default {
			Write-Warning "Non valid input"
		}
	}
} while ($Option -ne "q")


# Write-host "Press any key to continue..."
# [console]::ReadKey("NoEcho,IncludeKeyDown") | Out-Null
