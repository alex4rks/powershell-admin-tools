Set-ExecutionPolicy Bypass -Force
Enable-PSRemoting -Force
# Enable-PSRemoting -Force -SkipNetworkProfileCheck
# Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -RemoteAddress Any

# netsh advfirewall firewall add rule name="Open Port 5985 winrm" dir=in action=allow protocol=TCP localport=5985
Set-Item WSMan:localhost\client\trustedhosts -value * -Force
