#
# Kosarev Albert, 2017
#
# Sources:
# https://github.com/Disassembler0/Win10-Initial-Setup-Script/blob/master/Win10.ps1

# https://github.com/aikoncwd/win10script/blob/master/dependencias/telemetryOFF.bat
# https://gist.github.com/alirobe/7f3b34ad89a159e6daa1 
# https://github.com/W4RH4WK/Debloat-Windows-10/blob/master/scripts/
# https://github.com/hahndorf/Set-Privacy/blob/master/Set-Privacy.ps1
#
if ($PSVersionTable.BuildVersion.Major -lt 10)
{
    Write-Host This OS is not supported -ForegroundColor Red
    exit
}
$ErrorActionPreference = "SilentlyContinue"

####################################
#
# 1. Applying HKCU Settings to Registry
#
Write-Host "1. Applying HKCU Settings to Registry"
# Load default user registry
reg load "hklm\temp" "C:\Users\Default\NTUSER.DAT"
if ($?)
{
	Write-Host "SUCCESS: The default hive is now loaded"
} 
else 
{
	SchTasks.exe /Create /TN "DefaultUserRegLoad" /SC ONSTART /TR "reg.exe load hklm\temp C:\users\default\NTUSER.DAT" /RU "System" /RL HIGHEST >$null
	SchTasks.exe /Run /TN "DefaultUserRegLoad" >$null
	SchTasks.exe /delete /tn "DefaultUserRegLoad" /F >$null
	Start-Sleep 1
	reg query hklm\temp > $null
	if ($?)
	{
		Write-Host "SUCCESS: The default hive is now loaded"
	}
}


# Change Explorer View to This PC
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f >$null

# OneDrive (see #6)
reg delete "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f >$null 2>$null
reg delete "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>$null

# Disable autoplay for all media and devices & Disable Autorun
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "1" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f >$null

# Disable Feedback
reg add "hklm\temp\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f >$null

# Disable show most used apps at start menu
# reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >$null

# Disable show recent items at start menu
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f >$null

# Show recently used files & folders in Quick Access
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f >$null

# RSS Feeds - Disable
reg add "hklm\temp\Software\Microsoft\Feeds" /v "SyncStatus" /t REG_DWORD /d "0" /f >$null

# Disable Bing Search
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >$null

# Advertising Info disable
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >$null

# Disable Cortana
reg add "hklm\temp\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >$null
reg add "hklm\temp\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >$null
reg add "hklm\temp\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f >$null
# Cortana history disable
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d "0" /f >$null

# Turn On Quiet Hours Action Center
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_TOASTS_ENABLED" /t REG_DWORD /d "0" /f >$null

# Disable Startup Run
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "OneDrive"  /t REG_BINARY /d "0300000064A102EF4C3ED101" /f >$null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "OneDrive"  /t REG_BINARY /d "0300000064A102EF4C3ED101" /f >$null

# Disable Access to Devices to Modern Apps
# location sensor:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Camera:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Mic:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Calendar: 
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# SMS, MMS:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Wireless interfaces:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Account info:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Diagnostics:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Call History:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Email:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Tasks:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# App notifications:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Disable apps share and sync non-explicitly paired wireless devices over uPnP
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f >$null
# ..Settings
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f >$null
# reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync" "BackupPolicy" /t REG_DWORD /d "60" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f >$null
# ..Location
reg add "hklm\temp\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f >$null

# Disabling typing info
reg add "hklm\temp\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f >$null 

# Disable access to language list
reg add "hklm\temp\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "0" /f >$null

# Smart Screen disable
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >$null 

# Push notification disable
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f >$null 

# Show known file extensions
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f >$null

# Show hidden files
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f >$null

# Hide sync provider notifications 
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f >$null

# Disable simple sharing wizard
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SharingWizardOn" /t REG_DWORD /d "0" /f >$null

# Show System Protected files
# reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SuperHidden" /t REG_DWORD /d "1" /f >$null

# Disable Network Thumbs
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnailsOnNetworkFolders" /t REG_DWORD /d "1" /f >$null

# Disable Let apps run in the background, since Creators Update
# reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >$null
Get-ChildItem "hklm:\temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
		Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
		Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
	}

# Disable downloaded files from being blocked
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f >$null

# Disable ADS
# https://winaero.com/blog/disable-ads-windows-10/
# Stop installing unwanted apps
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >$null
# Start menu suggestions
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f >$null
# Ads in explorer
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f >$null
# Tips about Windows
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f >$null
# Locksreen images & tips
# reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f >$null        # problems on logon
# reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f >$null # problems on logon
# 
# Various Ads disable
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f >$null
reg delete "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f >$null 2>$null
# Welcome page
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f >$null
# Settings ads
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f >$null

# 1. Disable 3rd party ads for Enterprise
reg add "hklm\temp\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f >$null
# 2. Disable Windows Spotlight notifications in Action Center
reg add "hklm\temp\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnActionCenter" /t REG_DWORD /d "1" /f >$null

# Disable Storage Sense
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d "1" /f >$null

# Disable Shared Experiences
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\CDP" /v "RomeSdkChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f >$null


### UI Settings
# Menu Show Delay Reduce
reg add "hklm\temp\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "200" /f >$null
# Hide Taskbar People icon
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d "0" /f >$null
# Show all tray icons
# reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f >$null 2>$null


# Unload Default User Registry
[gc]::Collect()
reg unload "hklm\temp" # >$null
if ($?)
{
	Write-Host "SUCCESS: The default hive is now unloaded"
}
else
{
	SchTasks.exe /Create /TN "DefaultUserRegUnload" /SC ONSTART /TR "reg.exe unload hklm\temp" /RU "System" /RL HIGHEST >$null
	SchTasks.exe /Run /TN "DefaultUserRegUnload" # >$null
	SchTasks.exe /delete /tn "DefaultUserRegUnload" /F >$null
	Start-Sleep 2
	reg query hklm\temp >$null
	if (!$?)
	{
		Write-Host "SUCCESS: The default hive is now unloaded"
		# icacls C:\Users\Default\NTUSER.DAT  /grant Everyone:RX
	}
	else 
	{
		Write-Host "ERROR: Default hive is not unloaded"
	}
}



########################
#
# 2. Applying HKLM Settings
#
Write-Host "2. Applying HKLM Settings"

# Customer experience improvement program - Disable
reg add "HKLM\Software\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >$null

# Disable install 3rd party apps (not for Home/Pro) issues with updates
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f >$null
# Disable tips (not for Home/Pro)
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f >$null

# Disable first logon animations
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d "0" /f >$null

# Disable automatic maintenance
# reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >$null

# Disable Cortana
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >$null

# IE
# IE - Disable first run
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "1" /f >$null
# IE - Addon dialog disable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" /v "IgnoreFrameApprovalCheck" /t REG_DWORD /d "1" /f >$null
# IE - Hide Edge Button
reg add "HKLM\Software\Microsoft\Internet Explorer\Main" /v "HideNewEdgeButton" /t REG_DWORD /d "1" /f >$null
# IE - Hide smile button 
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoHelpItemSendFeedback" /t REG_DWORD /d "1" /f >$null
# IE 
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Suggested Sites" /v "Enabled" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer" /v "AllowServicePoweredQSA" /t REG_DWORD /d "1" /f >$null

# Disable location based info in searches
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f >$null

# Disable search web when searching pc
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f >$null

# Send Settings To Cloud
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d "2" /f >$null

# Disable using your machine for sending windows updates to others
# reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f >$null
# P2P Updates Only in LAN
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "1" /f >$null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "3" /f >$null

# Disable synchronizing files to cloud
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d "1" /f >$null

# Disable Telemetry Collection
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >$null 
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f >$null 
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f >$null 
Remove-Item "C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" -Force -EA 0
icacls "C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger" /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

# Disable Web Search in search bar
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f >$null 

# Disable Smart Screen
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f >$null

# Consumer Expr Improvement Program Disable
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >$null

# Application Telemetry Disable
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >$null

# Steps Recorder Disable
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f >$null

# Advertising Info
reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >$null

# LocationAndSensors disable
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\System\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >$null

# Restrict input collection
reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >$null

# Prevent Handwriting data sharing
reg add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f >$null 
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f >$null

# NoLockScreenCamera
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f >$null 

# Biometric disable
reg add "HKLM\Software\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f >$null

# Windows Update
# Dont offer Removal toolkit via AU
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >$null 

# Windows Store AutoUpdate Disable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f >$null

# Disable Windows Update automatic restart
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "UxOption" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d "1" /f >$null
# Disable auto update
# reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f >$null

# Disable Driver download via Windows Update
# reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >$null
# Disable Windows Updates for other products (e.g. Microsoft Office)
# reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" /v "RegisteredWithAU" /t REG_DWORD /d "0" /f >$null

# IE infodelivery stop
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" /v "NoUpdateCheck" /t REG_DWORD /d "1" /f >$null

# IE geolocation stop
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Geolocation" /v "PolicyDisableGeolocation" /t REG_DWORD /d "1" /f >$null

# Control Panel Enhanced icons disabled
# reg add "HKLM\Software\Policies\Microsoft\Windows\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f >$null
# reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f >$null 

# Wifi Sense Disable
reg add "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "Value" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "Value" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\features" /v "WiFiSenseCredShared" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\features" /v "WiFiSenseOpen" /t REG_DWORD /d "0" /f >$null

# Disable Password reveal button
reg add "HKLM\Software\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d "1" /f >$null  

# Disable DRM access to internet
reg add "HKLM\Software\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f >$null

# Disable Remote Assistance
reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f >$null

# Remove 3D Object folder from user profile
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f >$null 2>$null
# Desktop:	{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}
# Documents: {A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}, {d3162b92-9365-467a-956b-92703aca08af}
# Downloads	{374DE290-123F-4565-9164-39C4925E467B}, {088e3905-0323-4b02-9826-5d99428e115f}
# Music	{1CF1260C-4DD0-4ebb-811F-33C572699FDE}, {3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}
# Pictures 	{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}, {24ad3ad4-a569-4530-98e1-ab02f9417aa8}
# Videos {A0953C92-50DC-43bf-BE83-3742FED03C9C}, {f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}
 
# Disable Look for app in the Store
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f >$null

# Disable You have new apps that can open this type of file notification
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoNewAppAlert" /t REG_DWORD /d "1" /f >$null

# Disable Windows Ink
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d "0" /f >$null

# Context menu
# Disable share button 
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v  "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" /f >$null
# Disable Scan with Windows Defender
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f >$null
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f >$null

# Disable Xbox DVR
# reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f >$null

# New User Improving Login Time (disables setup dotnet, ie, wmp, ...)
# reg delete "HKLM\Software\Microsoft\Active Setup\Installed Components\{2C7339CF-2B09-4501-B3F3-F3508C9228ED}\StubPath" /f >$null
# reg delete "HKLM\Software\Microsoft\Active Setup\Installed Components\{2D46B6DC-2207-486B-B523-A557E6D54B47}\StubPath" /f >$null
# reg delete "HKLM\Software\Microsoft\Active Setup\Installed Components\{44BBA840-CC51-11CF-AAFA-00AA00B6015C}\StubPath" /f >$null
# reg delete "HKLM\Software\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}\StubPath" /f >$null
# reg delete "HKLM\Software\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4340}\StubPath" /f >$null
# reg delete "HKLM\Software\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4383}\StubPath" /f >$null
# reg delete "HKLM\Software\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}\StubPath" /f >$null
# reg delete "HKLM\Software\Microsoft\Active Setup\Installed Components\>{22d6f312-b0f6-11d0-94ab-0080c74c7e95}\StubPath" /f >$null

# Disable Firewall
# Set-NetFirewallProfile -Profile * -Enabled False

#

##################
#
# 3. Disabling Tasks
#
Write-Host "3. Disabling Tasks"

schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable 
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable 
schtasks /Change /tn "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\HypervisorFlightingTask" /Disable 
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Location\Notifications" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable 
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable 
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable 
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable 
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable 


####################
#
# 4. Disabling Services
#
Write-Host "4. Disabling Services"

# Set-Service "AppReadiness" -StartupType "Disabled"  -EA 0 # for Modern Apps
Set-Service "DiagTrack" -StartupType "Disabled"  -EA 0 # Diagnostics
Set-Service "diagnosticshub.standardcollector.service" -StartupType "Disabled" -EA 0 # Diagnostics
Set-Service "dmwappushservice" -StartupType "Disabled" -EA 0 # WAP Push Messages
Set-Service "WMPNetworkSvc" -StartupType "Disabled" -EA 0 # Windows Media
Set-Service "HomeGroupListener" -StartupType "Disabled" -EA 0 # HomeGroup
Set-Service "HomeGroupProvider" -StartupType "Disabled" -EA 0 # HomeGroup
## Set-Service "WSearch" -StartupType "Disabled" -EA 0  # Search
## Set-Service "wlidsvc" -StartupType "Disabled" -EA 0  # Microsoft Account Sign-in Assistant 
## XblAuthManager, XblGameSave, XboxNetApiSvc # Xbox Services 

################
#
# 5. Removing Apps
#
# Example: http://www.scconfigmgr.com/2016/03/01/remove-built-in-apps-when-creating-a-windows-10-reference-image/
#
Write-Host "5. Removing Apps"

$Apps = @(
	"Microsoft.3DBuilder",
	"Microsoft.Print3D",
	"Microsoft.BingFinance",
	"Microsoft.BingNews",
	"Microsoft.BingSports",
	"Microsoft.BingFoodAndDrink",
    "Microsoft.BingTravel",
    "Microsoft.BingHealthAndFitness",
	"Microsoft.BingWeather",
    "Microsoft.WindowsReadingList",
	"Microsoft.Getstarted",
	"Microsoft.MicrosoftOfficeHub",
	"Microsoft.MicrosoftSolitaireCollection",
	"Microsoft.Office.OneNote",
	"Microsoft.Office.Sway",
	"Microsoft.People",
	"Microsoft.WindowsCamera",
	"Microsoft.WindowsMaps",
	"Microsoft.WindowsPhone",
	"Microsoft.WindowsSoundRecorder",
	"Microsoft.WindowsFeedbackHub",
	"Microsoft.Messaging",
	"Microsoft.CommsPhone",
	
	"Microsoft.HologramsApp",
	"HoloShell",
	"HoloItemPlayerApp",
	"HoloCamera",
	"Microsoft.MinecraftUWP",
    "Microsoft.NetworkSpeedTest",
	"Microsoft.OneConnect",
	"Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftPowerBIForWindows",
	
	# non-Microsoft
    "9E2F88E3.Twitter",
	"AD2F1837.HPPrinterControl",
    "PandoraMediaInc.29680B314EFC2",
    "Flipboard.Flipboard",
    "ShazamEntertainmentLtd.Shazam",
    "king.com.CandyCrushSaga",
    "king.com.CandyCrushSodaSaga",
    "king.com.*",
    "ClearChannelRadioDigital.iHeartRadio",
    "4DF9E0F8.Netflix",
    "6Wunderkinder.Wunderlist",
    "Drawboard.DrawboardPDF",
    "2FE3CB00.PicsArt-PhotoStudio",
    "D52A8D61.FarmVille2CountryEscape",
    "TuneIn.TuneInRadio",
    "GAMELOFTSA.Asphalt8Airborne",
    #"TheNewYorkTimes.NYTCrossword",
    "DB6EA5DB.CyberLinkMediaSuiteEssentials",
    "Facebook.Facebook",
    "flaregamesGmbH.RoyalRevolt2",
    "Playtika.CaesarsSlotsFreeCasino",
    "A278AB0D.MarchofEmpires",
    "KeeperSecurityInc.Keeper",
    "ThumbmunkeysLtd.PhototasticCollage",
    "XINGAG.XING",
    "89006A2E.AutodeskSketchBook",
    "D5EA27B7.Duolingo-LearnLanguagesforFree",
    "46928bounde.EclipseManager",
    "ActiproSoftwareLLC.562882FEEB491", # Code Writer
    "DolbyLaboratories.DolbyAccess",
    "SpotifyAB.SpotifyMusic",
    "A278AB0D.DisneyMagicKingdoms",
    "WinZipComputing.WinZipUniversal"

	# "Microsoft.MSPaint",
	# "Microsoft.SkypeApp",
	# "microsoft.windowscommunicationsapps",
	
	# apps which cannot be removed using Remove-AppxPackage
    #"Microsoft.BioEnrollment"
    #"Microsoft.MicrosoftEdge"
    #"Microsoft.Windows.Cortana"
    #"Microsoft.WindowsFeedback"
    #"Microsoft.XboxGameCallableUI"
    #"Microsoft.XboxIdentityProvider"
    #"Windows.ContactSupport"
	
	)
foreach ($App in $Apps) 
{
	$AppPackageFullName = Get-AppxPackage -AllUsers -Name $App | Select-Object -ExpandProperty PackageFullName
        
    if ($AppPackageFullName -ne $null)
    {
        try 
        {
            Remove-AppxPackage $AppPackageFullName -EA 0
            Write-Host "$($AppPackageFullName) removed from all users" -ForegroundColor Yellow -BackgroundColor Black
        }
        catch [Exception]
        {
            Write-Host "Error Removing $($AppPackageFullName) from all users`n $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
        }
    }
        
	# provisioned apps
	Get-AppxProvisionedPackage -Online -EA 0 | Where-Object { $_.DisplayName -like $App } |  Remove-ProvisionedAppxPackage -Online -EA 0
}

# 5.1 Removing Capabilities
Write-Host "5.1 Removing Capabilities"
Get-WindowsCapability -Online -EA 0 | ? {$_.Name -like '*ContactSupport*' -and $_.State -like "Installed"} | Remove-WindowsCapability -Online -EA 0
Get-WindowsCapability -Online -EA 0 | ? {$_.Name -like '*Holographic*'  -and $_.State -like "Installed"} | Remove-WindowsCapability -Online -EA 0
Get-WindowsCapability -Online -EA 0 | ? {$_.Name -like '*QuickAssist*'  -and $_.State -like "Installed"} | Remove-WindowsCapability -Online -EA 0


#############################
#
# 6. Disabling Features, OneDrive, Defender & Other
#
Write-Host "6. Disabling Features, OneDrive, Defender & Other"

# 6.1. Disabling OneDrive
Write-Host "6.1. Disabling OneDrive"
# Disable synchronizing files to onedrive
### reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\Skydrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\Skydrive" /v "DisableLibrariesDefaultSaveToSkyDrive" /t REG_DWORD /d "1" /f >$null
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-E9E1-435f-B3D9-28DAA648C0F6}" /f >$null 2>$null
reg delete "HKCR\CLSID{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>$null
reg delete "HKCR\Wow6432Node\CLSID{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>$null
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f >$null
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f >$null
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f >$null 2>$null
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>$null

Stop-Process -Name OneDrive -Force -EA 0
Start-Process "C:\Windows\SysWOW64\OneDriveSetup.exe" "/uninstall" -NoNewWindow -Wait -EA 0
<#takeown /F "C:\Windows\SysWOW64\OneDriveSetup.exe" /A
icacls "C:\Windows\SysWOW64\OneDriveSetup.exe" /inheritance:r /GRANT *S-1-5-32-544:F /C /Q
Remove-Item "C:\Windows\SysWOW64\OneDriveSetup.exe" -Force -EA 0

Start-Process "C:\Windows\System32\OneDriveSetup.exe" "/uninstall" -NoNewWindow -Wait -EA 0
takeown /F "C:\Windows\System32\OneDriveSetup.exe" /A
icacls "C:\Windows\System32\OneDriveSetup.exe" /inheritance:r /GRANT *S-1-5-32-544:F /C /Q
Remove-Item "C:\Windows\System32\OneDriveSetup.exe" -Force -EA 0
#>
# 6.2 Disable Windows Defender
Write-Host "6.2 Disable Windows Defender"
reg add "HKLM\Software\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Wow6432Node\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Wow6432Node\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v  "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" /f >$null
reg add "HKLM\Software\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" /v  "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >$null
# Disable Windows Defender Security Center autorun
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f >$null
# Disable Windows Defender Cloud
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f >$null
reg add "HKLM\Software\Wow6432Node\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Wow6432Node\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f >$null
# Disable Windows Defender Tasks
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable

<# 6.3 Flash 32, 64
takeown /F "C:\Windows\System32\Macromed" /A /R /D Y
icacls "C:\Windows\System32\Macromed" /inheritance:r /GRANT *S-1-5-32-544:F /C /T /Q
Remove-Item "C:\Windows\System32\Macromed" -Recurse -Force
takeown /F "C:\Windows\SysWOW64\Macromed" /A /R /D Y
icacls "C:\Windows\SysWOW64\Macromed" /inheritance:r /GRANT *S-1-5-32-544:F /C /T /Q
Remove-Item "C:\Windows\SysWOW64\Macromed" -Recurse -Force
#>

# IPv6 disable
Write-Host "IPv6 disable"
reg add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "255" /f >$null
netsh interface 6to4 set state state disabled >$null
netsh interface isatap set state disabled >$null
netsh interface teredo set state disabled >$null

# Removing and disabling SMBv1
Write-Host "Removing and disabling SMBv1"
dism /Online /Disable-Feature /FeatureName:SMB1Protocol /Quiet /NoRestart >$null
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0" /f >$null

# Removing Media Player
dism.exe /online /Disable-Feature /Featurename:WindowsMediaPlayer /Quiet /NoRestart >$null

# Power Settings
Write-Host "Powercfg settings"
powercfg -hibernate off >$null
powercfg -change -disk-timeout-ac 0 >$null
powercfg -change -standby-timeout-ac 0 >$null
powercfg -change -monitor-timeout-ac 10 >$null
# Disable wake timers
# https://superuser.com/questions/973009/conclusively-stop-wake-timers-from-waking-windows-10-desktop
powercfg.exe -List | Select-String 'GUID' |
% {
    Write-Host $_
    $guid = $_ -replace '^.*:\s+(\S+?)\s+.*$', '$1'
    powercfg.exe -setdcvalueindex $guid SUB_SLEEP RTCWAKE 0
    powercfg.exe -setacvalueindex $guid SUB_SLEEP RTCWAKE 0
}
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUPowerManagement" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "WakeUp" /t REG_DWORD /d "0" /f >$null



# Clean Start menu & Taskbar, min = 1 item
Write-Host "Default Start Menu"
$StartMenu = "<?xml version=`"1.0`" encoding=`"utf-8`"?>
<LayoutModificationTemplate 
    xmlns=`"http://schemas.microsoft.com/Start/2014/LayoutModification`"
    xmlns:defaultlayout=`"http://schemas.microsoft.com/Start/2014/FullDefaultLayout`"
    xmlns:start=`"http://schemas.microsoft.com/Start/2014/StartLayout`"
    xmlns:taskbar=`"http://schemas.microsoft.com/Start/2014/TaskbarLayout`"
    Version=`"1`">
  <LayoutOptions StartTileGroupCellWidth=`"6`" />
  <DefaultLayoutOverride>
    <StartLayoutCollection>
      <defaultlayout:StartLayout GroupCellWidth=`"6`" xmlns:defaultlayout=`"http://schemas.microsoft.com/Start/2014/FullDefaultLayout`">
        <start:Group Name=`" `" xmlns:start=`"http://schemas.microsoft.com/Start/2014/StartLayout`">
          <!--<start:Tile Size=`"2x2`" Column=`"0`" Row=`"0`" AppUserModelID=`"Microsoft.BingWeather_8wekyb3d8bbwe!App`" />-->
          <start:DesktopApplicationTile Size=`"2x2`" Column=`"0`" Row=`"0`" DesktopApplicationLinkPath=`"%appdata%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk`" />
        </start:Group>
      </defaultlayout:StartLayout>
    </StartLayoutCollection>
  </DefaultLayoutOverride>
  <CustomTaskbarLayoutCollection PinListPlacement=`"Replace`">
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
        <taskbar:DesktopApp DesktopApplicationLinkPath=`"%appdata%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk`" />
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>"
$StartMenu | Out-File -FilePath "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification_tmp.xml" -Force -Encoding utf8
Import-StartLayout -LayoutPath "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification_tmp.xml" -MountPath C:\
