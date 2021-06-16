#
# Kosarev Albert, 2020
#
# Script performs all necessary operations to optimize Windows 10 in 6 sections:
# 1. Applying HKCU Settings to Registry
# All operations performed for default user registry file C:\Users\Default\NTUSER.DAT and for currently logged on user, if there are no logged on users LastLoggedOnUser used
# 2. Applying HKLM Settings
# 3. Disabling Tasks
# Disables all telemetry tasks
# 4. Disabling Services
# Disables telemetry services
# 5. Removing Apps
# Removes annoying Microsoft and 3rd party modern apps and capabilities
# 6. Disabling Features, OneDrive, Defender & Other
#  Disables OneDrive, Windows Defender, IPv6, SMBv1.
#  Set default Power Settings.
#  Cleans Start menu and Taskbar by setting 1 file explorer shortcut.
#
# Script can be primarly used for unattended MDT Windows deployment, it has no user interaction, just comment or uncomment necessary lines.
# Usage (no parameters):
# Set-Windows10-Optimizations.ps1
#
# Optimized to run on recent windows 10 builds, e.g. 1709, 1803, 1809, 1903, 1909, 2004
#
# Sources:
# https://github.com/Disassembler0/Win10-Initial-Setup-Script/
#
# https://gist.github.com/alirobe/7f3b34ad89a159e6daa1 
# https://github.com/W4RH4WK/Debloat-Windows-10/blob/master/scripts/
# https://github.com/hahndorf/Set-Privacy/blob/master/Set-Privacy.ps1
#
# https://github.com/farag2/Windows-10-Sophia-Script/blob/master/Sophia/Sophia.psm1

if ($PSVersionTable.BuildVersion.Major -lt 10) {
    Write-Host This OS version is not supported -ForegroundColor Red
    exit
}
#  1='Work Station' 2='Domain Controller' 3='Server'
if ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -ne 1) {
    Write-Host This OS type is not supported -ForegroundColor Red
    exit
}
$ErrorActionPreference = "SilentlyContinue"

####################################
#
# 1. Applying HKCU Settings to Registry
#
Write-Host "1. Applying HKCU Settings to Registry"
# $CurrentLoggedOnUser = $(Get-WMIObject -Class Win32_ComputerSystem | Select-Object Username).Username.Split("\")[1]

Function GetUserSID
{
	param([string]$username)
	return (Get-WMIObject -Class Win32_UserAccount -Filter "name = '$username'").Sid
}

Function GetUserNameFromSID 
{
	param([string]$sid)
	if ($sid -eq "temp")
	{
		return "Default"
	}
	$objSID = New-Object System.Security.Principal.SecurityIdentifier($sid) 
	$objUser = $objSID.Translate([System.Security.Principal.NTAccount]) 
	return $objUser.Value
}

New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -EA 0 
# Get SID of users who has interactive access to computer
[string[]]$UserSidsArray = (Get-ChildItem "HKU:\" | Where-Object {($_.Name -match "S-1-5-21-") -and ($_.Name -notmatch "Classes$")}).Name | ForEach-Object {$_.Replace("HKEY_USERS\", "")}
$UserSids = New-Object System.Collections.ArrayList(,$UserSidsArray)
# add hku\temp for default user to list
$UserSids.Add("temp")
$UserSids

# Load default user registry
reg load "hku\temp" "C:\Users\Default\NTUSER.DAT" 
Start-Sleep 4
if (Test-Path HKU:\temp)
{
	Write-Host "SUCCESS: The default hive is now loaded by reg load"
} 
else 
{
	SchTasks.exe /Create /TN "DefaultUserRegLoad" /SC ONSTART /TR "reg.exe load hku\temp C:\users\default\NTUSER.DAT" /RU "System" /RL HIGHEST /F
	SchTasks.exe /Run /TN "DefaultUserRegLoad" 
	SchTasks.exe /Delete /TN "DefaultUserRegLoad" /F 
	Start-Sleep 4
	reg query hku\temp > $null
	if (Test-Path HKU:\temp)
	{
		Write-Host "SUCCESS: The default hive is now loaded by task"
	}
}

foreach ($userSid in $UserSids)
{
	if (-not (Test-Path HKU:\$($userSid)))
	{
		Write-Host "HKU:\$($userSid) was not found"
		continue
	}
	Write-Host "Applying settings for user: $(GetUserNameFromSID($userSid)) with path hku\$($userSid)"
	# Change Explorer View to This PC
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f >$null

	# OneDrive (see #6)
	reg delete "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f >$null 2>$null
	reg delete "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>$null

	# Disable autoplay for all media and devices & Disable Autorun
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "1" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f >$null

	# Disable Feedback
	reg add "hku\$($userSid)\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f >$null

	# Disable show most used apps at start menu
	# reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >$null

	# Show recently used files & folders in Quick Access
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f >$null

	# RSS Feeds - Disable
	reg add "hku\$($userSid)\Software\Microsoft\Feeds" /v "SyncStatus" /t REG_DWORD /d "0" /f >$null

	# Advertising Info disable
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >$null

	# Disable Cortana
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >$null
	# Search button only, no field
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "1" /f >$null

	# Cortana history disable
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d "0" /f >$null
	# Disable Bing Search
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >$null
	
	reg add "hku\$($userSid)\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f >$null
	
	# Turn On Quiet Hours Action Center
	# reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_TOASTS_ENABLED" /t REG_DWORD /d "0" /f >$null
	# 1809: Focus Assist: Alarms Only 
	# Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$$windows.data.notifications.quiethourssettings\Current" /v "Data" /t REG_BINARY /d "020000002bc05e5d177dd4010000000043420100c20a01d214264d006900630072006f0073006f00660074002e005100750069006500740048006f00750072007300500072006f00660069006c0065002e0041006c00610072006d0073004f006e006c00790000" /f

	# Disable Startup Run
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "OneDrive"  /t REG_BINARY /d "0300000064A102EF4C3ED101" /f >$null
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "OneDrive"  /t REG_BINARY /d "0300000064A102EF4C3ED101" /f >$null

	# Disable Access to Devices to Modern Apps
	# location sensor:
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f >$null
	# Camera:
	# reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f >$null
	# Mic:
	# reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f >$null
	# Calendar: 
	# reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f >$null
	# SMS, MMS:
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f >$null
	# Wireless interfaces:
	# reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Deny" /f >$null
	# Account info:
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Deny" /f >$null
	# Diagnostics:
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Deny" /f >$null
	# Call History:
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f >$null
	# Email:
	# reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Deny" /f >$null
	# Tasks:
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" /v "Value" /t REG_SZ /d "Deny" /f >$null
	# App notifications:
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Deny" /f >$null
	# Disable apps share and sync non-explicitly paired wireless devices over uPnP
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f >$null
	# ..Settings
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f >$null
	# reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\SettingSync" "BackupPolicy" /t REG_DWORD /d "60" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f >$null
	# ..Location
	reg add "hku\$($userSid)\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f >$null

	# Disabling typing info
	reg add "hku\$($userSid)\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f >$null 

	# Disable "Let websites provide locally relevant content"
	reg add "hku\$($userSid)\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >$null

	# Smart Screen disable
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >$null 

	# Push notification disable, better leave enabled since 1803
	# reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f >$null 

	# Show known file extensions
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f >$null

	# Show hidden files
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f >$null

	# Hide sync provider notifications 
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f >$null

	# Disable simple sharing wizard
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SharingWizardOn" /t REG_DWORD /d "0" /f >$null

	# Show System Protected files
	# reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SuperHidden" /t REG_DWORD /d "1" /f >$null

	# Disable Network Thumbs
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnailsOnNetworkFolders" /t REG_DWORD /d "1" /f >$null
	# Disable Bing search in the Start Menu (USA only)
	reg add "hku\$($userSid)\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f >$null
	
	# Disable Let apps run in the background, since Creators Update
	# Can be problems with notofications in 1809, works ok in 1903:
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >$null
	# dont work for default profile
	# since 2004 cortana = search
	Get-ChildItem "hku:\$($userSid)\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Search*", "Microsoft.Windows.Cortana*","Microsoft.Windows.ShellExperienceHost*","Microsoft.Windows.SecHealthUI*" | ForEach-Object {
			Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
			Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
		}
	

	# Disable downloaded files from being blocked
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "DefaultFileTypeRisk" /t REG_DWORD /d "1808" /f
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f >$null

	# Disable ADS
	# https://winaero.com/blog/disable-ads-windows-10/
	# Stop installing unwanted apps
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >$null
	# Start menu suggestions
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f >$null
	# Ads in explorer
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f >$null
	# Tips about Windows
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f >$null
	# Locksreen images & tips
	# reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f >$null        # problems on logon
	# reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f >$null # problems on logon
	# 
	# Various Ads disable
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f >$null
	reg delete "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f >$null 2>$null
	# Welcome page
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f >$null
	# Settings ads
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000105Enabled" /t REG_DWORD /d "0" /f >$null
	# Disable 'Suggest ways I can finish setting up my device to get most out of Windows', since 2004
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "0" /f >$null
	
	# 1. Disable 3rd party ads for Enterprise/Pro
	reg add "hku\$($userSid)\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f >$null
	# 2. Disable Windows Spotlight notifications in Action Center
	reg add "hku\$($userSid)\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnActionCenter" /t REG_DWORD /d "1" /f >$null
		
	# Do not offer tailored experiences based on the diagnostic data setting (current user only)
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f >$null
		
	# Disable Storage Sense
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d "1" /f >$null

	# Disable Shared Experiences
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\CDP" /v "RomeSdkChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f >$null


	### UI Settings
	# Menu Show Delay Reduce
	reg add "hku\$($userSid)\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "100" /f >$null
	# Hide Taskbar People icon
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d "0" /f >$null
	# Show all tray icons
	# reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f >$null 2>$null
	# Always open the file transfer dialog box in the detailed mode
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d "1" /f >$null
	
	# Disables GameDVR (GameDVR can reduce fps in games)
	reg add "hku\$($userSid)\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f >$null
	reg add "hku\$($userSid)\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f >$null
	
	# Let Windows try to fix apps so they're not blurry
	reg add "hku\$($userSid)\Control Panel\Desktop" /v "EnablePerProcessSystemDPI" /t REG_DWORD /d "1" /f >$null
}

# Unload Default User Registry if it was loaded
if (Test-Path HKU:\temp) {
	[gc]::Collect()
	Start-Sleep 2
	reg unload "hku\temp" 
	Start-Sleep 2
	if (-not (Test-Path HKU:\$($userSid))) {
		Write-Host "SUCCESS: The default hive is now unloaded by reg unload"
	} else {
		Write-Host "Trying to unload..."
		SchTasks.exe /Create /TN "DefaultUserRegUnload" /SC ONSTART /TR "reg.exe unload hku\temp" /RU "System" /RL HIGHEST  /F
		SchTasks.exe /Run /TN "DefaultUserRegUnload" 
		SchTasks.exe /Delete /TN "DefaultUserRegUnload" /F 
		Start-Sleep 2
		reg query hku\temp 
		if (-not (Test-Path HKU:\$($userSid))) {
			Write-Host "SUCCESS: The default hive is now unloaded by task"
		} else {
			Write-Host "ERROR: Default hive is not unloaded"
		}
	}
}

if (Test-Path HKU:\) {
	Remove-PSDrive -Name HKU
}

########################
#
# 2. Applying HKLM Settings
#
Write-Host "2. Applying HKLM Settings"

# Customer experience improvement program - Disable
reg add "HKLM\Software\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >$null

# Disable install 3rd party apps (not for Home Edition) (bloatware tiles in start menu)
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f >$null
# Disable tips (not for Home/Pro)
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f >$null
# Disable video tips in Settings app
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f >$null


# Disable first logon animations
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d "0" /f >$null
# Disable Acrylic on the Sign In Screen, since Windows 10 Version 1903
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /t REG_DWORD /d "1" /f >$null

# Disable Cortana
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >$null
# Disable Web Search in search bar
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f >$null
# Disable location based info in searches
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f >$null
# Disable search web when searching pc
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f >$null

# IE
# IE - Disable first run
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "1" /f >$null
# IE - Addon dialog disable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" /v "IgnoreFrameApprovalCheck" /t REG_DWORD /d "1" /f >$null
# IE - Hide Edge Button
reg add "HKLM\Software\Microsoft\Internet Explorer\Main" /v "HideNewEdgeButton" /t REG_DWORD /d "1" /f >$null
# IE - Hide smile button 
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoHelpItemSendFeedback" /t REG_DWORD /d "1" /f >$null
# IE - Disable suggested sites
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Suggested Sites" /v "Enabled" /t REG_DWORD /d "0" /f >$null
# IE - Disable enhanced suggestions in the Address bar
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer" /v "AllowServicePoweredQSA" /t REG_DWORD /d "0" /f >$null
# IE - Infodelivery stop
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" /v "NoUpdateCheck" /t REG_DWORD /d "1" /f >$null
# IE - geolocation stop
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Geolocation" /v "PolicyDisableGeolocation" /t REG_DWORD /d "1" /f >$null
# Edge - disable preload at startup
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d "0" /f >$null
# Edge - Disable search suggestions
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\SearchScopes" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f >$null
# Edge - Disable phishing filter
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f >$null
# Edge - disable EDGE help tips
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" /v "DisableHelpSticker" /t REG_DWORD /d "1" /f >$null

# Send Settings To Cloud
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d "2" /f >$null
# Disable synchronizing files to cloud
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d "1" /f >$null

# Disable Telemetry Collection
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >$null 
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener\{DD17FA14-CDA6-7191-9B61-37A28F7A10DA}" /v "Enabled" /t REG_DWORD /d "0" /f >$null

reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f >$null
Remove-Item "C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" -Force -EA 0
icacls "C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger" /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
## Disable KMS telemetry
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d "1" /f >$null

# Disable app recommendations 
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "AicEnabled" /t REG_SZ /d "Anywhere" /f >$null

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

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f >$null
reg add "HKLM\System\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >$null
# Disable automatic Maps updates
reg add "HKLM\System\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d "0" /f >$null

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
#
# Windows Update
## Windows Update - Disable auto update
## reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUPowerManagement" /t REG_DWORD /d "0" /f >$null
## Autoupdate: 1= Don't check; 2= Check but don't download; 3= Download but don't install; 4= Download and install
## reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t REG_DWORD /d "1" /f >$null
## Disable OS Upgrade (1703 -> 1709, etc.)
## reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableOSUpgrade" /d "1" /f >$null
## Windows Store AutoUpdate Disable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f >$null
## Disable Windows Update automatic restart
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "UxOption" /t REG_DWORD /d "1" /f >$null
## Set computer active hours to 8-2
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursStart" /t REG_DWORD /d "8" /f >$null
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursEnd" /t REG_DWORD /d "2" /f >$null
##
## Delivery Optimization
## Disable using your machine for sending windows updates to others
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f >$null
## Windows Update - P2P Updates Only in LAN
## reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "1" /f >$null
## reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "3" /f >$null
## Disable Driver download from Windows Update
## reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >$null
## Disable automatic driver downloads from Windows Update
## reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "2" /f >$null
## Disable Windows Updates for other products (e.g. Microsoft Office)
## reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" /v "RegisteredWithAU" /t REG_DWORD /d "0" /f >$null
## Windows Update - Dont offer Removal toolkit via AU
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >$null 
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f >$null 


# Windows 17040 Timeline
# Disable Collect Activity History
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f >$null
# Disable Timeline
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f >$null

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
# Show Runas in Start menu
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "ShowRunasDifferentuserinStart" /t REG_DWORD /d "1" /f >$null

# Disable You have new apps that can open this type of file notification
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoNewAppAlert" /t REG_DWORD /d "1" /f >$null

# Windows 1809: Disable Edge shortcut creation
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "DisableEdgeDesktopShortcutCreation" /t REG_DWORD /d "1" /f >$null

# Disable Windows Ink
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d "0" /f >$null

# Disable automatic maintenance
# reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >$null

# Context menu
# Disable share button 
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v  "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" /f >$null
# Disable Scan with Windows Defender
# reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f >$null 2>$null
# reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f >$null 2>$null



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
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable 
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\Location\Notifications" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable 
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable 
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
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
$AppRemover = {
	$Apps = @(
		"Microsoft.549981C3F5F10", # cortana app
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
		"Microsoft.OfficeLens",
		"Microsoft.Whiteboard",
		"Microsoft.Microsoft3DViewer",
		
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
		"Facebook.Facebook",
		"ThumbmunkeysLtd.PhototasticCollage",
		"XINGAG.XING",
		"89006A2E.AutodeskSketchBook",
		"D5EA27B7.Duolingo-LearnLanguagesforFree",
		"46928bounde.EclipseManager",
		"ActiproSoftwareLLC.562882FEEB491", # Code Writer
		"DolbyLaboratories.DolbyAccess",
		"SpotifyAB.SpotifyMusic",
		"A278AB0D.DisneyMagicKingdoms",
		"WinZipComputing.WinZipUniversal",
		"A278AB0D.DragonManiaLegends",
		"Nordcurrent.CookingFever",
		# 1809
		"Microsoft.YourPhone",
		"Microsoft.MixedReality.Portal"
		
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
		Get-AppxProvisionedPackage -Online -EA 0 | Where-Object { $_.DisplayName -match $App } |  Remove-ProvisionedAppxPackage -Online -EA 0
	}

	# 5.1 Removing Capabilities
	Write-Host "5.1 Removing Capabilities"
	Get-WindowsCapability -Online -EA 0 | Where-Object {$_.Name -like '*ContactSupport*' -and $_.State -like "Installed"} | Remove-WindowsCapability -Online -EA 0
	Get-WindowsCapability -Online -EA 0 | Where-Object {$_.Name -like '*Holographic*'  -and $_.State -like "Installed"} | Remove-WindowsCapability -Online -EA 0
	Get-WindowsCapability -Online -EA 0 | Where-Object {$_.Name -like '*QuickAssist*'  -and $_.State -like "Installed"} | Remove-WindowsCapability -Online -EA 0
}

$JobGUID = [system.Guid]::NewGuid()
Start-Job -ScriptBlock $AppRemover -Name $JobGUID
# Wait for job 300 seconds
Wait-Job -Name $JobGUID -Timeout 300



#############################
#
# 6. Disabling Features, OneDrive, Defender & Other
#
Write-Host "6. Disabling Features, OneDrive, Defender & Other"

# 6.1. Disabling OneDrive
Write-Host "6.1. Disabling OneDrive"
# Disable synchronizing files to onedrive
### reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >$null # blocks onedrive completely even for installing
reg add "HKLM\Software\Policies\Microsoft\Windows\Skydrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\Skydrive" /v "DisableLibrariesDefaultSaveToSkyDrive" /t REG_DWORD /d "1" /f >$null
<# dont delete these fodler description because it can prevent folder renaming
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-E9E1-435f-B3D9-28DAA648C0F6}" /f >$null 2>$null
#>
# Remove OneDrive from Explorer sidebar
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f >$null
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f >$null
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f >$null 2>$null
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /f >$null 2>$null

Stop-Process -Name OneDrive -Force -EA 0
Start-Process "C:\Windows\SysWOW64\OneDriveSetup.exe" "/uninstall" -NoNewWindow -Wait -EA 0
#takeown /F "C:\Windows\SysWOW64\OneDriveSetup.exe" /A
#icacls "C:\Windows\SysWOW64\OneDriveSetup.exe" /inheritance:r /GRANT *S-1-5-32-544:F /C /Q
#Remove-Item "C:\Windows\SysWOW64\OneDriveSetup.exe" -Force -EA 0

Start-Process "C:\Windows\System32\OneDriveSetup.exe" "/uninstall" -NoNewWindow -Wait -EA 0
#takeown /F "C:\Windows\System32\OneDriveSetup.exe" /A
#icacls "C:\Windows\System32\OneDriveSetup.exe" /inheritance:r /GRANT *S-1-5-32-544:F /C /Q
#Remove-Item "C:\Windows\System32\OneDriveSetup.exe" -Force -EA 0

# 6.2 Disable Windows Defender
Write-Host "6.2 Disable Windows Defender"
Set-MpPreference 	-DisableIntrusionPreventionSystem $true `
					-DisableIOAVProtection $true `
					-DisableRealtimeMonitoring $true `
					-DisableScriptScanning $true `
					-EnableControlledFolderAccess Disabled `
					-EnableNetworkProtection AuditMode -Force `
					-MAPSReporting Disabled `
					-SubmitSamplesConsent NeverSend
# https://pastebin.com/kYCVzZPz
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f >$null

reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v  "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f > $null


# Disable Windows Defender Security Center autorun
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f >$null 2>$null
# Disable Windows Defender Cloud
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f >$null
# Cleanup
Remove-Item "C:\ProgramData\Microsoft\Windows Defender\Definition Updates" -Force -Recurse -EA 0

<# 6.3 Flash 32, 64
takeown /F "C:\Windows\System32\Macromed" /A /R /D Y
icacls "C:\Windows\System32\Macromed" /inheritance:r /GRANT *S-1-5-32-544:F /C /T /Q
Remove-Item "C:\Windows\System32\Macromed" -Recurse -Force
takeown /F "C:\Windows\SysWOW64\Macromed" /A /R /D Y
icacls "C:\Windows\SysWOW64\Macromed" /inheritance:r /GRANT *S-1-5-32-544:F /C /T /Q
Remove-Item "C:\Windows\SysWOW64\Macromed" -Recurse -Force
#>

# Network
# Allow connect to anon shares since 1709
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "AllowInsecureGuestAuth" /t REG_DWORD /d "1" /f >$null
# Disable NetBIOS on all network interfaces
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | ForEach-Object {Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name "NetbiosOptions" -Type DWord -Value 2}
# Disable LLMNR protocol (UDP 5355) useful for domain environment
# reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t "REG_DWORD" /d "0" /f

# IPv6 disable
#reg add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "255" /f >$null
# Prefer IPv4 over IPv6; IPv6 is still enabled, optimized for UWP apps in 1809
reg add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "32" /f >$null
netsh interface 6to4 set state state disabled >$null
netsh interface isatap set state disabled >$null
netsh interface teredo set state disabled >$null

# Removing and disabling SMBv1
Write-Host "Removing and disabling SMBv1"
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0" /f >$null

# Removing Media Player
# dism.exe /online /Disable-Feature /Featurename:WindowsMediaPlayer /Quiet /NoRestart >$null

# Power Settings
Write-Host "Powercfg settings"
powercfg -hibernate off >$null
powercfg -change -disk-timeout-ac 0 >$null
powercfg -change -standby-timeout-ac 0 >$null
powercfg -change -monitor-timeout-ac 15 >$null
# Disable wake timers
# https://superuser.com/questions/973009/conclusively-stop-wake-timers-from-waking-windows-10-desktop
powercfg.exe -List | Select-String 'GUID' | ForEach-Object {
    Write-Host $_
    $guid = $_ -replace '^.*:\s+(\S+?)\s+.*$', '$1'
    powercfg.exe -setdcvalueindex $guid SUB_SLEEP RTCWAKE 0
    powercfg.exe -setacvalueindex $guid SUB_SLEEP RTCWAKE 0
}
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUPowerManagement" /t REG_DWORD /d "0" /f >$null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "WakeUp" /t REG_DWORD /d "0" /f >$null

# Enable registry backup: http://www.outsidethebox.ms/19515/
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "EnablePeriodicBackup" /t REG_DWORD /d 1 /f >$null


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
