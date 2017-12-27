# Set-Windows10-Optimizations

Script performs all necessary operations in 6 sections:

1. Applying HKCU Settings to Registry

All operations performed for default user registry file C:\Users\Default\NTUSER.DAT.

_All results will be applied only to the new users._

Disables telemetry, ads, set explorer settings.


2. Applying HKLM Settings

Disables telemetry and ads, configures updates, IE.


*3. Disabling Tasks*

Disables all telemetry tasks.


*4. Disabling Services*

Disables telemetry services.


*5. Removing Apps*

Removes annoying Microsift and 3rd party modern apps and capabilities.


*6. Disabling Features, OneDrive, Defender & Other*

Disables OneDrive, Windows Defender, IPv6, SMBv1.

Set default Power Settings.

Cleans Start menu and Taskbar by setting 1 file explorer shortcut.


Script can be primarly used for unattended MDT Windows deployment, it has no user interaction, just comment or uncomment necessary lines.

Usage:

Set-Windows10-Optimizations.ps1


**Parameters:**

no parameters



#### Kosarev Albert, 2017
