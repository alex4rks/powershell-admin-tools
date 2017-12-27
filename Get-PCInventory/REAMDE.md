# Get-PCInventory

Script get CPU, RAM Motherboard, BIOS, Videocontroller, HDD, Network, OS info, checks if computer is VM and output it to the console or to the CSV or TXT file. All date are obtained from WMI queries.


Usage:

Load file into PS: Import-Module Get-PCInventory.ps1 -Force

**Parameters:**

-ADSearch - [switch] - search in AD location

-ADSearchBase - set AD location

-File - input file with pc names list

-Computer - single ip or dns name to check

-ReportPath - per PC txt/csv output file

-Txt - [switch] - if enabled creates txt file instead of CSV

-Csv - [switch] - output CSV file

If no output switches enabled output will be shown only on screen


**Example:**

```powershell
Get-PCInfo -Computer 192.168.1.4
 

Name                    : <COMPUTERNAME>
CPU Model               : Intel(R) Core(TM) i5-4670 CPU @ 3.40GHz
Physical Cores          : 4
Logical Cores           : 4
Motherboard Maker       : Gigabyte Technology Co., Ltd.
Motherboard Model       : H87-D3H-CF
BIOS Ver.               : F10
Total RAM (GB)          : 16
RAM Cap. GB = Speed MHz : 4 = 1333, 4 = 1333, 4 = 1333, 4 = 1333
Pagefile = MB           : C:\pagefile.sys = 2432
Video Card = RAM (MB)   : Intel(R) HD Graphics 4600 = 1024
Boot type               : UEFI
Disk Controller         : Intel(R) 8 Series/C220 Chipset Family SATA AHCI Controller
Disk = Size (GB)        : WDC WD2003FZEX-00Z4SA0 = 1863
Partitions (GB)         : C: 183 free of 224
                          D: 1089 free of 1638
NIC = Speed (Mbit)      : Intel(R) Ethernet Connection I217-V = 1000
NIC MAC                 : 94:00:00:B6:47:5B
NIC IP                  : 192.168.1.4
OS Name                 : Microsoft Windows 10 Enterprise
OS Version              : 10.0.16299
OS install date         : 2017-12-12
Current user            : <USERNAME>
Boot time = Uptime      : 2017-12-19 11:37:31 = 8days 2h 39m
Virtual Machine?        :
```



#### Kosarev Albert, 2017