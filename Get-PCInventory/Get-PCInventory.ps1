# //Requires -RunAsAdministrator

function Get-ComputerVirtualStatus {
    <#
    .SYNOPSIS
        internal function, check if computer is VM
    .DESCRIPTION
        Checks if computer is VM: Hyper-V, VMWare, VirtualPC, Xen, etc.
    .EXAMPLE
        PS C:\> Get-ComputerVirtualStatus -BIOSVersion $BIOS.Version -SerialNumber $BIOS.SerialNumber -Manufacturer $ComputerSystem.Manufacturer -Model $ComputerSystem.Model
    #>
	[CmdletBinding()]
	param( 
        [Parameter(Mandatory = $true)]
		[string]$BIOSVersion,
        [Parameter(Mandatory = $true)]
		[string]$SerialNumber,
        [Parameter(Mandatory = $true)]
		[string]$Manufacturer,
        [Parameter(Mandatory = $true)]
		[string]$Model
    ) 
    $Results = @()
   
    $ResultProps = @{   
        IsVirtual = $false 
        VirtualType = $null 
    }
    if ($SerialNumber -like "*VMware*") {
        $ResultProps.IsVirtual = $true
        $ResultProps.VirtualType = "Virtual - VMWare"
    }
    else {
        switch -wildcard ($BIOSVersion) {
            'VIRTUAL' { 
                $ResultProps.IsVirtual = $true 
                $ResultProps.VirtualType = "Virtual - Hyper-V" 
            } 
            'A M I' {
                $ResultProps.IsVirtual = $true 
                $ResultProps.VirtualType = "Virtual - Virtual PC" 
            } 
            '*Xen*' { 
                $ResultProps.IsVirtual = $true 
                $ResultProps.VirtualType = "Virtual - Xen" 
            }
        }
    }
    if (-not $ResultProps.IsVirtual) {
        if ($Manufacturer -like "*Microsoft*") { 
            $ResultProps.IsVirtual = $true 
            $ResultProps.VirtualType = "Virtual - Hyper-V" 
        } 
        elseif ($Manufacturer -like "*VMWare*") { 
            $ResultProps.IsVirtual = $true 
            $ResultProps.VirtualType = "Virtual - VMWare" 
        } 
        elseif ($Model -like "*Virtual*") { 
            $ResultProps.IsVirtual = $true
            $ResultProps.VirtualType = "Unknown Virtual Machine"
        }
    }
    $Results += New-Object PsObject -Property $ResultProps
    
    return $Results
}
 


function Get-PCInventory {
    <#
    .SYNOPSIS
        Internal function, gathers data from specified CIM session
    .DESCRIPTION
        Get-CimInstance is used rather than Get-WMIObject to get more speed, stability over slow links 
    .EXAMPLE
        PS C:\> Get-PCInventory -s $pc -CimSession $session
    #>
	[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string]$s,
        [Parameter(Mandatory = $true)]
        $CimSession,
        [switch]$DiskUsageDetailed
    )
    
    $videocontrollerlist = $null
    $disklist = $null
    $logicaldisklist = $null
    $niclist = $null
    $nicDrvList = $null
    $nicmaclist = $null
    $niciplist = $null
    $CPUListName = $null
    $CPUListPhysicalCores = $null
    $CPUListLogicalCores = $null
    $RAMBankList = $null

    $infoObject = New-Object PSObject	
	
        if (!($ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession)) {
            Add-Member -inputObject $infoObject -memberType NoteProperty -name "Name" -value "$($s) is online but RPC is closed == possible DNS name mismatch"
            $infoObject #Output to the screen for a visual feedback.
	        $infoColl += $infoObject
            Continue;
        }

        $CPUInfo = Get-CimInstance -ClassName Win32_Processor -CimSession $CimSession #Get CPU Information
	    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $CimSession #Get OS Information
        #$OSInstallDate = (([WMI]'').ConvertToDateTime((Get-WmiObject Win32_OperatingSystem -ComputerName $s).InstallDate)).tostring('yyyy-MM-dd')
        $OSInstallDate = $OSInfo.InstallDate.ToString("yyyy-MM-dd")
        
        # Windows 10 build number 
        # https://devblogs.microsoft.com/scripting/registry-cmdlets-working-with-the-registry/
        if ($OSInfo.Version.StartsWith("10.")) {	
            [uint32]$HKLM = 2147483650
            $Key = "Software\Microsoft\Windows NT\CurrentVersion"
            $OSReleaseId = (Invoke-CimMethod -Namespace root/cimv2 -ClassName StdRegProv `
                -MethodName GetSTRINGvalue -CimSession $CimSession `
                -Arguments @{hDefKey = $HKLM; sSubKeyName = $Key; sValueName = "ReleaseId"}).sValue 
            $OSUpdateBuildRelease = (Invoke-CimMethod -Namespace root/cimv2 -ClassName StdRegProv `
                -MethodName GetDWORDvalue -CimSession $CimSession `
                -Arguments @{hDefKey = $HKLM; sSubKeyName = $Key; sValueName = "UBR"}).uValue
        }
        
        # Get correct Video controller RAM value, more than 4 GB 
        # https://superuser.com/questions/1461858/fetch-correct-vram-for-gpu-via-command-line-on-windows
        [uint32]$HKLM = 2147483650
        $Key = "SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
        $VideoKeys = Invoke-CimMethod -Namespace root/cimv2 -ClassName StdRegProv `
            -MethodName EnumKey -CimSession $CimSession `
            -Arguments @{hDefKey = $HKLM; sSubKeyName = $Key} 
        $VideoKeys = $VideoKeys.sNames | Where-Object {$_.StartsWith("0")}

        $VideoRamHash = $null
        $VideoRamHash = @{}
        foreach ($videoKey in $VideoKeys) {
            $Value1_MatchingDeviceId = (Invoke-CimMethod -Namespace root/cimv2 -ClassName StdRegProv `
                -MethodName GetSTRINGvalue -CimSession $CimSession `
                -Arguments @{hDefKey = $HKLM; sSubKeyName = "$($key)\$($videoKey)"; sValueName = "MatchingDeviceId"}).sValue 
            $Value2_qwMemorySize = (Invoke-CimMethod -Namespace root/cimv2 -ClassName StdRegProv `
                -MethodName GetQWORDvalue -CimSession $CimSession `
                -Arguments @{hDefKey = $HKLM; sSubKeyName = "$($key)\$($videoKey)"; sValueName = "HardwareInformation.qwMemorySize"}).uValue
            if ($Value2_qwMemorySize -and (! ($VideoRamHash.ContainsKey($Value1_MatchingDeviceId)))) {
                $VideoRamHash.Add($Value1_MatchingDeviceId, $Value2_qwMemorySize)
            }
        }
        # $VideoRamHash

        # Motherboard
        $MotherBoard = Get-CimInstance -ClassName Win32_BaseBoard -CimSession $CimSession
        
        #BIOS
        $BIOS = Get-CimInstance -ClassName Win32_BIOS -CimSession $CimSession

        #Get Memory Information. The data will be shown in a table as MB, rounded to the nearest second decimal.
	    #$OSTotalVirtualMemory = [math]::round($OSInfo.TotalVirtualMemorySize / 1MB, 2)
	    #$OSTotalVisibleMemory = [math]::round(($OSInfo.TotalVisibleMemorySize / 1MB), 2)
	    $PhysicalMemory = Get-CimInstance -ClassName CIM_PhysicalMemory -CimSession $CimSession
        $PhysicalMemoryTotal = Get-CimInstance -ClassName CIM_PhysicalMemory -CimSession $CimSession | Measure-Object -Property capacity -Sum | 
            ForEach-Object { [Math]::Round(($_.sum / 1GB), 2) }
        $PageFile = (Get-CimInstance -ClassName Win32_PageFileUsage -CimSession $CimSession -Property *)

        $VideoController = Get-CimInstance -ClassName Win32_VideoController -CimSession $CimSession

		$IsUEFI = Get-CimInstance -ClassName Win32_DiskPartition -Filter "Type = 'GPT: System'" -CimSession $CimSession
        $HddInfo = Get-CimInstance -ClassName Win32_DiskDrive -Filter "MediaType LIKE 'Fixed%'" -CimSession $CimSession | 
            Select-Object Model,@{Name='Size(GB)';Exp={[math]::Round($_.Size /1gb, 2) -as [int]}}, InterfaceType
        $LogicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -CimSession $CimSession
        
        # NIC
        $NicInfo = Get-CimInstance -ClassName Win32_NetworkAdapter -CimSession $CimSession | 
            Where-Object { $_.Speed -and $_.Macaddress -and $_.Name -notmatch 'virtual|loop' } # -notmatch 'virtual|802\.11' ; wireless|wi-fi|
            # -Filter "NetEnabled='True'"
        foreach ($NetworkAdapter in $NicInfo) {
            $NicConfig = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -CimSession $CimSession -Filter "Index = '$($NetworkAdapter.Index)'"
            $NicDriver = Get-CimInstance -ClassName Win32_PnPSignedDriver -CimSession $CimSession -Filter "DeviceClass = 'NET'" | 
                Where-Object {$_.DeviceID -eq  $NetworkAdapter.PNPDeviceID}
        }

        # Get current logged in user
        $CurrentUser = $ComputerSystem.Username
         
		##
        ##
        ## Make a table: Add data to the infoObjects.	
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Name" -value $ComputerSystem.Name
		
        # CPU
        foreach ($CPU in $CPUInfo) {
            $CPUName = $CPU.Name -replace "  +"," "
            $CPUListName +=  "$($CPUName)`n"
            $CPUListPhysicalCores += "$($CPU.NumberOfCores)`n"
            $CPUListLogicalCores += "$($CPU.NumberOfLogicalProcessors)`n"
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU Model" -value $CPUListName.Substring(0, $CPUListName.Length - 1)
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Physical Cores" -value $CPUListPhysicalCores.Substring(0, $CPUListPhysicalCores.Length - 1)
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Logical Cores" -value $CPUListLogicalCores.Substring(0, $CPUListLogicalCores.Length - 1)

        # Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU Description" -value $CPUInfo.Description
		# Add-Member -inputObject $infoObject -memberType NoteProperty -name "Manufacturer" -value $CPUInfo.Manufacturer
		
		# Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU_L2CacheSize" -value $CPUInfo.L2CacheSize
		# Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU_L3CacheSize" -value $CPUInfo.L3CacheSize
		# Add-Member -inputObject $infoObject -memberType NoteProperty -name "Sockets" -value $CPUInfo.SocketDesignation
		
        # MB
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Motherboard Maker" -value $MotherBoard.Manufacturer
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Motherboard Model" -value $MotherBoard.Product
        		
        # BIOS
        # Add-Member -inputObject $infoObject -memberType NoteProperty -name "BIOS Name" -value $BIOS.Name
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "BIOS Ver." -value $BIOS.SMBIOSBIOSVersion

        # RAM		
        foreach ($RAMBank in $PhysicalMemory) {
            $RAMBankList += "$([math]::Round($RAMBank.Capacity /1GB, 2)) = $([int]$RAMBank.Speed), "
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Total RAM (GB)" -value $PhysicalMemoryTotal
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "RAM Cap. GB = Speed MHz" -value $RAMBankList.Substring(0, $RAMBankList.Length - 2)
        # Add-Member -inputObject $infoObject -memberType NoteProperty -name "TotalVirtual_Memory_MB" -value $OSTotalVirtualMemory
		# Add-Member -inputObject $infoObject -memberType NoteProperty -name "TotalVisable_Memory_MB" -value $OSTotalVisibleMemory
        
        # Pagefile
        $Pagefileinfo = "$($PageFile.Name) = $($PageFile.AllocatedBaseSize)"
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Pagefile = MB" -value $Pagefileinfo
        
        # Video
		# if 1 video adapter then print it even if it 'Basic Display Adapter'
        foreach ($video in $VideoController) {
            if ($video.Name -match "NVIDIA") {
                # 23.21.13.9101 ==> 391.01
                $drv = "drv: " + $video.DriverVersion.Substring(7).replace('.', '').insert(3, '.') + "  date: " + $video.DriverDate.ToString('yyyy-MM-dd')
            }
            if ($video.Name -match "Intel") {
                # 20.19.15.4835 ==> 15.4835
                $drv = "drv: " + $video.DriverVersion.Substring(6) + "  date: " + $video.DriverDate.ToString('yyyy-MM-dd')
            }
            if ($video.Name -match "AMD") {
               $drv = "drv: " + $video.DriverVersion + "  date: " + $video.DriverDate.ToString('yyyy-MM-dd')
            }
            
            $VideoPnpDeviceIdShort = $video.PNPDeviceID.split('&')[0] + "&" + $video.PNPDeviceID.split('&')[1] 
            $VideoControllerAdapterRam =  $VideoRamHash.Item($VideoPnpDeviceIdShort)
            $videocontrollerlist += "$($video.Name) = $([math]::Round($VideoControllerAdapterRam/1MB, 1))`n$drv`n"
            $drv = $null
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Video Card = RAM (MB)" -value $videocontrollerlist.Substring(0, $videocontrollerlist.Length - 1)
        
		$boottype = "Legacy boot"
		if ($IsUEFI) {
			$boottype = "UEFI"
		}
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Boot type" -value $boottype
		
		# disk controller
		#foreach ($diskController in $IdeController){
        #   $diskControllerlist += "$($diskController.Name)`n"}
		#Add-Member -inputObject $infoObject -memberType NoteProperty -name "Disk Controller" -value $diskControllerlist.Substring(0, $diskControllerlist.Length - 1)
		
        # disks
        foreach ($disk in $HddInfo) {
            $disklist += "$($disk.Model) = $($disk.'Size(GB)')`n"
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Disk = Size (GB)" -value $disklist.Substring(0, $disklist.Length - 1)

        foreach ($logicalDisk in $LogicalDisks) {
            if ($logicalDisk.DriveType -eq 3) {
                $logicalDiskList += "$($logicalDisk.DeviceID) $([math]::Round($logicalDisk.FreeSpace / 1GB, 0)) free of $([math]::Round($logicalDisk.Size / 1GB, 0))`n"
            }
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Partitions (GB)" -value $logicalDiskList.Substring(0, $logicalDiskList.Length - 1)
        
        # NICs
        foreach ($nic in $NicInfo) {
            $niclist += "$($nic.Name) = $([math]::Round($nic.speed/1000000,0))`n"
            $nicmaclist +="$($nic.MACAddress.Replace(':', '-'))`n"
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "NIC = Speed (Mbit)" -value $niclist.Substring(0, $niclist.Length - 1)
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "NIC MAC" -value $nicmaclist.Substring(0, $nicmaclist.Length - 1)

        # NIC driver info
        foreach ($nicDrv in $NicDriver) {
            $nicDrvList += "drv: $($nicDrv.DriverVersion)  date: $($nicDrv.DriverDate.ToString('yyyy-MM-dd'))`n"
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "NIC Driver Ver = Date" -value $nicDrvList.Substring(0, $nicDrvList.Length - 1)

        # NIC IP
        foreach ($nicip in $NicConfig) {
            $niciplist += "$($nicip.IPAddress)`n"
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "NIC IP" -value $niciplist.Substring(0, $niciplist.Length - 1)

        # OS
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS Name" -value "$($OSInfo.Caption) $($OSReleaseId)"
		if ($OSReleaseId) {
			Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS Version" -value "$($OSInfo.Version)..$($OSUpdateBuildRelease)"
		} else {
			Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS Version" -value $OSInfo.Version
		}
		
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS install date" -value $OSInstallDate 
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Current user" -value $CurrentUser
        
		# OS Boot & Uptime
		$Uptime = $OSInfo.LocalDateTime - $OSInfo.LastBootUpTime
        $UptimeString = "$($Uptime.Days)days $($Uptime.Hours)h $($Uptime.Minutes)m"
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Boot time = Uptime" -value "$($OSInfo.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')) = $($UptimeString)"
        # Admin users

        # Virtual
        $VirtualStatus = Get-ComputerVirtualStatus -BIOSVersion $BIOS.Version -SerialNumber $BIOS.SerialNumber -Manufacturer $ComputerSystem.Manufacturer -Model $ComputerSystem.Model
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Virtual Machine?" -value $VirtualStatus.VirtualType

    return $infoObject
}


function Get-DiskUsage {
    <#
    .SYNOPSIS
        Internal function, gathers disk usage
    .DESCRIPTION
        
    .EXAMPLE
        PS C:\> Get-DiskUsage -s $pc -CimSession $session
    #>
	[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string]$s,
        [Parameter(Mandatory = $true)]
        $CimSession
    )
    $obj = New-Object PSObject	
	Add-Member -inputObject $obj -memberType NoteProperty -name "Name" -value $s
    
        
    #$LogicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -CimSession $CimSession | Where-Object {($_.DriveType -eq 3) -and ($_.Size -gt 0) -and ($_.DeviceID -eq 'D:')}
    # todo: remove hardcoded drive ids
    $LogicalDiskC = Get-CimInstance -ClassName Win32_LogicalDisk -CimSession $CimSession | Where-Object {$_.DeviceID -match 'C:'}
    $LogicalDiskD = Get-CimInstance -ClassName Win32_LogicalDisk -CimSession $CimSession | Where-Object {$_.DeviceID -match 'D:'}
    # Check disk usage for C: D: disks, write values separated (useful for Excel reporting)
    #foreach ($logicalDisk in $LogicalDisks) {
    #write-host $logicalDisk.DeviceID
    Add-Member -inputObject $obj -memberType NoteProperty -name ("C: free (GB)") -value $([math]::Round($logicalDiskC.FreeSpace / 1GB, 0))
    Add-Member -inputObject $obj -memberType NoteProperty -name ("C: total (GB)") -value $([math]::Round($logicalDiskC.Size / 1GB, 0))
    if ($LogicalDiskC.FreeSpace -gt 0) {
        $DriveCFreeSpace = [math]::Floor($LogicalDiskC.FreeSpace * 100 / $logicalDiskC.Size)
    } else {
        $DriveCFreeSpace = ""
    }
    Add-Member -inputObject $obj -memberType NoteProperty -name ("C: free %") -value $DriveCFreeSpace
    
    
    if ($LogicalDiskD.Size -gt 0) {
        $D_FreeSpace = $([math]::Round($logicalDiskD.FreeSpace / 1GB, 0))
        $D_Size = $([math]::Round($logicalDiskD.Size / 1GB, 0))
        $D_FreeSpacePercent = [math]::Floor($LogicalDiskD.FreeSpace * 100 / $logicalDiskD.Size)

    } else {
        $D_FreeSpace = ""
        $D_Size = ""
        $D_FreeSpacePercent = ""
    }
    Add-Member -inputObject $obj -memberType NoteProperty -name ("D: free (GB)") -value $D_FreeSpace
    Add-Member -inputObject $obj -memberType NoteProperty -name ("D: total (GB)") -value $D_Size
    Add-Member -inputObject $obj -memberType NoteProperty -name ("D: free %") -value $D_FreeSpacePercent
       
    $WorkspaceName = $null
    $WorkspaceRoot = $null
    
    # https://stackoverflow.com/questions/51668578/split-multi-line-cell-into-new-rows-below
    foreach ($Workspace in $global:p4WorkspacesAll) {
        if ($Workspace.Split(";")[0] -eq $s) {
            $WorkspaceName += $Workspace.Split(";")[1] + "`n"
            $WorkspaceRoot += $Workspace.Split(";")[2] + "`n"
            $WorkspaceNameRoot += $Workspace.Split(";")[1] + "  "+ $Workspace.Split(";")[2] + "`n"
        }
    }
    
    if ($WorkspaceName){
        Add-Member -inputObject $obj -memberType NoteProperty -name "p4:ws_name  root" -value "$($WorkspaceNameRoot.Trim())"
    }
    <#if ($WorkspaceRoot){
        Add-Member -inputObject $obj -memberType NoteProperty -name "p4:ws_root" -value $WorkspaceRoot.Trim()
    }#>
    #Add-Member -inputObject $infoObject -memberType NoteProperty -name "$($logicalDiskD.DeviceID) free (GB)" -value $([math]::Round($logicalDiskD.FreeSpace / 1GB, 0))
    #Add-Member -inputObject $infoObject -memberType NoteProperty -name "$($logicalDiskD.DeviceID) total (GB)" -value $([math]::Round($logicalDiskD.Size / 1GB, 0))
    
    return $obj
}

function Get-PCInfo {
    <#
    .SYNOPSIS
        Get PC inventory report
    .DESCRIPTION
        The script gathers information, such as CPU, RAM, Disk, video, NIC, from specified computer and output it to console by default
    .PARAMETER Computer
		Name, IP address of the computer
	.PARAMETER InputFile
		Path to the txt file with computer list
	.PARAMETER ADSearch
		Search in AD location
	.PARAMETER ADSearchBase
		Set AD location
	.PARAMETER ReportPath
		Output each report into separate file
	.PARAMETER Txt
		If enabled creates txt file instead of CSV
	.PARAMETER Csv
		Output all PC reports in CSV file
		If no output switches enabled output will be shown only on screen
	.EXAMPLE
        PS C:\> Get-PCInfo -Computer 192.168.10.10 -Txt
        Get txt report to default path in $ReportPath
	.EXAMPLE
        PS C:\> Get-PCInfo -Computer computer1 -WSMan
        Get console report using WSMan protocol for slow links
    .NOTES    
    #>
    [CmdletBinding()]
    param(
		[string]$Computer,
        [string]$InputFile,
        [switch]$ADSearch,
        [string]$ADSearchBase = "OU=,OU=,DC=,DC=",
        [string]$ReportPath,
        [switch]$Txt,
        [switch]$Csv,
        [switch]$WSMan,
        [switch]$DiskUsageDetailed
    )
    
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    if (($ReportPath.Length -gt 1) -and ((-not $Txt) -or (-not $Csv))) {
        $Csv = $True
    }

    # Get pc list from AD or from File
    $PCName = @()
    if ($ADSearch) {
        Import-Module ActiveDirectory
        $PCs = Get-ADComputer -Filter {Enabled -eq $True} -SearchBase $ADSearchBase | Select-Object Name | Sort-Object -Property Name
        # $PCs
        $PCName = $PCs.Name
    } elseif ($InputFile.Length -gt 1) {
        $PCName = Get-Content $InputFile
    }
    if ($Computer.Length -gt 1) {
        $PCName = $Computer
    }
    

    $infoColl = @()
    $opts = $null
    if (!($WSMan)) {
        $opts = New-CimSessionOption -Protocol Dcom
    }
    
    foreach ($pc in $PCName) {    
        # it can be comments in txt input file
        if (($pc.StartsWith("#")) -or ($pc.Length -eq 0)) {
            continue
        } 
        
        if ($session = New-CimSession -ComputerName $pc -OperationTimeoutSec 3 -SessionOption $opts -ErrorAction SilentlyContinue) {
            if ($DiskUsageDetailed.IsPresent) {
                $global:p4WorkspacesAll = & "C:\Program Files\Perforce\p4.exe" -ztag -F "%Host%;%client%;%Root%" clients

                $infoObject = Get-DiskUsage -s $pc -CimSession $session
            } else {
                $infoObject = (Get-PCInventory -s $pc -CimSession $session)
            }

            if ($Txt) {
                $infoObject | Out-File -File "$ReportPath\$($infoObject.Name).txt" -Encoding Unicode
                Write-host "`n$($infoObject.Name) Report saved at $($ReportPath)\$($infoObject.Name).txt" -ForegroundColor Green
                $infoObject
                Continue
            }
            $infoObject
            $infoColl += $infoObject
        } else {
            if ($Csv) {
                $infoObjectUnreachable = New-Object PsObject -Property @{ Name = "$($pc) is unreachable" }
                Write-Host $infoObjectUnreachable
                $infoColl += $infoObjectUnreachable
            }
            Write-Host "`n$($pc) is unreachable`n" -ForegroundColor Red
        }
    }
    
    if ($Csv) {
        $ReportFilename = $ReportPath.TrimEnd('\')+"\_PC_Inventory_$((Get-Date).ToString('yyyy-MM-dd')).csv"
        Write-host "`nReport saved at $($ReportFilename)" -ForegroundColor Green
        $infoColl | Export-Csv -path $ReportFilename -NoTypeInformation -Encoding Unicode
    }

    $sw.Stop()
    Write-Warning "Running time CIM: $($sw.Elapsed)" 
}