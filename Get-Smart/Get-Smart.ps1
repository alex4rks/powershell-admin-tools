<#
Query_Smart_Multi
Requires RSAT, PowerShell Remoting.
http://en.wikipedia.org/wiki/S.M.A.R.T.
http://blogs.msdn.com/b/clemensv/archive/2011/04/11/reading-atapi-smart-data-from-drives-using-net-temperature-anyone.aspx
http://www.sans.org/windows-security/2010/02/11/powershell-byte-array-hex-convert
http://forums.seagate.com/t5/Barracuda-XT-Barracuda-Barracuda/S-M-A-R-T-data-decode/m-p/51963
http://www.users.on.net/~fzabkar/HDD/Seagate_SER_RRER_HEC.html
Properties that should indicate impending failure: 1,5,10,184,188,196,197,198,201,230

Adam Sailer
2014.06.04
#>
Function Get-Smart
{
Param(    
    [Parameter(Mandatory=$true)]
    [string]$Pattern
    )

$properties = @('Name', 'OperatingSystem')
[int[]]$wanted = @(1,5,10,184,188,196,197,198,201,230) | sort-object
[int[]]$wanted = @(1,5,7,9,10,12,184,187,188,193,195,196,197,198,201,230) | sort-object


$map = @{
	1 = 'ReadErrorRate';
	2 = 'ThroughputPerformance';
	3 = 'SpinUpTime';
	4 = 'StartStopCount';
	5 = 'ReallocatedSectorsCount';
	6 = 'ReadChannelMargin';
	7 = 'SeekErrorRate';
	8 = 'SeekTimePerformance';
	9 = 'PowerOnHoursPOH';
	10 = 'SpinRetryCount';
	11 = 'CalibrationRetryCount';
	12 = 'PowerCycleCount';
	13 = 'SoftReadErrorRate';
	183 = 'SATADownshiftErrorCount';
	184 = 'EndtoEnderror';
	185 = 'HeadStability';
	186 = 'InducedOpVibrationDetection';
	187 = 'ReportedUncorrectableErrors';
	188 = 'CommandTimeout';
	189 = 'HighFlyWrites';
	190 = 'TemperatureDifferencefrom100';
	191 = 'GSenseErrorRate';
	192 = 'PoweroffRetractCount';
	193 = 'LoadCycleCount';
	194 = 'Temperature';
	195 = 'HardwareECCRecovered';
	196 = 'ReallocationEventCount';
	197 = 'CurrentPendingSectorCount';
	198 = 'UncorrectableSectorCount';
	199 = 'UltraDMACRCErrorCount';
	200 = 'MultiZoneErrorRate';
	201 = 'OffTrackSoftReadErrorRate';
	202 = 'DataAddressMarkerrors';
	203 = 'RunOutCancel';
	204 = 'SoftECCCorrection';
	205 = 'ThermalAsperityRateTAR';
	206 = 'FlyingHeight';
	207 = 'SpinHighCurrent';
	208 = 'SpinBuzz';
	209 = 'OfflineSeekPerformance';
	211 = 'VibrationDuringWrite';
	212 = 'ShockDuringWrite';
	220 = 'DiskShift';
	221 = 'GSenseErrorRateAlt';
	222 = 'LoadedHours';
	223 = 'LoadUnloadRetryCount';
	224 = 'LoadFriction';
	225 = 'LoadUnloadCycleCount';
	226 = 'LoadInTime';
	227 = 'TorqueAmplificationCount';
	228 = 'PowerOffRetractCycle';
	230 = 'GMRHeadAmplitude';
	231 = 'DriveTemperature';
	240 = 'HeadFlyingHours';
	241 = 'TotalLBAsWritten';
	242 = 'TotalLBAsRead';
	250 = 'ReadErrorRetryRate';
	254 = 'FreeFallProtection';
}


$current = [ordered]@{}
$wanted | % { $item = $_; $current.Add($_, $map.$_) }


Function Process
{
    Param(    
        [Parameter(Mandatory=$true)]
        [hashtable]$map
        )

    $proc = gwmi win32_Processor
    $os = gwmi win32_OperatingSystem
    $cs = gwmi win32_ComputerSystem

    $drives = gwmi win32_diskDrive | select-object *; ## $drives
    $drivers = gwmi MSStorageDriver_ATAPISmartData -ns root\wmi | select-object *
    $predictions = gwmi MSStorageDriver_FailurePredictStatus -ns root\wmi | select-object *; ## $predictions


    $out = @()

    foreach ($drive in $drives)
    {
        $driver = $drivers | ? { ($_.InstanceName).StartsWith($drive.PNPDeviceID,1) }
        $prediction = $predictions | ? { ($_.InstanceName).StartsWith($drive.PNPDeviceID,1) }
        $serial = $drive.SerialNumber; if ($serial) { $serial = $drive.SerialNumber.trim() }
        
        
        $element = new-object -typeName PSObject

        $element | add-member -MemberType NoteProperty -Name System -Value $env:COMPUTERNAME
        $element | add-member -MemberType NoteProperty -Name SystemSerial -Value (gwmi win32_Bios).SerialNumber
        $element | add-member -MemberType NoteProperty -Name SystemAsset -Value (gwmi win32_SystemEnclosure).SMBIOSAssetTag
        $element | add-member -MemberType NoteProperty -Name SystemModel -Value $cs.Model
        $element | add-member -MemberType NoteProperty -Name OperatingSystem -Value $os.Caption
        $element | add-member -MemberType NoteProperty -Name ServicePack -Value $os.CSDVersion
        $element | add-member -MemberType NoteProperty -Name OperatingSystemVersion -Value $os.Version
        $element | add-member -MemberType NoteProperty -Name Architecture -Value $(if (($proc.AddressWidth -eq 64) -and ($proc.DataWidth -eq 64)) { 'x64' } else { 'x86' })
        $element | add-member -MemberType NoteProperty -Name CurrentUser -Value $cs.UserName


        $element | add-member -MemberType NoteProperty -Name DeviceID -Value $drive.DeviceID
        $element | add-member -MemberType NoteProperty -Name FirmwareRevision -Value $drive.FirmwareRevision
        $element | add-member -MemberType NoteProperty -Name Interface -Value $drive.InterfaceType
        $element | add-member -MemberType NoteProperty -Name MediaType -Value $drive.MediaType        
        $element | add-member -MemberType NoteProperty -Name Model -Value $drive.Model
        $element | add-member -MemberType NoteProperty -Name SerialNumber -Value $serial
        $element | add-member -MemberType NoteProperty -Name PredictFailure -Value $prediction.PredictFailure
        $element | add-member -MemberType NoteProperty -Name PredictReason -Value $prediction.Reason

        $map.Keys | sort-object | % { $element | add-member -MemberType NoteProperty -Name $map.$_ -Value $null }


        [byte[]]$smart = @([byte[]]$driver.VendorSpecific)

             
        $i = 2
        while ($i -lt $smart.Count)
        {
            [byte[]]$array = $smart[$i..($i + 11)]; $i += 12


            if ($array[0])
            {
                [int64]$sum = 0; $k = 0

                foreach ($byte in [byte[]]$array[5..10])
                {
                    [char[]]$chars = ([convert]::tostring($byte, 2).padleft(8,'0')).ToCharArray(); [array]::Reverse($chars)

                    $chars | % { $sum += ([int]::Parse($_) * [math]::Pow(2,$k)); $k++ }
                }

                try { $element.($map.Get_Item([int]$array[0])) = $sum }
                catch {}
            }
        }

        write-output $element
    }    
}


# $cn = @(get-adcomputer -Filter 'Name -like $pattern' -Properties $properties | ? { $_.OperatingSystem -match '(windows)(?!.*server.*)' } | % { $_.Name } | sort-object); $cn; $cn.Count

Invoke-Command -cn $pattern -scriptblock ${Function:Process} -argumentList $current
}