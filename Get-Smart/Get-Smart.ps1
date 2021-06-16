#//Requires -RunAsAdministrator
Function Get-Smart
{
	<#
	.SYNOPSIS
		Get-Smart print to console S.M.A.R.T. data from all supported disks in specified computer
	.DESCRIPTION
		The function print data in Name: Value table
	.EXAMPLE
		PS C:\> Get-Smart localhost
	.INPUTS
		Inputs (if any)
	.OUTPUTS
		Output (if any)
	.NOTES
		Remote Computer should support WMI 
	.LINK
		http://en.wikipedia.org/wiki/S.M.A.R.T.
		http://blogs.msdn.com/b/clemensv/archive/2011/04/11/reading-atapi-smart-data-from-drives-using-net-temperature-anyone.aspx
		http://www.sans.org/windows-security/2010/02/11/powershell-byte-array-hex-convert
		http://forums.seagate.com/t5/Barracuda-XT-Barracuda-Barracuda/S-M-A-R-T-data-decode/m-p/51963
		http://www.users.on.net/~fzabkar/HDD/Seagate_SER_RRER_HEC.html
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
    	[string]$ComputerName
    )

	$sw = [Diagnostics.Stopwatch]::StartNew()
	
	# [int[]]$wanted = @(1,5,10,184,188,196,197,198,201,230) | sort-object
	[int[]]$wanted = @(1,5,7,9,10,12,184,187,188,193,195,196,197,198,201,230) | Sort-Object

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
	170 = 'Available Reserved Space'; #new
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
	232 = 'Available Reserved Space';
	230 = 'GMRHeadAmplitude';
	231 = 'DriveTemperature';
	233 = 'Media Wearout Indicator';
	240 = 'HeadFlyingHours';
	241 = 'TotalLBAsWritten';
	242 = 'TotalLBAsRead';
	249 = 'NAND Writes (1GiB)';
	250 = 'ReadErrorRetryRate';
	254 = 'FreeFallProtection';
	}


	$current = [ordered]@{}
	$wanted | ForEach-Object { $current.Add($_, $map.$_) }

    try
    {
        $session = New-CimSession -ComputerName $ComputerName -OperationTimeoutSec 5 -SessionOption (New-CimSessionOption -Protocol Dcom) -EA 0 # test DCOM or WSMan
        # Get remote data
        $OS = Get-CimInstance -CimSession $session -ClassName CIM_ComputerSystem
        $drives = Get-CimInstance -CimSession $session -ClassName Win32_DiskDrive -Filter "MediaType LIKE 'Fixed%'" -Property * ## $drives
        $drivers = Get-CimInstance -CimSession $session -Namespace root/WMI -ClassName MSStorageDriver_ATAPISmartData -Property * # | select-object *
        $predictions = Get-CimInstance -CimSession $session -Namespace root/WMI -ClassName MSStorageDriver_FailurePredictStatus -Property * ## $predictions
    
    }
    catch
    {
        Write-Error "Cannont create CIM session!"
        return
    }

    
    # Process data

    # $current = [hashtable]$current

    foreach ($drive in $drives)
    {
        $driver = $drivers | Where-Object { ($_.InstanceName).StartsWith($drive.PNPDeviceID, 1) }
        $prediction = $predictions | Where-Object { ($_.InstanceName).StartsWith($drive.PNPDeviceID, 1) }
        $serial = $drive.SerialNumber
		if ($serial)
		{ 
			$serial = $drive.SerialNumber.trim() 
		}
               
        $element = New-Object -typeName PSObject

        $element | Add-Member -MemberType NoteProperty -Name System -Value ($OS.Name + '.' + $OS.Domain)
        $element | Add-Member -MemberType NoteProperty -Name DeviceID -Value $drive.DeviceID
        $element | Add-Member -MemberType NoteProperty -Name FirmwareRevision -Value $drive.FirmwareRevision
        $element | Add-Member -MemberType NoteProperty -Name Interface -Value $drive.InterfaceType
        $element | Add-Member -MemberType NoteProperty -Name MediaType -Value $drive.MediaType        
        $element | Add-Member -MemberType NoteProperty -Name Model -Value $drive.Model
        $element | Add-Member -MemberType NoteProperty -Name SerialNumber -Value $serial
        #$element | add-member -MemberType NoteProperty -Name Prediction:: -Value ""
        if ($prediction.PredictFailure) {
            $element | Add-Member -MemberType NoteProperty -Name PredictFailure -Value $prediction.PredictFailure
            $element | Add-Member -MemberType NoteProperty -Name PredictReason -Value $prediction.Reason
        }
        $current.Keys | Sort-Object | ForEach-Object { $element | Add-Member -MemberType NoteProperty -Name $current.$_ -Value $null }


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
                    [char[]]$chars = ([convert]::ToString($byte, 2).PadLeft(8,'0')).ToCharArray()
                    [array]::Reverse($chars)
                    $chars | ForEach-Object { $sum += ([int]::Parse($_) * [math]::Pow(2,$k)); $k++ }
                }
                
                try { $element.($current.Item([object][int]$array[0])) = $sum }
                catch {}
            }
        }

        # final output
        Write-Output $element
    } 

	$sw.Stop()
	Write-Warning "Running time: $($sw.Elapsed)"
}
