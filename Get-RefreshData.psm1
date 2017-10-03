function Get-RefreshSNOW{
<#
.Synopsis
   Get server refresh info from CMDB
.DESCRIPTION
   Get server refresh info from the Service-Now CMDB
.EXAMPLE
   $creds = get-credential -Message "Please Enter Your company.Service-Now.Com Credentials"
   $RefreshResults = Get-RefreshSNOW -ComputerNames $list -credentials $creds
   $RefreshResults | OGV -Title New
        Then look in the log file for failures and run the names of the failures again like this:
        $RefreshResults += Get-RefreshSNOW -ComputerNames $list[-1..-2] -credentials $creds
        $RefreshResults | Export-Csv -Path 'C:\Users\user\OneDrive - company\Documents\REFRESH\rightsize\security.csv' -NoTypeInformation -Force
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   You have to use ARMclient.exe to run the perf commands against OMS and you have to download Invoke-Parallel.ps1 and save as a module.
   Install the ARMClient - choco install armclient
   Log into ARMClient - ARMclient login
   Download Invoke-Parallel.ps1 - https://github.com/RamblingCookieMonster/Invoke-Parallel
   Save as module - mkdir 'C:\Program Files\WindowsPowerShell\Modules\Invoke-Parallel'
                    copy-item .\Invoke-Parallel.ps1 'C:\Program Files\WindowsPowerShell\Modules\Invoke-Parallel\.\Invoke-Parallel.psm1'

   Take used HDD space, convert to int, add 10% growth, round the number and +1
   Disk 20% growth formula: 
   ([int[]](($r[1].FreeSpace -split ';') -replace '\(GB\)','') | % {$_ * 1.2})|%{[math]::Round($_) + 1}
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
[CmdletBinding()]

param(
    [Parameter(Mandatory=$true,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true)]
    [string[]]$ComputerNames,

    $Credentials = $(Get-Credential -Message "Please Enter Your company.Service-Now.Com Credentials"),

    [string]$ErrorLog = 'C:\Windows\Temp\RefreshSNOWerrors.txt'

)
BEGIN{

#region Create Service Now Credentials
    
    #$SNowUser = “$($Credentials.UserName)” 
    $SNowCreds = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $Credentials.UserName, $Credentials.Password
    #$getMachines="https://company.service-now.com/api/now/table/cmdb_ci_win_server?sysparm_query=nameIN" + [string]::Join(",", $ComputerNames)
    
#endregion
    
    Import-Module C:\git\Scripts\Developers\JuserLastname\MyModules\Invoke-Parallel
    
    Write-Host "You must belong to SQLDB_ReadOnly for SQL data" -ForegroundColor Green
    #ARMClient.exe login
}
PROCESS{
try{
 $ComputerNames | Invoke-Parallel -Throttle 15 -RunspaceTimeout 180 -Parameter $SNowCreds -LogFile $ErrorLog -ScriptBlock {


     $getMachines="https://company.service-now.com/api/now/table/cmdb_ci_win_server?sysparm_query=install_status!=24^GOTOname=$_" ##CHANGE HERE should be $_
     $Result = (Invoke-RestMethod -Uri $getMachines -Credential $parameter -Body $Body -ContentType "application/json" ).result  ##CHANGE replaced $parameter with $creds

#region
if(($Result[0] | select-object u_lifecycle_phase).u_lifecycle_phase -eq "pr"){
    [string] $Server= ”SQLProd”
    [string] $Database = “CMpr”
}else{
    [string] $Server= ”SQL1QA”
    [string] $Database = “CMqa”
}
[string] $SqlQuery= $(“SELECT DISTINCT p.SystemName0 as Hostname
		,OS.Caption0 as OperatingSystem
        ,OS.OSArchitecture0 as Architecture
		,HW.Manufacturer0 as Manufacturer
		,HW.Model0 as Model
		,SerialNumber = bios.SerialNumber0
		,InstallDate = convert(varchar, OS.InstallDate0, 1)
		,Procs= STUFF(( SELECT	'; ' + p.Name0 
				FROM	[$Database].[dbo].[v_GS_PROCESSOR] AS T1
				WHERE T1.SystemName0 = p.SystemName0	
				ORDER BY Name0
				FOR XML	PATH('')
				), 1, 1, '')
		,MaxCpuSpeed= STUFF (( SELECT '; ' + CAST(p.MaxClockSpeed0 AS varchar (20))
				FROM	[$Database].[dbo].[v_GS_PROCESSOR] AS T1
				WHERE T1.SystemName0 = p.SystemName0	
				ORDER BY Name0
				FOR XML	PATH('')
				), 1, 1, '')
		,Cores= STUFF (( SELECT '; ' + CAST(p.NumberOfCores0 AS varchar (20))
				FROM	[$Database].[dbo].[v_GS_PROCESSOR] AS T1
				WHERE T1.SystemName0 = p.SystemName0	
				ORDER BY Name0
				FOR XML	PATH('')
				), 1, 1, '')
		,LogicalProcs= STUFF (( SELECT '; ' + CAST(p.NumberOfLogicalProcessors0 AS varchar (20))
				FROM	[$Database].[dbo].[v_GS_PROCESSOR] AS T1
				WHERE T1.SystemName0 = p.SystemName0	
				ORDER BY Name0
				FOR XML	PATH('')
				), 1, 1, '')
		,Memory = Round(OS.TotalVisibleMemorySize0 /1024,2)+1
		,DriveLetters = STUFF(( SELECT	' ' + T1.DeviceID0
				FROM	[$Database].[dbo].[v_GS_LOGICAL_DISK] AS T1
				WHERE T1.SystemName0 = d.SystemName0
				ORDER BY d.DeviceID0
				FOR XML	PATH('')
				), 1, 1, '')
		,VolumeNames = STUFF(( SELECT	'; ' + T1.VolumeName0
				FROM	[$Database].[dbo].[v_GS_LOGICAL_DISK] AS T1
				WHERE T1.SystemName0 = d.SystemName0
				ORDER BY d.VolumeName0
				FOR XML	PATH('')
				), 1, 1, '')
		,DiskSize = STUFF(( SELECT    ';' + Cast(Round(T1.Size0/1024,2) as varchar) + '(GB)'
				FROM	[$Database].[dbo].[v_GS_LOGICAL_DISK] AS T1
				WHERE T1.SystemName0 = d.SystemName0
				ORDER BY d.Size0
				FOR XML	PATH('')
				), 1, 1, '')
		,FreeSpace = STUFF(( SELECT    ';' + Cast(Round(T1.FreeSpace0/1024,2) as varchar) + '(GB)'
				FROM	[$Database].[dbo].[v_GS_LOGICAL_DISK] AS T1
				WHERE T1.SystemName0 = d.SystemName0
				ORDER BY d.FreeSpace0
				FOR XML	PATH('')
				), 1, 1, '')
		--,CAST (ROUND((Cast(d.FreeSpace0 as numeric(10,2)) / cast(d.Size0 as numeric(10,2))) * 100,0)as int) as '% Free'
  FROM 
  [$Database].[dbo].[v_GS_PROCESSOR] AS p 
  RIGHT JOIN [$Database].[dbo].[v_R_System] AS sys ON p.ResourceID=sys.ResourceID
  RIGHT JOIN [$Database].[dbo].[v_GS_OPERATING_SYSTEM] as OS ON OS.ResourceID=sys.ResourceID
  RIGHT JOIN [$Database].[dbo].[v_GS_LOGICAL_DISK] as d ON d.ResourceID=sys.ResourceID
  RIGHT JOIN [$Database].[dbo].[v_GS_COMPUTER_SYSTEM] as HW ON HW.resourceID=sys.ResourceID
  RIGHT JOIN [$Database].[dbo].[v_GS_PC_BIOS] as bios on bios.ResourceID=sys.ResourceID
  WHERE sys.Name0 = '$_'
	AND (d.DriveType0 = '3')”)
$Command = New-Object System.Data.SQLClient.SQLCommand
$Command.Connection = $Connection
$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
$SqlConnection.ConnectionString = “Server = $Server; Database = $Database;Integrated Security=true;Initial Catalog=master”
$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
$SqlCmd.CommandText = $SqlQuery
$SqlCmd.Connection = $SqlConnection
$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
$SqlAdapter.SelectCommand = $SqlCmd
$DataSet = New-Object System.Data.DataSet
$SqlAdapter.Fill($DataSet) | Out-Null
$SqlResults=$DataSet.Tables
#endregion

#region Get disk used Plus 10% for growth but only if NOT C:\ or if the 'rightsize' is larger than the original disk. No giving away storage!!
$d=([int[]](($SqlResults.Disksize -split ';') -replace '\(GB\)',''))
$f=([int[]](($SqlResults.freespace -split ';') -replace '\(GB\)',''))
$count=(($SqlResults.Disksize -split ';').count)
$DiskGrowth=for($i = 0; $i -lt $count ; $i++){
    if($i -eq 0){ #If disk0 and is less than or equal to 70 rightsize to 70
        70
    }else{ #right sizing non Disk0 disks
        $d2=$d[$i]
        $f2=$f[$i]
        #right size disk if 
        if(($($d2) - $($f2))*1.1 -gt $d2){
            $d2
        }else{
            $rightSizedDisk=($($d2) - $($f2))*1.1
            if([Math]::Round($rightSizedDisk) -lt 10 ){10
            }else{
            [Math]::Round($rightSizedDisk)
            }
      }
   }
}
#endregion

#region Total Storage Savings in GB
$dSize=([int[]](($SqlResults.Disksize -split ';') -replace '\(GB\)',''))
#$rSize=[int[]]$SqlResults.diskrightsize

#$count=(($SqlResults.Disksize -split ';').count)
$StorageSavings=for($i = 0; $i -lt $dSize.Count ; $i++){
    if($i -eq 0){ 0
    }else{
       $($dSize[$i]) - $($DiskGrowth[$i])
       }
}
$TotalStorageSavings=0
$StorageSavings | % {$TotalStorageSavings += $_}
#endregion

#region Server Size
$totalCores = 0
[int[]]($SqlResults.Cores -split ';').trim() |
    ForEach-Object { 
        $totalCores += $_ }
$serverSize=if($totalCores -le 32 -and $SqlResults.memory -le 24 ){'Small'}
    elseif([int]$totalCores -le 64 -and $SqlResults.memory -le 512){'Large'}
    else{'Custom'}
#endregion

#region Server Status Switch    
     $status=switch (($Result[0] | Select-Object install_status).install_status)
     {
        0{'UNKNOWN';break}
        1{'BUILD';break}
        10{'DECOMMPENDING';break}
        101{'Deployed';break}
        13{'LEGAL HOLD';break}
        15{'DECOMMISSIONED';break}
        20{'VENDOR MANAGED';break}
        24{'INVALID';break}
        30{'APP CONFIG';break}
        5{'DEPLOYED';break}
     }
#endregion
     
     $hash = [ordered]@{
                      "Name"=($Result[0] | select-object name).name
                      "Domain"=($Result[0] | select-object dns_domain).dns_domain
                      "OS"=$SqlResults.OperatingSystem
                      "Architecture"=$SqlResults.Architecture
                      "Manufacturer"=if(($manufacturer=$Result[0] | select-object manufacturer).manufacturer){
                                   $manufacturerLink = $manufacturer.manufacturer.link
                                   $manufacturerResult=Invoke-RestMethod -Uri $manufacturerLink -Credential $parameter -Body $Body -ContentType "application/json"
                                   $manufactureName=$manufacturerResult.result.name
                                   if($manufactureName){$manufactureName
                                   }else{
                                     $SqlResults.Manufacturer
                                   }
                                                                    }else{}        #manufacturer
                      "Model"=if(($Result[0] | select-object model_number).model_number){($Result[0] | select-object model_number).model_number
                              }else{
                                $SqlResults.Model 
                              }
                      "DR Tier"=($Result[0] | select-object u_dr_tier).u_dr_tier
                      "CMDB_SN"=if(($Result[0] | select-object serial_number).serial_number){($Result[0] | select-object serial_number).serial_number
                                }else{
                                    "NA"
                                }
                      "SQL_SN"=$SqlResults.serialnumber
                      "Manufacture Date"=if(($Result[0] | select-object serial_number).serial_number){ #Grabs SN from CMDB then hits up dell for warranty expirey and if not a Dell states so
                                              $SN=($Result[0] | select-object serial_number).serial_number
                                              if($manufactureName -like "*Dell*"){
                                                $warrantyUri="http://pcf-server-info.apps-zb.company.com:80/warranty"
                                                $vendor='dell'
                                                $json =  "{`"servicetag`": `"$($SN)`", `"vendor`": `"$($vendor)`"}"
                                                $warrantyResults=Invoke-WebRequest -Uri $warrantyUri -Body $json -ContentType "application/json" -Method Post
                                                    if($warrantyResults -match '"error": "That does not look like it is a valid serial number"'){
                                                        "Not a Dell"
                                                    }else{
                                                        [regex]$regex='(?<=StartDate=)\d{4}(-\d{2}){2}'
                                                        (($warrantyResults | ConvertFrom-Json).AssetEntitlementData)[-1] -match $regex | Out-Null
                                                        $Matches[0] | Out-String
                                                    }
                                                }
                                                if($manufactureName -like "*HP*"){
                                                    $lookup = [Management.Automation.PSObject]@{
                                                                             'countryCode' = "US"
                                                                             'productNo' = "null"
                                                                             'serialNo' = $SN
                                                                                                 }
                                                    $hpUrl = "https://hpscm-pro.glb.itcs.hp.com/mobileweb/hpsupport.asmx/GetEntitlementDetails"            
                                                    $Query = $((Invoke-RestMethod -Method Post -ContentType "application/json" -Uri $hpUrl -Body ($lookup | ConvertTo-Json)).d | ConvertFrom-Json)
                                                    $HPResults = $Query | Where-Object {$_.deliverables -like '*Onsite Support*'}
                                                    $hpManufactureDate = $HPResults.startDate
                                                    $hpWarrantyEndDate = $HPResults.EndDate
                                                    $hpManufactureDate |Out-String
                                                }
                                               
                                               }else{
                                                     "No SN"
                                                }
                      "Warranty Expiration"=if(($Result[0] | select-object serial_number).serial_number){ #Grabs SN from CMDB then hits up dell for warranty expirey and if not a Dell states so
                                                $SN=($Result[0] | select-object serial_number).serial_number
                                                if($manufactureName -like "*Dell*"){
                                                    $warrantyUri="http://internalserver.apps-zb.company.com:80/warranty"
                                                   # $SN=($Result[0] | select-object serial_number).serial_number
                                                    $vendor='dell'
                                                    $json =  "{`"servicetag`": `"$($SN)`", `"vendor`": `"$($vendor)`"}"
                                                    $warrantyResults=Invoke-WebRequest -Uri $warrantyUri -Body $json -ContentType "application/json" -Method Post
                                                        if($warrantyResults -match '"error": "That does not look like it is a valid serial number"'){
                                                            "Not a Dell"
                                                        }else{
                                                            [regex]$regex='(?<=EndDate=)\d{4}(-\d{2}){2}'
                                                            (($warrantyResults | ConvertFrom-Json).AssetEntitlementData)[0] -match $regex | Out-Null
                                                            $Matches[0] |Out-String
                                                        }
                                                }if($manufactureName -like "*HP*"){
                                                    $hpWarrantyEndDate | Out-String
                                                    }
                                                }else{
                                                     "No SN"
                                                }

                      "Location"=if(($Result[0] | select-object location).location){
                                    $location=($Result[0] | select-object location).location.link
                                    $locationResult=Invoke-RestMethod -Uri $location -Credential $parameter -Body $Body -ContentType "application/json"
                                    $locationResult.result.name
                                 }else{}
                      "Grid"=($Result[0] | select-object u_location_detail).u_location_detail
                      "Role"=($Result[0] | select-object u_patch_server_role).u_patch_server_role
                      "LifeCyclye" = ($Result[0] | select-object u_lifecycle_phase).u_lifecycle_phase
                      "Status"= $status
                      "Description"= ($Result[0] | select-object short_description).short_description
                       "Owned By"= if(($user=$Result[0] | select-object owned_by).owned_by){
                                   $userLink = $user.owned_by.link
                                   $userResult=Invoke-RestMethod -Uri $userLink -Credential $parameter -Body $Body -ContentType "application/json"
                                   $userResult.result.email
                                 }else{}
                     "Managed By"=if(($user=$Result[0] | select-object managed_by).managed_by){
                                   $managedByLink = $user.managed_by.link
                                   $userResult=Invoke-RestMethod -Uri $managedByLink -Credential $parameter -Body $Body -ContentType "application/json"
                                   $userResult.result.email
                                 }else{}
                     "SME"       = if(($user=$Result[0] | select-object assigned_to).assigned_to){
                                   $smeLink = $user.assigned_to.link
                                   $userResult=Invoke-RestMethod -Uri $smeLink -Credential $parameter -Body $Body -ContentType "application/json"
                                   $userResult.result.email
                                 }else{}
                     "CPU"    = $SqlResults.procs
                     "MaxCpuSpeed" = $SqlResults.MaxCpuSpeed
                     "CurrentCpuSpeed"=$SqlResulhts.CurrentCpuSpeed
                     "Cores"=$SqlResults.Cores
                     "LogicalProcs"=$SqlResults.LogicalProcs
                     "Memory"=$SqlResults.memory
                     "DriveLetters"=$SqlResults.DriveLetters
                     "VolumeNames"=$SqlResults.VolumeNames
                     "DiskSize"=$SqlResults.Disksize
                     "FreeSpace"=$SqlResults.freespace
                     "DiskRightSize"=$DiskGrowth | Out-String
                     "PotentialStoragSavings"=$TotalStorageSavings
                     "Size"=$serverSize
                     "cpuMax7DaysPercent"=0
                     "ramMax7DaysGB"=0
                     "Total Cores/Total vCPUS"=""
                     "Number of Virtual Sockets"=""
                     "Number of Cores Per Socket"=""
                     "Memory(GB)"=""
                     "VM HARDDISKS"=""
                     "OPERATING SYSTEM"=""
                     "ESXI HOST LOCATION"="" 
                     }
                         
     New-Object -TypeName psobject -Property $hash
    }
 }catch{
    
    Write-Warning "$ComputerName`: $($Error[0])"

 }
 }
 END{
    Write-Verbose "Logs written to $ErrorLog" -Verbose
 }

}

function Get-GraphiteStats{
<#
.Synopsis
   Pulls CPU and MEM perf info from http://grafana.io.company.com
.EXAMPLE
   $grafanaResults = Get-GraphiteStats -computerNames 'comp1' -Verbose
   $grafanaResults | OGV
.NOTES
   Cannot get this to work with Invoke-Parallel which is needed. The above example takes far too long to run at 
   TotalSeconds      : 76.0014262
#>
[CmdletBinding()]
param(
    $days = 7,
    [string[]]$computerNames
)
Begin{
    $startUrl = 'http://graphite.company.com/render/?target=collectd.telegraf.'
    $memSpec = '.Memory.win_mem.Committed_Bytes'
    $cpuSpec = '._Total.Processor.win_cpu.Percent_Processor_Time'
    $lanSpec = '.vmxnet3_Ethernet_Adapter.Network_Interface.win_perf_counters.Bytes_Total_persec'
    $endUrl = '&from=-' + $days + 'd' + '&format=json'
    
}
Process{
foreach($computerName in $computerNames){
    #Ensure all server names are capitalized
    $computerName = $computerName.toupper()
    #region Get max cpu
    $cpuUrl = $startUrl + $computerName + $cpuSpec + $endUrl
    $queryCpu = Invoke-WebRequest -Uri $cpuUrl  #-UseBasicParsing
    $dataPointsCpu = ($queryCpu.Content -split ',' | select-string '\[' |
        Where-Object {($psitem -notlike "*null*") -and ($psitem -notlike '*target*')})`
        -replace '\[',''
    $highestCpu = $dataPointsCpu |
        Select-Object @{n='cpuNumber';e={[int]$psitem}} |
        Sort-Object cpuNumber -Descending
    #endregion
    
    #region Get max RAM
    $memUrl = $startUrl + $computerName + $memSpec + $endUrl
    $queryMem = Invoke-WebRequest -Uri $memUrl #-UseBasicParsing
    $dataPointsMem = ((($queryMem.Content -split ',' | select-string '\[' |
        Where-Object {($psitem -notlike "*null*") -and ($psitem -notlike '*target*')`
        -and ($psitem -notlike ' "*datapoints": *')})`
        -split '\[' ) | select-string '\d') -replace '\.0',''
    $highestMem = ($dataPointsMem | % {$psitem / 1024 / 1024 / 1024} | sort -Descending)
    #endregion
    
    $hash = [ordered]@{
        "Server"=$computerName
        "cpuMax7DaysPercent"=$highestCpu.cpuNumber[0]
        "ramMax7DaysGB"=[math]::Round($highestMem[0])
       }
    
    New-Object -TypeName psobject -Property $hash
    }#End Invoke-Parallel
}
end{}
}

function Add-OMStoSNOWdata{
param(
$RefreshResults=$RefreshResults,
$OMSdata = $OMSdata
)

$RefreshResults | where {($_.cpuMax7DaysPercent -eq 0) -or ($_.cpuMax7DaysPercent -eq $null)} | Invoke-Parallel -ImportVariables -Throttle 20 -RunspaceTimeout 60 {
    $name = $null
    $name = $_.name
    if ($name -in ($OMSdata.server)){
        $_.cpuMax7DaysPercent = $($OMSdata | where {$_.server -eq $name} | select -ExpandProperty cpuMax7DaysPercent)
    }
}

$RefreshResults | where {($_.ramMax7DaysGB -eq 0) -or ($_.ramMax7DaysGB -eq $null)} | Invoke-Parallel -ImportVariables -Throttle 20 -RunspaceTimeout 60 {
    $name = $null
    $name = $_.name
    if ($name -in ($OMSdata.server)){
        $_.ramMax7DaysGB = $($OMSdata | where {$_.server -eq $name} | select -ExpandProperty ramMax7DaysGB)
    }
}
}


# Get-RefreshOMSv2 deprecated in lieu of 
function Get-RefreshOMSv2{
<#
.Synopsis
   Pulls 7 day CPU and RAM info from WIndows machines in OMS
.DESCRIPTION
   Long description
.EXAMPLE
   $OMSdata = Get-RefreshOMSv2 -ComputerNames $list[0..4] -Domain prod -Verbose
#>
[CmdletBinding()]
param(
[Parameter(Mandatory=$true)]
[string[]]$ComputerNames,

[Parameter(Mandatory=$true)]
[ValidateSet("QA", "PROD")]
$Domain
    
)
 Begin
    {
    $WorkspaceName = switch($Domain){
        'PROD' { 'key1' }
        'QA' { 'key2' }
    }
   
    }
    Process
    {
    

foreach($Computer in $ComputerNames)  {
#Login-AzureRmAccount 

#region CPU average #################################################
$APIReturnLimit = 5000
#$WorkspaceName = "key1"
$OMSWorkspace = Get-AzureRmOperationalInsightsWorkspace | Where-Object {$_.Name -eq $WorkspaceName }
$OMSWorkspaceName = $OMSWorkspace.Name
#$OMSWorkspaceResourceGroup = "OI-Default-East-US"
$OMSWorkspaceResourceGroup = $OMSWorkspace.ResourceGroupName
$SearchQuery = "Type=Perf Computer=*$Computer* (ObjectName=Processor OR ObjectName=Memory) (CounterName=`"% Processor Time`" OR CounterName=`"% Committed Bytes In Use`") | measure max(CounterValue) by Computer,CounterName"
$Now = [DateTime]::UtcNow
$StartDate = $Now.AddHours(-168)
$EndDate = $Now.AddHours(-1)
$arrResults = New-Object System.Collections.ArrayList

$FirstCall = Get-AzureRmOperationalInsightsSearchResults -WorkspaceName $OMSWorkspaceName -ResourceGroupName $OMSWorkspaceResourceGroup -Query $SearchQuery -Start $StartDate -End $Now -Top $APIReturnLimit
# Split and extract request Id
$FirstCallReqIdParts = $FirstCall.Id.Split("/")
$FirstCallReqId = $FirstCallReqIdParts[$FirstCallReqIdParts.Count -1]

while($FirstCall.Metadata.Status -eq "Pending") {
  $FirstCall = Get-AzureRmOperationalInsightsSearchResults -WorkspaceName $OMSWorkspaceName -ResourceGroupName $OMSWorkspaceResourceGroup -Id $FirstCallReqId -Top $APIReturnLimit
}

#Processing results returned from the first API call
Foreach ($item in $FirstCall.value)
{
  $objResult = ConvertFrom-JSON $item
  $objResult.psobject.Members.Remove('__metadata')
  [void]$arrResults.Add($objResult)
}


If ($ResultsetSize -gt $APIReturnLimit)
{
 
  $i = 0
  $AllDone = $false
  Do {
    $i++
    $iSkip = $APIReturnLimit * $i
   
    $SubsequentQuery = "$SearchQuery | Skip $iSkip | Top $APIReturnLimit"
   
    $SubsequentCall = Get-AzureRmOperationalInsightsSearchResults -WorkspaceName $OMSWorkspaceName -ResourceGroupName $OMSWorkspaceResourceGroup -Query $SubsequentQuery -Start $StartDate -End $EndDate -Top $APIReturnLimit
    # Split and extract request Id
    $SubsequentCallReqIdParts = $SubsequentCall.Id.Split("/")
    $SubsequentCallReqId = $SubsequentCallReqIdParts[$SubsequentCallReqIdParts.Count -1]
    while($SubsequentCall.Metadata.Status -eq "Pending") {
      $SubsequentCall = Get-AzureRmOperationalInsightsSearchResults -WorkspaceName $OMSWorkspaceName -ResourceGroupName $OMSWorkspaceResourceGroup -Id $SubsequentCallReqId -Top $APIReturnLimit
    }

   $SubsequentCallResultsetSize = $SubsequentCall.value.count
    If ($SubsequentCallResultsetSize -gt 0)
    {
     
      Foreach ($item in $SubsequentCall.value)
      {
        $objResult = ConvertFrom-JSON $item
        $objResult.psobject.Members.Remove('__metadata')
        [void]$arrResults.Add($objResult)
      }
    } else {
     
      $AllDone = $true
    }

  } Until ($AllDone)
}
$MaxCPU = $null
$MaxRAM = $null
$MaxCPU = $arrResults[0].AggregatedValue
$MaxRAM = $arrResults[1].AggregatedValue


#endregion
Write-Host "$Computer"
$hash = [ordered]@{
    
    "Server"=$Computer 
    "cpuMax7Days"=[math]::Round($MaxCPU,2)
    "ramMax7Days"=[math]::Round($MaxRAM,2)
    
                  }

New-Object -TypeName psobject -Property $hash

    }
    }
    End
    {
    Write-Host "Are you having issues? Did you log into Azure? Login-AzureRmAccount" -ForegroundColor Yellow
    }



}