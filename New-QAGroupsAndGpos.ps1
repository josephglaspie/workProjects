###############################################################################################
<#
 .Synopsis
    Creates OU, Blue/Green Restricted LA/RDP groups, and GPO.
 .DESCRIPTION
    Creates OU, Blue/Green Restricted LA/RDP groups, and GPO. Must be run from GreenDomain.NET DomainController and requires domain.qadomain.com DA creds. 
 .EXAMPLE
    Create-RestictedGroupsAndGPOs -ApplicationName 1Test -verbose
 .EXAMPLE
    Another example of how to use this cmdlet
 #>
function Create-RestictedGroupsAndGPOs{
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,
          ValueFromPipelineByPropertyName=$true)]
    $ApplicationName,

    $AmerCreds= $(Get-Credential -Message "Your domain.qadomain.com DA creds")
)

$BlueDomainController='DC04.domain.qadomain.com'
#if($AmerCreds){}else{$AmerCreds=Get-Credential -Message "Your domain.qadomain.com DA creds"}
$OU=New-ADOrganizationalUnit -Path "OU=servers,OU=tier_1,DC=domain,DC=qadomain,DC=com" -Server $BlueDomainController -Name $ApplicationName -Credential $AmerCreds -PassThru
$OU=($OU | Select DistinguishedName).DistinguishedName
$BlueGroupPath='OU=PRIV,OU=Groups,OU=TIER_1,DC=domain,DC=qadomain,DC=com'
$GreenGroupPath='OU=PRIV,OU=Groups,OU=Tier_1,OU=QAHOMEDEPOT,DC=QATHDRETAIL,DC=NET'

[regex]$reg='(?<=\bOU=)\w+\b'
$OUs = $OU -split ','
$names=$OUs | foreach {if($_ -match $reg){$matches.Values}}
[array]::Reverse($names)

    $length = $names.Count / $OU.Count
    $i = 0
    $result=foreach ($line in $names){
    $lineout += '-'
    [string]$lineout += $line
    $i++
       if ($i -eq $length){
        write-output $lineout
        $i=0
        $lineout = ""
        }
}
Write-Verbose "Taking target location out of OU path for group and GPO naming $result"
$results=$result | % { $_ -replace "-Tier_1","Tier1" }

#Create New LA and RDP BLUE groups

$NewGroups = @() 
foreach($r in $results) {
    $LA = 'T1_CMP_'+$r+'_LA'
    $RDP = 'T1_CMP_'+$r+'_RDP' 
    try{
        $NewLABlue= New-ADGroup -GroupScope DomainLocal -GroupCategory Security -Path $BlueGroupPath -Name $LA -PassThru -Server $BlueDomainController -Credential $AmerCreds
    }catch{
        Write-Warning "$LA : $($Error[0].exception.message)"
    }
    try{
        $NewRDPBlue = New-ADGroup -GroupScope DomainLocal -GroupCategory Security -Path $BlueGroupPath -Name $RDP -PassThru -Server $BlueDomainController -Credential $AmerCreds
    }catch{
        Write-Warning "$RDP : $($Error[0].exception.message)"
    }
    $NewGroups += $LA
    $NewGroups += $RDP
    Write-Verbose "Creating Blue Groups`r`n$NewLABlue `r`n$NewRDPBlue"
}#End foreach BLUE groups

$RetailAccounts = $NewGroups | % {"$_" -replace "T1_CMP_Tier1","T1_CMP_Domain-Tier1"}
    try{
        $NewLAGreen= New-ADGroup -GroupScope DomainLocal -GroupCategory Security -Path $GreenGroupPath -Name $RetailAccounts[0] -PassThru
    }catch{
        Write-Warning "$($R): $($Error[0].exception.message)"
    }
    try{
        $NewRDPGreen = New-ADGroup -GroupScope DomainLocal -GroupCategory Security -Path $GreenGroupPath -Name $RetailAccounts[1] -PassThru
    }catch{
        Write-Warning "$($RetailAccounts[1]) : $($Error[0].exception.message)"
    }
#endregion
Write-Verbose "Creating Green Groups`r`n$NewLAGreen `r`n$NewRDPGreen"

$TemplateGPOName='T1_WSE_CMP_Tier1-Servers-TEMPLATE-Restricted-Groups-Restrictive'
$NewGPOName= "T1_WSE_CMP_$results-Restricted-Groups-Restrictive"
$newGPO = Copy-GPO $TemplateGPOName -TargetName $NewGPOName -SourceDomain domain.qadomain.com -TargetDomain domain.qadomain.com
sleep 10
Write-Verbose "New GPO ID $($newGPO.id)"

$Path="\\domain.qadomain.com\SYSVOL\domain.qadomain.com\Policies\{$($newGPO.id)}\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
$NewPath="\\domain.qadomain.com\SYSVOL\domain.qadomain.com\Policies\{$($newGPO.id)}\Machine\microsoft\windows nt\SecEdit\GptTmplTEST.inf"


#region This regex finds the lines of the GptTmpl.inf with LA and RDP SIDs in it and replaces the template users with the new group SIDs.
[regex]$reg='.(\w*-){4}\w+\s=\s.\w-(\d*-){6}\d*'
$Data = Get-Content $Path

$newData = For($i=0;$i-lt $Data.count;$i++){
    if($data[$i] -match 'S-1-5-32-544'){
        $data[$i] -replace $reg,"*S-1-5-32-544__Members = *$($NewLABlue.sid.Value),*$($NewLAGreen.sid.Value)"
        }
    else{$data[$i]}
}
$newData | out-file $NewPath -Force
sleep 2
$data=Get-Content $NewPath
$newData = For($i=0;$i-lt $Data.count;$i++){   
    if ($Data[$i] -match 'S-1-5-32-555'){
        $Data[$i] -replace $reg,"*S-1-5-32-555__Members = *$($NewRDPBlue.sid.Value),*$($NewRDPGreen.sid.Value)"
        }
     else{$data[$i]}
}
$newData | out-file $NewPath -Force

sleep 5

#overwrite old .inf and remove temp inf
try{ cp $NewPath $Path -Force
     rm $NewPath
}catch{
     Write-Warning "$($error[0].Exception.Message)"}
#endregion GptTmpl.inf editing
}
Write-Host "Linking the GPO to $OU can be accomplished once the DoubleHop issue is addressed!!" -ForegroundColor Yellow
<# Linking the GPO can be accomplished once the DoubleHop issue is addressed
$SB = {
    $dc=Get-ADDomainController -Discover -DomainName "domain.qadomain.com" | select -ExpandProperty hostname
    New-GPLink -Server $BlueDomainController -Guid $($newGPO.id) -Target $OU -LinkEnabled Yes -Domain domain.qadomain.com
}
Invoke-Command -Session $ses -ScriptBlock $SB
#>