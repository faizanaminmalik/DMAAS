﻿# process commandline arguments
# ./protectPhysical.ps1 -physFQDN 192.168.1.133 -inclusions '/C/Temp','/E/New Folder/','/E/Path2' -startTime 23:00 -timeZone 'Asia/Calcutta'
[CmdletBinding()]
param (
    [Parameter()][string]$username = 'DMaaS',
    [Parameter(Mandatory = $True)][string]$apiKey,  # apiKey
    [Parameter(Mandatory = $True)][string]$regionId,  # DMaaS SQL Source Region Id
    [Parameter(Mandatory = $True)][string]$policyName,  # protection policy
    [Parameter()][array]$physFQDN ='',  # physical Source FQDN
    [Parameter()][string]$physList = '',  # optional textfile of Physical Servers to protect
    [Parameter()][string]$priority = 'kMedium',  # protection instance priority (default is kMedium)
    [Parameter()][string]$qosPolicy = 'kBackupSSD',  # QoS policy optimizes throughput performance (default is kBackupSSD)
    [Parameter()][bool]$abort = $false, # abort during blackout periods (default is false)
    #[Parameter()][string]$environment = 'kPhysical',  # environment type (kPhysical, kVMware, kAWS, kO365, kNetapp, kSQL, kOracle) (default is kPhysical)
    [Parameter()][string]$volumes = '',  # which volumes to backup
    [Parameter()][bool]$autoProtected = $true,  # whether Physical objects are autoProtected (default is true)
    [Parameter()][bool]$skipNested = $false,  # whether to skip backing up nested volumes (default is false)
    [Parameter()][bool]$usePathLevel = $true,  # whether to use Path Level Skip Nested Volume Setting (default is true)
    [Parameter()][bool]$nasSymlink = $false,  # whether to follow NAS Symlink targets (default is false)
    [Parameter()][bool]$quiesce = $true,  # optional whether to quiesce the backups (Default is true)
    [Parameter()][bool]$contOnFail = $true,  # optional whether to continue on quiesce failure (Default is true)
    [Parameter()][bool]$sourceSideDedup = $false,  # optional whether to perform Source Side Deduplication (Default is false)
    [Parameter()][bool]$index = $false,  # optional whether objects are indexed (default is false)
    [Parameter()][bool]$skipPhysicalRDMDisks = $false,  # optional whether to skip backing up Physical RDM Disks (Default is false)
    [Parameter()][string]$startTime = '04:00',  # e.g. 23:30 for 11:30 PM
    [Parameter()][string]$timeZone = 'America/Chicago', # default 'America/New_York'
    [Parameter()][string]$backupRunTypeFull = 'kFull', # default 'America/New_York'
    [Parameter()][string]$backupRunTypeInc = 'kIncremental', # default 'America/New_York'
    [Parameter()][string]$objectProtectionType = 'kFile', # default 'America/New_York'
    [Parameter()][int]$incSLA = 66,  # incremental SLA minutes
    [Parameter()][int]$fullSLA = 127,  # full SLA minutes
    [Parameter(Mandatory = $False)][bool]$deleteAllSnapshots = $False,  # whether all Snapshots are deleted (default to $False)
    [Parameter()][array]$inclusions =''  # comma separarated inclusion list eg -inclusions '/C/Users/Faizan','/C/Temp/,'/E/New Movies/'
)

# outfile
$dateString = (get-date).ToString('yyyy-MM-dd')
$outfileName = "log-protectDMaasPhysical-$dateString.txt"

# validate startTime
[int64]$hour, [int64]$minute = $startTime.split(':')
$tempInt = ''
if(! (($hour -and $minute) -or ([int]::TryParse($hour,[ref]$tempInt) -and [int]::TryParse($minute,[ref]$tempInt)))){
    Write-Host "Please provide a valid start time" -ForegroundColor Yellow
    exit
}

# gather list of SQL Sources to Register
$physServersToAdd = @()
foreach($phys in $physFQDN){
    $physServersToAdd += $phys
}
if ('' -ne $physList){
    if(Test-Path -Path $physList -PathType Leaf){
        $physFQDN = Get-Content $physList
        foreach($phys in $physFQDN){
            $physServersToAdd += [string]$phys
        }
    }else{
        Write-Host "Physical Server list $physList not found!" -ForegroundColor Yellow
        exit
    }
}

$physServersToAdd = @($physServersToAdd | Where-Object {$_ -ne ''})

if($physServersToAdd.Count -eq 0){
    Write-Host "No Physical Servers specified" -ForegroundColor Yellow
    exit
}


# source the cohesity-api helper code
. $(Join-Path -Path $PSScriptRoot -ChildPath cohesity-api.ps1)

Write-Host "Connecting to DMaaS"

# authenticate
apiauth -username $username -regionid $regionId

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"

#test API Connection
Write-host "Testing API Connection...`n"
$headers.Add("apiKey", "$apiKey")
$apiTest = Invoke-RestMethod 'https://helios.cohesity.com/irisservices/api/v1/public/mcm/clusters/info' -Method 'GET' -Headers $headers

if(!$apiTest){
    write-host "Invalid API Key" -ForegroundColor Yellow
    exit
}


# validate DMaaS Tenant ID
Write-host "Validating Tenant ID...`n"
$headers.Add("accept", "application/json, text/plain, */*")
#$headers.Add('content-type: application/json')
$tenant = Invoke-RestMethod 'https://helios.cohesity.com/irisservices/api/v1/mcm/userInfo' -Method 'GET' -Headers $headers
$tenantId = $tenant.user.profiles.tenantId
Write-host "Tenant ID: " $tenantId

# validate DMaaS Region ID
Write-host "`nValidating Region ID..."
$region = Invoke-RestMethod "https://helios.cohesity.com/v2/mcm/dms/tenants/regions?tenantId=$tenantId" -Method 'GET' -Headers $headers

$region = api get -v2 mcm/dms/tenants/regions?tenantId=$tenantId

foreach($regionIds in $region){

    $regionIds = $region.tenantRegionInfoList.regionId

    $compareRegion = Compare-Object -IncludeEqual -ReferenceObject $regionIds -DifferenceObject $regionId -ExcludeDifferent

    if(!$compareRegion){
        write-host "There are no matching Region Ids asssociated with the confirmed Tenant ID." -ForegroundColor Yellow
        exit
    }

}

$headers.Add("regionId", "$regionId")
$headers.Add("Content-Type", "application/json")


# Write-Host "Finding protection policy"
# $policy = Invoke-RestMethod "https://helios.cohesity.com/v2/mcm/data-protect/policies?types=DMaaSPolicy" -Method 'GET' -Headers $headers

# foreach($pol in $policy.policies){
#     if($pol.policies.name -eq "$policyName"){
#     }
# }
# $policyId = $pol.id
# write-host "$policyId"

# if(!$policyId){
#     write-host "Policy $policyName not found" -ForegroundColor Yellow
#     exit
# }

Write-Host "Finding protection policy"

$policy = (api get -mcmv2 data-protect/policies?types=DMaaSPolicy).policies | Where-Object name -eq $policyName
if(!$policy){
    write-host "Policy $policyName not found" -ForegroundColor Yellow
    exit
}

$policyId = $policy.id
write-host "Policy ID: $policyId"

# find Physical source

foreach($physServer in $physServersToAdd){

    Write-Host "Finding Physical Server $physServer"

    $sources = Invoke-RestMethod "https://helios.cohesity.com/v2/mcm/data-protect/sources" -Method 'GET' -Headers $headers

    $source = $sources.sources | where-object {$_.name -eq "$physServer"}

    # Write-host "Finding Physical Server $physServer"
    # $sources = (api get -mcmv2 data-protect/sources?environments=kPhysical) | Where-Object {$_.sources.name -eq $physServer}
    # if(!$sources){
    #     Write-Host "Physical Server $physServer not found!" -ForegroundColor Yellow
    #     exit
    # }

    # $source = $sources.sources

    $sourceId = $source.sourceInfoList.registrationId
    $regId = $sourceId.split(':')
    [int64]$regId = $regId[2]

    write-host "Physical Source $physServer Registration Id: $regId"

    $environment = $source.environment

    #---------------------------------------------------------------------------------------------------------------#

    Write-Host "Determining if Physical Source is already Protected..."

    $object = (api get -v2 data-protect/search/protected-objects).objects | Where-Object name -eq $physServer
    if($object){
        write-host "Unprotecting $physServer in order to assign new Protection configuration."

        # configure unprotection parameters
        $unProtectionParams = @{
            "action" = "UnProtect";
            "objectActionKey" = $object.environment;
            "unProtectParams" = @{
                "objects" = @(
                    @{
                        "id" = $object.id;
                        "deleteAllSnapshots" = $deleteAllSnapshots;
                        "forceUnprotect" = $true;
                    };
                );
            };
            # "snapshotBackendTypes" = $object.environment;
        }

        # unprotect objects
        $unprotectResponse = api post -v2 data-protect/protected-objects/actions $unProtectionParams
        $unprotectResponse | out-file -filepath ./$outfileName -Append
        Write-Host "Unprotected $physServer"
    }


    #---------------------------------------------------------------------------------------------------------------#


    # configure protection parameters

    # $body = "{`"policyId`":`"$policyId`",`"startTime`":{`"hour`":$hour,`"minute`":$minute,`"timeZone`":`"$timeZone`"},`"priority`":`"$priority`",`"sla`":[{`"backupRunType`":`"$backupRunTypeFull`",`"slaMinutes`":$fullSLA},{`"backupRunType`":`"$backupRunTypeInc`",`"slaMinutes`":$incSLA}],`"qosPolicy`":`"$qosPolicy`",`"abortInBlackouts`":$abort,`"environment`":`"$environment`",`"physicalParams`":{`"objectProtectionType`":`"$objectProtectionType`",`"fileObjectProtectionTypeParams`":{`"indexingPolicy`":{`"enableIndexing`":$index,`"includePaths`":[],`"excludePaths`":[]},`"objects`":[{`"id`":$regId,`"filePaths`":[{`"includedPath`":`"$volumes`",`"excludedPaths`":[],`"skipNestedVolumes`":$skipNested}],`"usesPathLevelSkipNestedVolumeSetting`":$usePathLevel,`"nestedVolumeTypesToSkip`":[],`"followNasSymlinkTarget`":$nasSymlink}],`"performSourceSideDeduplication`":$sourceSideDedup,`"quiesce`":$quiesce,`"continueOnQuiesceFailure`":$contOnFail,`"dedupExclusionSourceIds`":[],`"globalExcludePaths`":[]}}}"


    $body = @{
        "policyId" = "$policyId";
        "startTime" = @{
            "hour"     = $hour;
            "minute"   = $minute;
            "timeZone"= "$timeZone"
        }
        "priority" = "kMedium";
        "sla"              = @(
        @{
            "backupRunType" = "kFull";
            "slaMinutes"    = $fullSlaMinutes
        };
        @{
            "backupRunType" = "kIncremental";
            "slaMinutes"    = $incrementalSlaMinutes
        }
    );
        "qosPolicy"="$qosPolicy";
        "abortInBlackouts"=$abort;
        "objects" = @(
        @{
            "environment"="$environment";
            "physicalParams"= @{
                "objectProtectionType"="kFile";
                "fileObjectProtectionTypeParams"= @{
                    "indexingPolicy"= @{
                        "enableIndexing"=$index;
                        "includePaths"= @();
                        "excludePaths"= @()
                    }
                    "objects"= @(
                    @{
                        "id"=$regId;
                        "isAutoprotected"= $autoProtected;
                        "filePaths"= @() #Will be updated as per cmdline args
                        "usesPathLevelSkipNestedVolumeSetting"=$usePathLevel;
                        "nestedVolumeTypesToSkip"= @();
                        "followNasSymlinkTarget"=$nasSymlink
                        }
                    )
                    "performSourceSideDeduplication"=$sourceSideDedup;
                    "quiesce"=$quiesce;
                    "continueOnQuiesceFailure"= $contOnFail;
                    "dedupExclusionSourceIds"=@();
                    "globalExcludePaths"=@()
                }
            }
        }
    )
}



# *********************************************** Inclusion Logic Start *****************************************************************************
#Faizan
# At the end of this Logic Section we will have $filePaths populated with relevant data of inclusions

if ($inclusions -ne '')
{
    foreach($pol in $inclusions)
    {
       # $body.objects.physicalParams.fileObjectProtectionTypeParams.objects[0].filePaths = @($body.objects.physicalParams.fileObjectProtectionTypeParams.objects[0].filePaths + @{

       # $body.objects.physicalParams.fileObjectProtectionTypeParams.objects[0].filePaths += (@{
        ($body.objects.physicalParams.fileObjectProtectionTypeParams.objects | where {$_.ContainsKey('filePaths')}).filePaths += (@{

        "includedPath"=$pol;
        "excludedPaths"= @();
        "skipNestedVolumes"=$skipNested
        })
}
}else{
    Write-Host "Inclusion List Empty $inclusions! All Drives will be Protected" -ForegroundColor Yellow
    ($body.objects.physicalParams.fileObjectProtectionTypeParams.objects | where {$_.ContainsKey('filePaths')}).filePaths += (@{
        "includedPath"='$ALL_LOCAL_DRIVES';
        "excludedPaths"= @();
        "skipNestedVolumes"=$skipNested
    })
}

# *********************************************** Inclusion Logic End *****************************************************************************


    if($source){
        Write-Host "Protecting $physServer"
        # $response = api post -v2 data-protect/protected-objects $protectionParams
        write-host = $body
        # $bodyJson = $body | ConvertTo-Json
        # write-host "$bodyJson"

        # $response = Invoke-RestMethod "https://helios.cohesity.com/v2/data-protect/protected-objects/$regid" -Method 'PUT' -Headers $headers -Body $bodyJson

        $response = api post -v2 data-protect/protected-objects $body
        $response | out-file -filepath ./$outfileName -Append
        Write-Host "Protected $physServer"
    }else{
        Write-Host "Physical Server $physServer not found" -ForegroundColor Yellow
    }
}
$body.objects.physicalParams.fileObjectProtectionTypeParams.objects[0].filePaths.includedPath