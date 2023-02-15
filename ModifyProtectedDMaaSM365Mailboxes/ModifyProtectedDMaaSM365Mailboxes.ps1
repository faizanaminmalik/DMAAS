# process commandline arguments
[CmdletBinding()]
param (
    [Parameter()][string]$username = 'DMaaS', # Username used to log into Helios
    [Parameter(Mandatory = $True)][string]$region,  # DMaaS region
    [Parameter(Mandatory = $True)][string]$policyName = '',  # protection policy name
    [Parameter(Mandatory = $True)][string]$sourceName,  # name of registered O365 source
    [Parameter()][array]$mailboxes = '',  # optional names of mailboxes protect use @() for array of mailboxes
    [Parameter()][string]$mailboxList = '', # optional textfile of mailboxes to protect 'Mailbox_list.txt', 
    [Parameter()][string]$startTime = '23:59',  # e.g. 23:30 for 11:30 PM
    [Parameter()][string]$timeZone = 'America/Los_Angeles', # e.g. 'America/New_York'
    [Parameter()][int]$incrementalSlaMinutes = 99,  # incremental SLA minutes
    [Parameter()][int]$fullSlaMinutes = 199,  # full SLA minutes
    [Parameter(Mandatory = $False)][bool]$deleteAllSnapshots = $False,  # whether all Snapshots are deleted (default to $False)
    [Parameter()][int]$pageSize = 50000
)

# gather list of mailboxes to protect
$mailboxesToAdd = @()
foreach($mailbox in $mailboxes){
    $mailboxesToAdd += $mailbox
}
if ('' -ne $mailboxList){
    if(Test-Path -Path $mailboxList -PathType Leaf){
        $mailboxes = Get-Content $mailboxList
        foreach($mailbox in $mailboxes){
            $mailboxesToAdd += [string]$mailbox
        }
    }else{
        Write-Host "mailbox list $mailboxList not found!" -ForegroundColor Yellow
        exit
    }
}

$mailboxesToAdd = @($mailboxesToAdd | Where-Object {$_ -ne ''})

if($mailboxesToAdd.Count -eq 0){
    Write-Host "No mailboxes specified" -ForegroundColor Yellow
    exit
}

# parse startTime
$hour, $minute = $startTime.split(':')
$tempInt = ''
if(! (($hour -and $minute) -or ([int]::TryParse($hour,[ref]$tempInt) -and [int]::TryParse($minute,[ref]$tempInt)))){
    Write-Host "Please provide a valid start time" -ForegroundColor Yellow
    exit
}

# source the cohesity-api helper code
. $(Join-Path -Path .\ -ChildPath cohesity-api.ps1)

# authenticate
apiauth -username $username -regionid $region

$policy = (api get -mcmv2 data-protect/policies?types=DMaaSPolicy).policies | Where-Object name -eq $policyName
if(!$policy){
    write-host "Policy $policyName not found" -ForegroundColor Yellow
    exit
}

# find O365 source
$rootSource = api get protectionSources/rootNodes?environments=kO365 | Where-Object {$_.protectionSource.name -eq $sourceName}
if(!$rootSource){
    Write-Host "O365 Source $sourceName not found" -ForegroundColor Yellow
    exit
}
$source = api get "protectionSources?id=$($rootSource.protectionSource.id)&excludeOffice365Types=kMailbox,kUser,kGroup,kSite,kPublicFolder,kTeam,kO365Exchange,kO365OneDrive,kO365Sharepoint&allUnderHierarchy=false"
$usersNode = $source.nodes | Where-Object {$_.protectionSource.name -eq 'Users'}
if(!$usersNode){
    Write-Host "Source $sourceName is not configured for O365 Mailboxes" -ForegroundColor Yellow
    exit
}

$nameIndex = @{}
$smtpIndex = @{}
$users = api get "protectionSources?pageSize=$pageSize&nodeId=$($usersNode.protectionSource.id)&id=$($usersNode.protectionSource.id)&hasValidMailbox=true&allUnderHierarchy=false"
while(1){
    # implement pagination
    foreach($node in $users.nodes){
        $nameIndex[$node.protectionSource.name] = $node.protectionSource.id
        $smtpIndex[$node.protectionSource.office365ProtectionSource.primarySMTPAddress] = $node.protectionSource.id
    }
    $cursor = $users.nodes[-1].protectionSource.id
    $users = api get "protectionSources?pageSize=$pageSize&nodeId=$($usersNode.protectionSource.id)&id=$($usersNode.protectionSource.id)&hasValidMailbox=true&allUnderHierarchy=false&afterCursorEntityId=$cursor"
    if(!$users.PSObject.Properties['nodes'] -or $users.nodes.Count -eq 1){
        break
    }
}  

#Unprotect the Mailboxes if they are already protected
Write-Host "Determining if the M365 Source(s) is already Protected..." #Work in Progress 7/20/2022 8:27PM
 
foreach ($Sourceobject in $mailboxesToAdd)
            {$unprotectItemObjects = (api get -v2 data-protect/search/protected-objects).objects | Where-Object {$_.name -eq $Sourceobject -and $_.sourceInfo.uuid -contains $Sourcename}
            $unprotectItem = $unprotectItemObjects.name
            



    if($unprotectItem){
        write-host "Unprotecting $unprotectItem in order to assign new Protection configuration." 

        # configure unprotection parameters
        $unProtectionParams = @{
            "action" = "UnProtect";
            "objectActionKey" = "kO365Exchange";
            "unProtectParams" = @{
                "objects" = @( 
                    @{
                        "id" = $unprotectItemObjects.id;
                        "deleteAllSnapshots" = $deleteAllSnapshots;
                        "forceUnprotect" = $true;
                    };
                );
            };
            # "snapshotBackendTypes" = $object.environment;
        }

        # unprotect objects
        $unprotectResponse = api post -v2 data-protect/protected-objects/actions $unProtectionParams 
        #$unprotectResponse | out-file -filepath .\$outfileName -Append
        Write-Host "Unprotected $unprotectItem"
    }
    Else {"Unable to Find $unprotectItem in order to unprotect prior to assigning new Protection configuration." }
   }



# configure protection parameters
$protectionParams = @{
    "policyId"         = $policy.id;
    "startTime"        = @{
        "hour"     = [int64]$hour;
        "minute"   = [int64]$minute;
        "timeZone" = $timeZone
    };
    "priority"         = "kMedium";
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
    "qosPolicy"        = "kBackupSSD";
    "abortInBlackouts" = $false;
    "objects"          = @()
}

$mailboxesAdded = 0

# find mailboxes
foreach($mailbox in $mailboxesToAdd){
    $userId = $null
    if($smtpIndex.ContainsKey($mailbox)){
        $userId = $smtpIndex[$mailbox]
    }elseif($nameIndex.ContainsKey($mailbox)){
        $userId = $nameIndex[$mailbox]
    }
    if($userId){
        $protectionParams.objects = @(@{
            "environment"     = "kO365Exchange";
            "office365Params" = @{
                "objectProtectionType"              = "kMailbox";
                "userMailboxObjectProtectionParams" = @{
                    "objects"        = @(
                        @{
                            "id" = $userId
                        }
                    );
                    "indexingPolicy" = @{
                        "enableIndexing" = $true;
                        "includePaths"   = @(
                            "/"
                        );
                        "excludePaths"   = @();

                    }
                    "excludeFolders" = @("Calendar","In-Place archive","Recoverable Items")
                }
            }
        })
        Write-Host "Protecting $mailbox"
        $response = api post -v2 data-protect/protected-objects $protectionParams
    }else{
        Write-Host "Mailbox $mailbox not found" -ForegroundColor Yellow
    }
}
