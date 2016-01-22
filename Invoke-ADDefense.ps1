Import-Module ActiveDirectory

# TODO: registry sweeps

function Invoke-ThreadedFunction {
<#
    .SYNOPSIS

        Helper used by any threaded host enumeration functions

    .PARAMETER ComputerName

        Array of ComputerNames to run the specified ScriptBlock against.

    .PARAMETER ScriptBlock

        Script block to run against each computer in ComputerName.

    .PARAMETER ScriptParameters

        Hash tables of additional parameters to supply to the script block.

    .PARAMETER Threads

        Number of concurrent threads to run, default of 50.
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$True)]
        [String[]]
        $ComputerName,

        [Parameter(Position=1,Mandatory=$True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Parameter(Position=2)]
        [Hashtable]
        $ScriptParameters,

        [Int]
        $Threads = 50
    )

    begin {

        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        Write-Verbose "[*] Total number of hosts: $($ComputerName.count)"

        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        #   Thanks Carlos!

        # create a pool of maxThread runspaces
        $Pool = [runspacefactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        $Jobs = @()
        $PS = @()
        $Wait = @()

        $Counter = 0
    }

    process {

        ForEach ($Computer in $ComputerName) {

            # make sure we get a server name
            if ($Computer -ne '') {
                # Write-Verbose "[*] Enumerating server $Computer ($($Counter+1) of $($ComputerName.count))"

                While ($($Pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -MilliSeconds 500
                }

                # create a "powershell pipeline runner"
                $PS += [powershell]::create()

                $PS[$Counter].runspacepool = $Pool

                # add the script block + arguments
                $Null = $PS[$Counter].AddScript($ScriptBlock).AddParameter('ComputerName', $Computer)
                if($ScriptParameters) {
                    ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                        $Null = $PS[$Counter].AddParameter($Param.Name, $Param.Value)
                    }
                }

                # start job
                $Jobs += $PS[$Counter].BeginInvoke();

                # store wait handles for WaitForAll call
                $Wait += $Jobs[$Counter].AsyncWaitHandle
            }
            $Counter = $Counter + 1
        }
    }

    end {

        Write-Verbose "Waiting for scanning threads to finish..."

        $WaitTimeout = Get-Date

        # set a 60 second timeout for the scanning threads
        while ($($Jobs | Where-Object {$_.IsCompleted -eq $False}).count -gt 0 -or $($($(Get-Date) - $WaitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -MilliSeconds 500
            }

        # end async call
        for ($y = 0; $y -lt $Counter; $y++) {

            try {
                # complete async job
                $PS[$y].EndInvoke($Jobs[$y])

            } catch {
                Write-Warning "error: $_"
            }
            finally {
                $PS[$y].Dispose()
            }
        }
        
        $Pool.Dispose()
        Write-Verbose "All threads completed!"
    }
}


# # return live hosts
# $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
# $ComputerName = Invoke-ThreadedFunction -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100


function Find-BadPwdAttempt {
<#
    .SYNOPSIS

        Pulls all users with BadPwdCount > a specified threshold (default of 3).

    .PARAMETER Domain

        Specific domain to pull users from, otherwise defaults the current domain.

    .PARAMETER SearchForest

        Switch. Search all domains in the forest instead of the current one.

    .PARAMETER Threshold

        Threshold for BadPwdCount, default of 3
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain = $ENV:UserDNSDomain,

        [Switch]
        $SearchForest,

        [Int]
        $Threshold = 3
    )

    process {
        if($SearchForest) {
            # enumerate all DCs in the current forest
            $Domains = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).Domains.Name
        }
        else {
            $Domains = @($Domain)
        }
        $Domains | ForEach-Object {
            Write-Verbose "Enumerating domain: $_"
            Get-ADUser -filter * -Properties BadPwdCount -Server $_ | where {$_.badpwdcount -gt $Threshold}
        }        
    }
}


function Find-MaliciousSidHistory {
<#
    .SYNOPSIS

        Pulls all users with a SIDHistory set for all domains in the forest.

    .PARAMETER Domain

        Specific domain to pull users from, otherwise defaults the current domain.

    .PARAMETER SearchForest

        Switch. Search all domains in the forest instead of the current one.
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain = $ENV:UserDNSDomain,

        [Switch]
        $SearchForest
    )

    process {
        if($SearchForest) {
            # enumerate all DCs in the current forest
            $Domains = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).Domains.Name
        }
        else {
            $Domains = @($Domain)
        }
        $Domains | ForEach-Object {
            Write-Verbose "Enumerating domain: $_"
            Get-ADUser -Filter * -Properties SIDHistory -Server $_ | Where-Object { $_.SIDHistory }
        }
    }
}


function Find-ExpiredActiveMachine {
<#
    .SYNOPSIS

        Finds machines account that have logged on in the last 30 days but have 
        machine account passwords > 30 days.

    .PARAMETER Domain

        Specific domain to pull users from, otherwise defaults the current domain.

    .PARAMETER SearchForest

        Switch. Search all domains in the forest instead of the current one.
#>
    
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain = $ENV:UserDNSDomain,

        [Switch]
        $SearchForest
    )

    process {
        if($SearchForest) {
            # enumerate all DCs in the current forest
            $Domains = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).Domains.Name
        }
        else {
            $Domains = @($Domain)
        }
        $Domains | ForEach-Object {
            Write-Verbose "Enumerating domain: $_"
            Get-ADComputer -Filter * -Properties pwdLastSet,LastLogonDate -Server $_ | Where-Object {
                ([DateTime]::FromFileTime($_.pwdLastSet) -lt (Get-Date).AddDays(-30)) -and ($_.LastLogonDate -gt (Get-Date).AddDays(-30))
            }
        }
    }
}


function Find-GoldenTicketEvent {
<#
    .SYNOPSIS

        Finds potential golden ticket events.

        Based on Sean Metcalf (@pyrotek3)'s work at https://adsecurity.org/?p=1515

    .PARAMETER ComputerName
        
        Array of specific computers to pull events from.

    .PARAMETER Domain

        Specific domain to pull events from, otherwise defaults the current domain.

    .PARAMETER SearchForest

        Switch. Search all domains in the forest instead of the current one.

    .LINK

        https://adsecurity.org/?p=1515
#>
    
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String[]]
        $ComputerName,

        [String]
        $Domain = $ENV:UserDNSDomain,

        [Switch]
        $SearchForest
    )

    process {

        if($ComputerName) {
            $TargetComputers = @($ComputerName)
        }
        elseif($SearchForest) {
            # enumerate all DCs in the current forest
            $TargetComputers = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).Domains.DomainControllers.Name
        }
        else {
            $TargetComputers = @($Domain)
        }

        $TargetComputers | ForEach-Object {
            Write-Verbose "Enumerating computer: $_"
            # filter on logon/logoff events
            Get-WinEvent -ComputerName $_ -FilterHashTable @{ LogName = "Security"; ID = 4624,4634 } | ForEach-Object {

                # convert to XML to extract the user/domain information easily
                $RawMessage = $_.Message
                $XML = [xml]$_.ToXml()
                $User = $XML.Event.EventData.Data[1].'#text'
                $Domain = $XML.Event.EventData.Data[2].'#text'

                # ignore null user, machine accounts, and anonymous logins
                if(($User -ne "-") -and ($User -notmatch '\$$') -and ($User -ne 'ANONYMOUS LOGON')) {
                    # null or 'eo.oe' or FQDN for the domain
                    if (($Domain -match 'eo.oe') -or ($Domain -match '\.') -or ($Domain -match '-') -or ($Domain.Trim() -eq '')) {

                        # turn the result into a custom object
                        $Properties = @{}
                        $XML.Event.EventData.Data | % {
                            $Properties[$_.Name] = $_."#text"
                        }
                        $Properties["ComputerName"] = $XML.Event.System.Computer
                        $Properties["RawMessage"] = $RawMessage
                        New-Object -TypeName PSObject -Property $Properties
                    }
                }
            }
        }
    }
}


function Find-MsfPsExec {
<#
    .SYNOPSIS

        Finds potential MSF PsExec execution on hosts.

        Based on SChris Campbell (@obscuresec)'s work at http://obscuresecurity.blogspot.com/p/presentation-slides.html

    .PARAMETER ComputerName
        
        Array of specific computers to pull events from.

    .PARAMETER Domain

        Specific domain to pull events from, otherwise defaults the current domain.

    .PARAMETER SearchForest

        Switch. Search all domains in the forest instead of the current one.

    .LINK

        http://obscuresecurity.blogspot.com/p/presentation-slides.html
#>
    
    [CmdletBinding()]
    param(
        [String[]]
        $ComputerName,

        [String]
        $Domain = $ENV:UserDNSDomain,

        [Switch]
        $SearchForest,

        [Int]
        $Threads = 50
    )

    # TODO handle threading when passed an array of $ComputerName...
    if($ComputerName) {
        $TargetComputers = @($ComputerName)
    }
    elseif($SearchForest) {
        # enumerate all DCs in the current forest
        $TargetDCs = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).Domains.DomainControllers.Name
    }
    else {
        $TargetDCs = @($Domain)
    }

    $TargetDCs | ForEach-Object {
        $TargetComputers += (Get-ADComputer -Filter * -Server PRIMARY.testlab.local).DNSHostName
    }

    $HostEnumBlock = {
        param($ComputerName)

        # check if the server is up first
        $Up = $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
        if($Up) {
            Get-WinEvent -ComputerName $ComputerName -FilterHashTable @{ LogName = "System"; ID = 7045 } | 

                    Where-Object {($_.Message -like "*%SYSTEMROOT%\????????.exe*") -or ($_.Message -like "*Service File Name:*powershell.exe*")} | 

                        Select-Object MachineName,UserID,TimeCreated,ProcessID,Message
        }
    }

    # kick off the threaded script block + arguments 
    Invoke-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -Threads 50
}
