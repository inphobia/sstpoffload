Function Enable-SstpOffload {

    [cmdletbinding(SupportsShouldProcess)]
    [Outputtype("None", "PSCustomObject")]

    Param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName, HelpMessage = "Enter the name of the remote RRAS server.")]
        [ValidateNotNullOrEmpty()]
        [string[]]$Computername = $env:computername,
        [Parameter(Position = 1, Mandatory, HelpMessage = "Enter the SHA2 certificate hash", ValueFromPipelineByPropertyName)]
        [ValidateNotNullorEmpty()]
        #The hash value must be 64 characters long
        [ValidateScript( {$_.length -eq 64})]
        [alias("hash")]
        [string]$CertificateHash,
        [switch]$Restart,
        [Parameter(HelpMessage = "Enter an optional credential in the form domain\username or machine\username")]
        [PSCredential]$Credential,
        [ValidateSet('Default', 'Basic', 'Credssp', 'Digest', 'Kerberos', 'Negotiate', 'NegotiateWithImplicitCredential')]
        [ValidateNotNullorEmpty()]
        [string]$Authentication = "default",
        [switch]$UseSSL,
        [switch]$Passthru
    )

    Begin {
        Write-Verbose "Starting $($myinvocation.mycommand)"

        #display some meta information for troubleshooting
        Write-Verbose "PowerShell version: $($psversiontable.psversion)"
        Write-Verbose "Operating System: $((Get-Ciminstance -class win32_operatingsystem -property caption).caption)"

        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SstpSvc\Parameters"

        $sb = {

            Param([string]$RegPath, [string]$CertificateHash, [bool]$Restart, [bool]$Passthru)

            Try {
                $VerbosePreference = $using:verbosepreference
            }
            catch {
                Write-Verbose "Using local Verbose preference"
            }
            Try {
                $whatifpreference = $using:whatifpreference
            }
            Catch {
                Write-Verbose "Using local Whatif preference"
            }

            Write-Verbose "WhatIf = $whatifpreference"
            Write-verbose "Verbose = $VerbosePreference"

            #validate this registry path exists. It might not.
            If (Test-Path -Path $regPath) {
                Write-Verbose "Updating $regpath"
                Write-Verbose "Creating certbinary from $CertificateHash"
                $certbinary = @()
                for ($i = 0; $i -lt $CertificateHash.Length ; $i += 2) {
                    $certbinary += [Byte]::Parse($CertificateHash.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber)
                }

                #use transactions when modifying the registry so that if any change fails
                #the entire transaction fails
                if (-Not $whatifpreference) {
                    Start-Transaction -RollbackPreference TerminatingError
                }
                Write-Verbose "Setting SstpSvc parameter values"
                #define a hashtable of parameter values to splat to New-Itemproperty
                $newParams = @{
                    Path         = $regPath
                    Force        = $True
                    PropertyType = "DWORD"
                    Name         = ""
                    Value        = ""
                    WhatIf       = $whatifpreference
                    ErrorAction  = "stop"
                }

                if (-Not $whatifpreference) {
                    $newParams.Add("UseTransaction", $True)
                }
                $newParams | Out-String | Write-Verbose

                $newParams.name = 'UseHttps'
                $newParams.value = 0

                Try {
                    Write-Verbose "Create new item property $($newparams.name) with a value of $($newparams.value)"
                    New-ItemProperty @newParams | Out-Null
                }

                Catch {
                    Throw $_
                }

                $newParams.name = 'isHashConfiguredByAdmin'
                $newParams.value = 1

                Try {
                     Write-Verbose "Create new item property $($newparams.name) with a value of $($newparams.value)"
                    New-ItemProperty @newParams | Out-Null
                }
                Catch {
                    Throw $_
                }

                $newParams.name = 'SHA256CertificateHash'
                $newParams.value = $certbinary
                $newParams.PropertyType = "binary"

                Try {
                    Write-Verbose "Create new item property SHA256CertificateHash"
                    New-ItemProperty @newParams | Out-Null
                }
                Catch {
                    Throw $_
                }

                #if registry entry SHA1CertificateHash exists, delete it
                Try {
                    $key = Get-ItemProperty -path $RegPath -name SHA1CertificateHash -ErrorAction Stop
                    if ($key) {
                        Write-Verbose "Removing SHA1CertificateHash"
                        $rmParams = @{
                            Path        = $RegPath
                            Name        = "SHA1CertificateHash"
                            ErrorAction = "Stop"
                        }
                        if (-Not $whatifpreference) {
                            $rmParams.Add("UseTransaction", $True)
                        }
                        Remove-ItemProperty @rmParams
                    }
                }
                Catch {
                    #ignore the error if the registry value is not found
                    Write-Verbose "SHA1CertificateHash key not found"
                }
                if (-not $whatifpreference) {
                    Complete-Transaction
                }

                if (-Not $WhatifPreference) {

                    #set a flag to indicate registry changes where successful
                    #so that -Passthru and service message are only displayed if this is true
                    Write-Verbose "Validating changes"
                    if ( (Get-ItempropertyValue -path $regpath -name IsHashConfiguredByAdmin) -eq 1) {

                        Write-Verbose "Registry changes successful"

                        if ($Restart) {
                            Write-Verbose "Restarting RemoteAccess service on $env:Computername"
                            Restart-Service -name RemoteAccess -force
                        }
                        else {
                            $msg = @"

You must restart the RemoteAccess service before any registry changes take effect.

PS C:\> Get-Service RemoteAccess -computername $env:computername | Restart-Service -force

Or use PowerShell Remoting:

PS C:\> invoke-command {Restart-Service RemoteAccess -force} -computername $env:computername

"@
                            Write-Warning $msg
                        }

                        if ($Passthru) {
                            Get-ItemProperty -Path $regPath |
                                Select-Object -property UseHttps, isHashConfiguredByAdmin,
                            @{Name = "SHA1Hash"; Expression = {[System.BitConverter]::ToString($_.SHA1CertificateHash) -replace "-", ""}},
                            @{Name = "SHA256Hash"; Expression = {[System.BitConverter]::ToString($_.SHA256CertificateHash) -replace "-", ""}},
                            @{Name = "Computername"; Expression = {$env:COMPUTERNAME}}

                        }

                    } #if validated
                    else {
                        write-Error "Registry changes failed. $($_.Exception.Message)"
                    }
                } #should process
                else {
                    Write-Verbose "You would also need to restart the RemoteAccess service."
                }
            } #if registry path found
            else {
                Write-Warning "Can't find registry path $($regpath)"
            }
        } #close scriptblock

        #define a set of parameter values to splat to Invoke-Command
        $icmParams = @{
            Scriptblock  = $sb
            ArgumentList = ""
            ErrorAction  = "Stop"
        }

    } #Begin

    Process {

        foreach ($computer in $computername) {

            $icmParams.ArgumentList = @($regPath, $CertificateHash, $restart, $passthru)
            #only use -Computername if querying a remote computer
            if ($Computername -ne $env:computername) {
                Write-Verbose "Using remote parameters"
                $icmParams.Computername = $computer
                $icmParams.HideComputername = $True
                $icmParams.Authentication = $Authentication

                if ($pscredential.username) {
                    Write-Verbose "Adding an alternate credential for $($pscredential.username)"
                    $icmParams.Add("Credential", $PSCredential)
                }
                if ($UseSSL) {
                    Write-Verbose "Using SSL"
                    $icmParams.Add("UseSSL", $True)
                }
                Write-Verbose "Using $Authentication authentication."
            }
            $icmParams | Out-String | Write-verbose

            Write-Verbose "Modifying $($computer.toUpper())"
            Try {
                #display result without the runspace ID
                Invoke-Command @icmParams | Select-Object -Property * -ExcludeProperty RunspaceID
            }
            Catch {
                Throw $_
            }
        } #foreeach
    } #process

    End {
        Write-Verbose "Ending $($myinvocation.MyCommand)"
    }
} #end function