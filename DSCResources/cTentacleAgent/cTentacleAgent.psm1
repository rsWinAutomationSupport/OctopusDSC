function Get-TargetResource
{
    [OutputType([Hashtable])]
    param (
        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [ValidateSet("Started", "Stopped")]
        [string]$State = "Started",
        
        [string]$ApiKey,
        [string]$OctopusServerUrl,
        [string[]]$Environments,
        [string[]]$Roles,
        [string]$DefaultApplicationDirectory,
        [int]$ListenPort,
        [string]$RegisteredNic
        <#[bool]$InitialDeploy,
        [string[]]$DeployProject,
        [string]$DeployVersion#>
    )

    Write-Verbose "Checking if Tentacle is installed"
    $installLocation = (get-itemproperty -path "HKLM:\Software\Octopus\Tentacle" -ErrorAction SilentlyContinue).InstallLocation
    $present = ($installLocation -ne $null)
    Write-Verbose "Tentacle present: $present"
    
    $currentEnsure = if ($present) { "Present" } else { "Absent" }

    $serviceName = (Get-TentacleServiceName $Name)
    Write-Verbose "Checking for Windows Service: $serviceName"
    $serviceInstance = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentState = "Stopped"
    if ($serviceInstance -ne $null) 
    {
        Write-Verbose "Windows service: $($serviceInstance.Status)"
        if ($serviceInstance.Status -eq "Running") 
        {
            $currentState = "Started"
        }
        
        if ($currentEnsure -eq "Absent") 
        {
            Write-Verbose "Since the Windows Service is still installed, the service is present"
            $currentEnsure = "Present"
        }
    } 
    else 
    {
        Write-Verbose "Windows service: Not installed"
        $currentEnsure = "Absent"
    }

    return @{
        Name = $Name; 
        Ensure = $currentEnsure;
        State = $currentState;
    };
}

function Set-TargetResource 
{
    param (       
        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [ValidateSet("Started", "Stopped")]
        [string]$State = "Started",
        
        [string]$ApiKey,
        [string]$OctopusServerUrl,
        [string[]]$Environments,
        [string[]]$Roles,
        [string]$DefaultApplicationDirectory = "$($env:SystemDrive)\Applications",
        [int]$ListenPort = 10933,
        [string]$RegisteredNic
        <#[bool]$InitialDeploy = $false,
        [string[]]$DeployProject,
        [string]$DeployVersion#>
   )

    if ($Ensure -eq "Absent" -and $State -eq "Started") 
    {
        throw "Invalid configuration: service cannot be both 'Absent' and 'Started'"
    }

    if ( (-not $InitialDeploy) -and ($DeployProject -or $DeployVersion))
    {
        throw "Invalid configuration: Resource set to not do initial deploy but Project and/or Version to deploy to specified"
    }

    $currentResource = (Get-TargetResource -Name $Name)

    Write-Verbose "Configuring Tentacle..."

    if ($State -eq "Stopped" -and $currentResource["State"] -eq "Started") 
    {
        $serviceName = (Get-TentacleServiceName $Name)
        Write-Verbose "Stopping $serviceName"
        Stop-Service -Name $serviceName -Force
    }

    if ($Ensure -eq "Absent" -and $currentResource["Ensure"] -eq "Present")
    {
        Remove-TentacleRegistration -name $Name -apiKey $ApiKey -octopusServerUrl $OctopusServerUrl
        
        $serviceName = (Get-TentacleServiceName $Name)
        Write-Verbose "Deleting service $serviceName..."
        Invoke-AndAssert { & sc.exe delete $serviceName }
        
        # Uninstall msi
        Write-Verbose "Uninstalling Tentacle..."
        $tentaclePath = "$($env:SystemDrive)\Octopus\Tentacle.msi"
        $msiLog = "$($env:SystemDrive)\Octopus\Tentacle.msi.uninstall.log"
        if (test-path $tentaclePath)
        {
            $msiExitCode = (Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $tentaclePath /quiet /l*v $msiLog" -Wait -Passthru).ExitCode
            Write-Verbose "Tentacle MSI installer returned exit code $msiExitCode"
            if ($msiExitCode -ne 0) 
            {
                throw "Removal of Tentacle failed, MSIEXEC exited with code: $msiExitCode. View the log at $msiLog"
            }
        }
        else 
        {
            throw "Tentacle cannot be removed, because the MSI could not be found."
        }
    } 
    elseif ($Ensure -eq "Present" -and $currentResource["Ensure"] -eq "Absent") 
    {
        Write-Verbose "Installing Tentacle..."
        New-Tentacle -name $Name -apiKey $ApiKey -octopusServerUrl $OctopusServerUrl -port $ListenPort -RegisteredNic $RegisteredNic -environments $Environments -roles $Roles -DefaultApplicationDirectory $DefaultApplicationDirectory
        Write-Verbose "Tentacle installed!"
    }

    if ($State -eq "Started" -and $currentResource["State"] -eq "Stopped") 
    {
        $serviceName = (Get-TentacleServiceName $Name)
        Write-Verbose "Starting $serviceName"
        Start-Service -Name $serviceName
    }
    <#if ($State -eq "Started" -and $Ensure -eq "Present" -and $InitialDeploy)
    {
        foreach($project in $DeployProject){
			if ($DeployVersion -and $DeployProject.count -eq 1)
			{
				Invoke-InitialDeploy -name $Name -apiKey $ApiKey -octopusServerUrl $octopusServerUrl -Environments $Environments -Project $project -Version $DeployVersion -Wait
			}
			else
			{
				Invoke-InitialDeploy -name $Name -apiKey $ApiKey -octopusServerUrl $octopusServerUrl -Environments $Environments -Project $project -Wait
			}
		}
    }#>

    Write-Verbose "Finished"
}

function Test-TargetResource 
{
    param (       
        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [ValidateSet("Started", "Stopped")]
        [string]$State = "Started",
        
        [string]$ApiKey,
        [string]$OctopusServerUrl,
        [string[]]$Environments,
        [string[]]$Roles,
        [string]$DefaultApplicationDirectory,
        [int]$ListenPort,
        [string]$RegisteredNic
        <#[bool]$InitialDeploy,
        [string[]]$DeployProject,
        [string]$DeployVersion#>
    )
 
    $currentResource = (Get-TargetResource -Name $Name)

    $ensureMatch = $currentResource["Ensure"] -eq $Ensure
    Write-Verbose "Ensure: $($currentResource["Ensure"]) vs. $Ensure = $ensureMatch"
    if (!$ensureMatch) 
    {
        return $false
    }
    
    $stateMatch = $currentResource["State"] -eq $State
    Write-Verbose "State: $($currentResource["State"]) vs. $State = $stateMatch"
    if (!$stateMatch) 
    {
        return $false
    }

    return $true
}

function Get-TentacleServiceName 
{
    param ( [string]$instanceName )

    if ($instanceName -eq "Tentacle") 
    {
        return "OctopusDeploy Tentacle"
    } 
    else 
    {
        return "OctopusDeploy Tentacle: $instanceName"
    }
}

function Request-File 
{
    param (
        [string]$url,
        [string]$saveAs
    )
 
    Write-Verbose "Downloading $url to $saveAs"
    $downloader = new-object System.Net.WebClient
    $downloader.DownloadFile($url, $saveAs)
}

function Invoke-AndAssert {
    param ($block) 
  
    & $block | Write-Verbose
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne $null) 
    {
        throw "Command returned exit code $LASTEXITCODE"
    }
}
 
# After the Tentacle is registered with Octopus, Tentacle listens on a TCP port, and Octopus connects to it. The Octopus server
# needs to know the public IP address to use to connect to this Tentacle instance. Is there a way in Windows Azure in which we can 
# know the public IP/host name of the current machine?
function Get-MyPublicIPAddress([string]$RegisteredNic)
{
    Write-Verbose "Getting IP address of $($RegisteredNic) NIC"
    $ip = Get-NetIPAddress -InterfaceAlias $RegisteredNic -AddressFamily IPv4 | select -exp IPAddress
    <#$downloader = new-object System.Net.WebClient
    $ip = $downloader.DownloadString("http://icanhazip.com").Trim()#>
    return $ip
}
 
function New-Tentacle 
{
    param (
        [Parameter(Mandatory=$True)]
        [string]$name,
        [Parameter(Mandatory=$True)]
        [string]$apiKey,
        [Parameter(Mandatory=$True)]
        [string]$octopusServerUrl,
        [Parameter(Mandatory=$True)]
        [string[]]$environments,
        [Parameter(Mandatory=$True)]
        [string[]]$roles,
        [int] $port,
        [string]$RegisteredNic,
        [string]$DefaultApplicationDirectory
    )
 
    if ($port -eq 0) 
    {
        $port = 10933
    }

    Write-Verbose "Beginning Tentacle installation" 
  
    $tentacleDownloadUrl = "http://octopusdeploy.com/downloads/latest/OctopusTentacle64"
    if ([IntPtr]::Size -eq 4) 
    {
        $tentacleDownloadUrl = "http://octopusdeploy.com/downloads/latest/OctopusTentacle"
    }

    mkdir "$($env:SystemDrive)\Octopus" -ErrorAction SilentlyContinue

    $tentaclePath = "$($env:SystemDrive)\Octopus\Tentacle.msi"
    if ((test-path $tentaclePath) -ne $true) 
    {
        Write-Verbose "Downloading latest Octopus Tentacle MSI from $tentacleDownloadUrl to $tentaclePath"
        Request-File $tentacleDownloadUrl $tentaclePath
    }
  
    Write-Verbose "Installing MSI..."
    $msiLog = "$($env:SystemDrive)\Octopus\Tentacle.msi.log"
    $msiExitCode = (Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $tentaclePath /quiet /l*v $msiLog" -Wait -Passthru).ExitCode
    Write-Verbose "Tentacle MSI installer returned exit code $msiExitCode"
    if ($msiExitCode -ne 0) 
    {
        throw "Installation of the Tentacle MSI failed; MSIEXEC exited with code: $msiExitCode. View the log at $msiLog"
    }
 
    Write-Verbose "Open port $port on Windows Firewall"
    Invoke-AndAssert { & netsh.exe advfirewall firewall add rule protocol=TCP dir=in localport=$port action=allow name="Octopus Tentacle: $Name" }
    
    $ipAddress = Get-MyPublicIPAddress $RegisteredNic
    #$ipAddress = $ipAddress.Trim()
 
    Write-Verbose "Public IP address: $ipAddress"
    Write-Verbose "Configuring and registering Tentacle"
  
    pushd "${env:ProgramFiles}\Octopus Deploy\Tentacle"
 
    $tentacleHomeDirectory = "$($env:SystemDrive)\Octopus"
    $tentacleAppDirectory = $DefaultApplicationDirectory
    $tentacleConfigFile = "$($env:SystemDrive)\Octopus\$Name\Tentacle.config"
    Invoke-AndAssert { & .\tentacle.exe create-instance --instance $name --config $tentacleConfigFile --console }
    Invoke-AndAssert { & .\tentacle.exe configure --instance $name --home $tentacleHomeDirectory --console }
    Invoke-AndAssert { & .\tentacle.exe configure --instance $name --app $tentacleAppDirectory --console }
    Invoke-AndAssert { & .\tentacle.exe configure --instance $name --port $port --console }
    Invoke-AndAssert { & .\tentacle.exe new-certificate --instance $name --console }
    Invoke-AndAssert { & .\tentacle.exe service --install --instance $name --console }

    $registerArguments = @("register-with", "--instance", $name, "--server", $octopusServerUrl, "--name", $env:COMPUTERNAME, "--publicHostName", $ipAddress, "--apiKey", $apiKey, "--comms-style", "TentaclePassive", "--force", "--console")

    foreach ($environment in $environments) 
    {
        foreach ($e2 in $environment.Split(',')) 
        {
            $registerArguments += "--environment"
            $registerArguments += $e2.Trim()
        }
    }
    foreach ($role in $roles) 
    {
        foreach ($r2 in $role.Split(',')) 
        {
            $registerArguments += "--role"
            $registerArguments += $r2.Trim()
        }
    }

    Write-Verbose "Registering with arguments: $registerArguments"
    Invoke-AndAssert { & .\tentacle.exe ($registerArguments) }

    popd
    Write-Verbose "Tentacle commands complete"
}


function Remove-TentacleRegistration 
{
    param (
        [Parameter(Mandatory=$True)]
        [string]$name,
        [Parameter(Mandatory=$True)]
        [string]$apiKey,
        [Parameter(Mandatory=$True)]
        [string]$octopusServerUrl
    )
  
    $tentacleDir = "${env:ProgramFiles}\Octopus Deploy\Tentacle"
    if ((test-path $tentacleDir) -and (test-path "$tentacleDir\tentacle.exe")) 
    {
        Write-Verbose "Beginning Tentacle deregistration" 
        Write-Verbose "Tentacle commands complete"
        pushd $tentacleDir
        Invoke-AndAssert { & .\tentacle.exe deregister-from --instance "$name" --server $octopusServerUrl --apiKey $apiKey --console }
        popd
    }
    else 
    {
        Write-Verbose "Could not find Tentacle.exe"
    }
}

<#function Invoke-InitialDeploy
{
    param (
        [Parameter(Mandatory=$True)]
        [string]$name,
        [Parameter(Mandatory=$True)]
        [string]$apiKey,
        [Parameter(Mandatory=$True)]
        [string]$octopusServerUrl,
        [Parameter(Mandatory=$True)]
        [string]$Project,
        [Parameter(Mandatory=$True)]
        [string[]]$Environments,
        [string]$Version = "latest",
        [Switch]$Wait = $true
    )

    $octoDL = "http://download.octopusdeploy.com/octopus-tools/2.5.10.39/OctopusTools.2.5.10.39.zip"
    if (Test-Path "$($env:SystemDrive)\Octopus\OctopusTools\$($Project)_initial.txt")
    {
        Write-Verbose "Initial Deployment for $Project already done, nothing to do"
        return
    }

    if ( -not (Test-Path "$($env:SystemDrive)\Octopus\OctopusTools\Octo.exe"))
    {
        if ( -not (Test-Path "$($env:SystemDrive)\Octopus\OctopusTools.zip"))
        {
            Write-Verbose "Downloading OctopusTools from $octoDL"
            Request-File -url $octoDL -saveAs "$($env:SystemDrive)\Octopus\OctopusTools.zip"
        }
        Write-Verbose "Unpacking OctopusTools to $($env:SystemDrive)\Octopus\OctopusTools\"
        Add-Type -assemblyname System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory("$($env:SystemDrive)\Octopus\OctopusTools.zip","$($env:SystemDrive)\Octopus\OctopusTools\")

    }
    pushd "$($env:SystemDrive)\Octopus\OctopusTools\"
    foreach ($environment in $environments)
    {
        Write-Verbose "Deploying Project $Project to environment $environment"
        $deployArguments = @("deploy-release", "--project", $Project, "--deployto", $environment, "--releaseNumber", $Version, "--specificmachines", $env:COMPUTERNAME, "--server", $octopusServerUrl, "--apiKey", $apiKey)
        if ($Wait)
        {
            $deployArguments += "--waitfordeployment"
        }
        Invoke-AndAssert { & .\octo.exe $deployArguments}
    }
    "Done" | Out-File "$($env:SystemDrive)\Octopus\OctopusTools\$($Project)_initial.txt"
}#>

