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
        
        [bool]$AutoRegister,
        [string]$ApiKey,
        [string]$OctopusServerUrl,
        [string[]]$Environments,
        [string[]]$Roles,
        [string]$DefaultApplicationDirectory,
        [int]$ListenPort,        
        [string]$OctopusHomeDirectory,
        [string]$OctopusServerThumbprint
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
        
        [bool]$AutoRegister = $true,
        [string]$ApiKey,
        [string]$OctopusServerUrl,
        [string[]]$Environments,
        [string[]]$Roles,
        [string]$DefaultApplicationDirectory = "$($env:SystemDrive)\Applications",
        [int]$ListenPort = 10933,
        [string]$OctopusHomeDirectory = "$($env:SystemDrive)\Octopus",
        [string]$OctopusServerThumbprint        
    )

    if ($Ensure -eq "Absent" -and $State -eq "Started") 
    {
        throw "Invalid configuration: service cannot be both 'Absent' and 'Started'"
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
        if ($AutoRegister) {
            Remove-TentacleRegistration -name $Name -apiKey $ApiKey -octopusServerUrl $OctopusServerUrl
        }
        
        $serviceName = (Get-TentacleServiceName $Name)
        Write-Verbose "Deleting service $serviceName..."
        Invoke-AndAssert { & sc.exe delete $serviceName }
        
        # Uninstall msi
        Write-Verbose "Uninstalling Tentacle..."
        $tentaclePath = "$OctopusHomeDirectory\Tentacle.msi"
        $msiLog = "$OctopusHomeDirectory\Tentacle.msi.uninstall.log"
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
        New-Tentacle -name $Name -AutoRegister $AutoRegister -apiKey $ApiKey -octopusServerUrl $OctopusServerUrl `
            -port $ListenPort -environments $Environments -roles $Roles -DefaultApplicationDirectory $DefaultApplicationDirectory `
            -OctopusHomeDirectory $OctopusHomeDirectory -OctopusServerThumbprint $OctopusServerThumbprint
        Write-Verbose "Tentacle installed!"
    }

    if ($State -eq "Started" -and $currentResource["State"] -eq "Stopped") 
    {
        $serviceName = (Get-TentacleServiceName $Name)
        Write-Verbose "Starting $serviceName"
        Start-Service -Name $serviceName
    }

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
        
        [bool]$AutoRegister,
        [string]$ApiKey,
        [string]$OctopusServerUrl,
        [string[]]$Environments,
        [string[]]$Roles,
        [string]$DefaultApplicationDirectory,
        [int]$ListenPort,    
        [string]$OctopusHomeDirectory,
        [string]$OctopusServerThumbprint
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
function Get-MyPublicIPAddress
{
    Write-Verbose "Getting public IP address"
    $downloader = new-object System.Net.WebClient
    $ip = $downloader.DownloadString("http://ifconfig.me/ip")
    return $ip
}
 
function New-Tentacle 
{
    param (
        [Parameter(Mandatory=$True)]
        [string]$name,
        [Parameter(Mandatory=$True)]
        [bool]$AutoRegister,
        [string]$apiKey,
        [string]$octopusServerUrl,
        [string[]]$environments,
        [string[]]$roles,
        [int] $port,
        [Parameter(Mandatory=$True)]
        [string]$DefaultApplicationDirectory,
        [Parameter(Mandatory=$True)]
        [string]$OctopusHomeDirectory,
        [string]$OctopusServerThumbprint
    )
 
    if ($port -eq 0) 
    {
        $port = 10933
    }
    if ($AutoRegister -and (!$apiKey -or !$octopusServerUrl -or !$environments -or !$roles)) 
    {
        throw "When creating Tentacle using AutoRegister=true the follow parameters must be provided: apiKey, octopusServerUrl, environments, roles"
    }
    if (!$AutoRegister -and !$OctopusServerThumbprint) 
    {
        throw "When creating Tentacle using AutoRegister=false the follow parameters must be provided: OctopusServerThumbprint"
    }
    
    Write-Verbose "Beginning Tentacle installation" 
  
    #$tentacleDownloadUrl = "http://octopusdeploy.com/downloads/latest/OctopusTentacle64"
    # Temporarily using version 2.6 instead to be compatible with 2.x server
    $tentacleDownloadUrl = "https://download.octopusdeploy.com/octopus/Octopus.Tentacle.2.6.5.1010-x64.msi"
            
    if ([IntPtr]::Size -eq 4) 
    {
        #$tentacleDownloadUrl = "http://octopusdeploy.com/downloads/latest/OctopusTentacle"
        # Temporarily using version 2.6 instead to be compatible with 2.x server
        $tentacleDownloadUrl = "https://download.octopusdeploy.com/octopus/Octopus.Tentacle.2.6.5.1010.msi"
    }

    mkdir $OctopusHomeDirectory -ErrorAction SilentlyContinue

    $tentaclePath = "$OctopusHomeDirectory\Tentacle.msi"
    if ((test-path $tentaclePath) -ne $true) 
    {
        Write-Verbose "Downloading latest Octopus Tentacle MSI from $tentacleDownloadUrl to $tentaclePath"
        Request-File $tentacleDownloadUrl $tentaclePath
    }
  
    Write-Verbose "Installing MSI..."
    $msiLog = "$OctopusHomeDirectory\Tentacle.msi.log"
    $msiExitCode = (Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $tentaclePath /quiet /l*v $msiLog" -Wait -Passthru).ExitCode
    Write-Verbose "Tentacle MSI installer returned exit code $msiExitCode"
    if ($msiExitCode -ne 0) 
    {
        throw "Installation of the Tentacle MSI failed; MSIEXEC exited with code: $msiExitCode. View the log at $msiLog"
    }
 
    $windowsFirewall = Get-Service -Name MpsSvc   
    if ($windowsFirewall.Status -eq "Running")
    {
        Write-Verbose "Open port $port on Windows Firewall"
        Invoke-AndAssert { & netsh.exe advfirewall firewall add rule protocol=TCP dir=in localport=$port action=allow name="Octopus Tentacle: $Name" }
    }
    else
    {
        Write-Verbose "Windows Firewall Service is not running... skipping firewall rule addition"
    }
            
    Write-Verbose "Configuring Tentacle"
  
    pushd "${env:ProgramFiles}\Octopus Deploy\Tentacle"

    Invoke-AndAssert { & .\tentacle.exe create-instance --instance $name --config "$OctopusHomeDirectory\$Name\Tentacle.config" --console }
    Invoke-AndAssert { & .\tentacle.exe configure --instance $name --home $OctopusHomeDirectory --console }
    Invoke-AndAssert { & .\tentacle.exe configure --instance $name --app $DefaultApplicationDirectory --console }
    Invoke-AndAssert { & .\tentacle.exe configure --instance $name --port $port --console }
    if (!$AutoRegister) 
    {
        Write-Verbose "Adding trusted server thumbprint $OctopusServerThumbprint"
        Invoke-AndAssert { & .\tentacle.exe configure --instance $Name --trust $OctopusServerThumbprint --console }
    }
    Invoke-AndAssert { & .\tentacle.exe new-certificate --instance $name --console }
    Invoke-AndAssert { & .\tentacle.exe service --install --instance $name --console }

    if ($AutoRegister) 
    {
        $ipAddress = Get-MyPublicIPAddress
        $ipAddress = $ipAddress.Trim()
        Write-Verbose "Public IP address: $ipAddress"
        Write-Verbose "Automatically registering Tentacle with server $octopusServerUrl"
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
    }
    
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

