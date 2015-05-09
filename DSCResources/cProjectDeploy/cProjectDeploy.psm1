function Invoke-InitialDeploy{
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
    <#if (Test-Path "$($env:SystemDrive)\Octopus\OctopusTools\$($Project)_initial.txt"){
        Write-Verbose "Initial Deployment for $Project already done, nothing to do"
        return
    }#>

    if ( -not (Test-Path "$($env:SystemDrive)\Octopus\OctopusTools\Octo.exe")){
        if ( -not (Test-Path "$($env:SystemDrive)\Octopus\OctopusTools.zip")){
            Write-Verbose "Downloading OctopusTools from $octoDL"
            Request-File -url $octoDL -saveAs "$($env:SystemDrive)\Octopus\OctopusTools.zip"
        }
        Write-Verbose "Unpacking OctopusTools to $($env:SystemDrive)\Octopus\OctopusTools\"
        Add-Type -assemblyname System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory("$($env:SystemDrive)\Octopus\OctopusTools.zip","$($env:SystemDrive)\Octopus\OctopusTools\")

    }
    pushd "$($env:SystemDrive)\Octopus\OctopusTools\"
    foreach ($environment in $environments){
        Write-Verbose "Deploying Project $Project to environment $environment"
        $deployArguments = @("deploy-release", "--project", $Project, "--deployto", $environment, "--releaseNumber", $Version, "--specificmachines", $env:COMPUTERNAME, "--server", $octopusServerUrl, "--apiKey", $apiKey)
        if ($Wait){
            $deployArguments += "--waitfordeployment"
        }
        Invoke-AndAssert { & .\octo.exe $deployArguments}
    }
    "Done" | Out-File "$($env:SystemDrive)\Octopus\OctopusTools\$($Project)_initial.txt"
}
function Get-TargetResource{
    param (
        [Parameter(Mandatory=$True)]
        [string]$apiKey,
        [Parameter(Mandatory=$True)]
        [string]$octopusServerUrl,
        [Parameter(Mandatory=$True)]
        [string]$DeployProject,
        [Parameter(Mandatory=$True)]
        [string[]]$Environments,
        [string]$DeployVersion = "latest",
        [Switch]$Wait = $true
    )
}
function Test-TargetResource{
    param (
        [Parameter(Mandatory=$True)]
        [string]$apiKey,
        [Parameter(Mandatory=$True)]
        [string]$octopusServerUrl,
        [Parameter(Mandatory=$True)]
        [string]$DeployProject,
        [Parameter(Mandatory=$True)]
        [string[]]$Environments,
        [string]$DeployVersion = "latest",
        [Switch]$Wait = $true
    )
    if (Test-Path "$($env:SystemDrive)\Octopus\OctopusTools\$($Project)_initial.txt"){
        Write-Verbose "Initial Deployment for $Project already done, nothing to do"
        return $True
    }
    else{return $false}
}
function Set-TargetResource{
    param (
        [Parameter(Mandatory=$True)]
        [string]$apiKey,
        [Parameter(Mandatory=$True)]
        [string]$octopusServerUrl,
        [Parameter(Mandatory=$True)]
        [string]$DeployProject,
        [Parameter(Mandatory=$True)]
        [string[]]$Environments,
        [string]$DeployVersion = "latest",
        [Switch]$Wait = $true
    )

    if ($DeployVersion -and $DeployProject){
        Invoke-InitialDeploy -name $Name -apiKey $ApiKey -octopusServerUrl $octopusServerUrl -Environments $Environments -Project $project -Version $DeployVersion -Wait
    }
	else{
        Invoke-InitialDeploy -name $Name -apiKey $ApiKey -octopusServerUrl $octopusServerUrl -Environments $Environments -Project $project -Wait
    }
}