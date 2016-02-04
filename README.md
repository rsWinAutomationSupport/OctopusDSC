This repository contains a PowerShell module with a DSC resource that can be used to install the [Octopus Deploy](http://octopusdeploy.com) Tentacle agent.

## Sample

First, ensure the OctopusDSC module is on your `$env:PSModulePath`. Then you can create and apply configuration like this.

```
Configuration SampleConfig
{
    param ($ApiKey, $OctopusServerUrl, $Environments, $Roles, $ListenPort)
 
    Import-DscResource -Module OctopusDSC
 
    Node "localhost"
    {
        cTentacleAgent OctopusTentacle 
        { 
            Ensure = "Present" 
            State = "Started" 
 
            # Tentacle instance name. Leave it as 'Tentacle' unless you have more 
            # than one instance
            Name = "Tentacle"
 
            # Registration - all parameters required
            ApiKey = $ApiKey
            OctopusServerUrl = $OctopusServerUrl
            Environments = $Environments
            Roles = $Roles
 
            # Optional settings
            ListenPort = $ListenPort
            DefaultApplicationDirectory = "C:\Applications"
            OctopusHomeDirectory = "C:\Octopus"
        }
    }
}
 
SampleConfig -ApiKey "API-ABCDEF12345678910" -OctopusServerUrl "https://demo.octopusdeploy.com/" -Environments @("Development") -Roles @("web-server", "app-server") -ListenPort 10933

Start-DscConfiguration .\SampleConfig -Verbose -wait

Test-DscConfiguration
```

The OctopusDSC module also supports installing the Octopus tentacle with a trusted server thumbprint instead of automatically registering with your Octopus server. This is useful when the Octopus server is not reachable from the Tentacle.

To use this feature apply a configuration like this:

```
Configuration SampleConfig
{
    param ($ListenPort)
 
    Import-DscResource -Module OctopusDSC
 
    Node "localhost"
    {
        cTentacleAgent OctopusTentacle 
        { 
            Ensure = "Present"
            State = "Started"
 
            # Tentacle instance name. Leave it as 'Tentacle' unless you have more 
            # than one instance
            Name = "Tentacle"
            
            # Set AutoRegister to $false to add trusted server thumbprint instead
            AutoRegister = $false
            
            # Octopus server thumbprint required
            OctopusServerThumbprint = '1234567890ABCD1234567789ADBSDGSEYW233SDS'                                      
 
            # Optional settings
            ListenPort = $ListenPort;
            DefaultApplicationDirectory = "C:\Applications"
            OctopusHomeDirectory = "C:\Octopus"
        }
    }
}
 
SampleConfig -ListenPort 10933

Start-DscConfiguration .\SampleConfig -Verbose -wait

Test-DscConfiguration
```

## Settings

When `Ensure` is set to `Present`, the resource will:

 1. Download the Tentacle MSI from the internet
 2. Install the MSI
 3. Configure Tentacle in listening mode on the specified port (10933 by default)
 4. Add a Windows firewall exception for the listening port
 5. Optionally register the Tentacle with your Octopus server, using the registration settings, or add trusted server thumbprint

When `Ensure` is set to `Absent`, the resource will:

 1. Optionally de-register the Tentacle from your Octopus server, using the registration settings
 2. Delete the Tentacle windows service
 3. Uninstall using the MSI

When `State` is `Started`, the resource will ensure that the Tentacle windows service is running. When `Stopped`, it will ensure the service is stopped.

## Drift

Currently the resource only considers the `Ensure` and `State` properties when testing for drift. 

This means that if you set `Ensure` to `Present` to install Tentacle, then later set it to `Absent`, testing the configuration will return `$false`. Likewise if you set the `State` to `Stopped` and the service is running. 

However, if you were to set the `ListenPort` to a new port, the drift detection isn't smart enough to check the old configuration, nor update the registered machine. You'll need to uninstall and reinstall for these other settings to take effect.

## Development
If you are making changes to the module, keep in mind that your changes may not be loaded, as the module gets cached by `WmiPrvSE`. You can use the following command to kill `WmiPrvSE`:

```
Stop-Process -Name WmiPrvSE -Force -ErrorAction SilentlyContinue | out-null
```

