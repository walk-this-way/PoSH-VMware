<#
This script enforces secure boot on an ESXi host.
#>

Function fn_PressAnyKey {
    Write-Host "Ensure you put the host into Maintenance Mode." -ForegroundColor White
    Write-Host "Press " -ForegroundColor Yellow -NoNewLine
    Write-Host "[Enter]" -ForegroundColor Red -NoNewLine
    Write-Host " to Continue..." -ForegroundColor Yellow -NoNewLine
    Read-Host
}

Write-Host "This script requires the host to reboot" -ForegroundColor Red 
Write-Host "This setting cannot be configured until Secure Boot is properly enabled in the BIOS." -ForegroundColor Red
Write-Host "This script will enforce Secure Boot on the ESXi host." -ForegroundColor Red

# Connect to the vCenter server
$vcenter = Read-Host -Prompt "Enter vCenter you want to connect to"
Connect-VIServer $vcenter 

#Check vCenter version
$vCenterVersion = (Get-View ServiceInstance).Content.About.Version
Write-Host "Connected to vCenter $vcenter with version $vCenterVersion"

$VMHosts = Get-VMHost -Location $Location
if ($VMHosts.Count -eq 0) {
    Write-Host "No ESXi hosts found in the location $Location"
    Disconnect-VIServer -Confirm:$false
    exit
}
Write-Host
Write-Host "The following ESXi hosts are in the cluster $Location : "   
Write-Host $VMHosts -Separator "`n" 
Write-Host
Write-Host "You can filter the names of the Hosted being remediated" -ForegroundColor Green
Write-Host
Write-Host "Enter the search string to filter or just press Enter to not filter" -ForegroundColor Green
Write-Host "Filtering must have a * wildcard at the front or back (or both) to match multiple Hosts" -ForegroundColor Green
Write-Host 

$selectedHosts = Read-Host -Prompt "Enter Optional Hostname Filter  " 

if ($selectedHosts -eq "") {
        $selectedHosts = "*"
    }

Write-Host "Filtering Hosts with $selectedHosts" -ForegroundColor Green
Write-Host

$selectedHosts = $selectedHosts -replace '\*','.*'
$VMHosts = $VMHosts | Where-Object { $_.Name -match $selectedHosts }

#If the vCenter version is 6.7, do this
if ($vCenterVersion -eq "6.7.0") {
    Write-Host "This script is not supported on vCenter version 6.7.0, check secure boot status."
    Disconnect-VIServer -Confirm:$false
    exit
}

#If the vCenter version is 7.0, do this
elseif ($vCenterVersion -eq "7.0.0") {
    #Check if Secure Boot is already enabled
    $VMHosts | ForEach-Object {
        $esxcli = Get-EsxCli -VMHost $_
        $arguments = $esxcli.system.settings.encryption.get.CreateArgs()
        $result = $esxcli.system.settings.encryption.get.Invoke($arguments)
        if ($result.requiresecureboot -eq $true) {
            Write-Host "Secure Boot is already enabled on host $($_.Name)" -ForegroundColor Green
        }
        else {
            Write-Host "Enforcing Secure Boot on host $($_.Name)" -ForegroundColor Red
            $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
            $arguments.requiresecureboot = $true
            $esxcli.system.settings.encryption.set.Invoke($arguments)
            Write-Host "Secure Boot has been enforced on host $($_.Name)" -ForegroundColor Green
        }
    }
}
#else, if vCenter version is 8.0, do this
elseif ($vCenterVersion -eq "8.0.0") {
    #Check if Secure Boot is already enabled
    $VMHosts | ForEach-Object {
        $esxcli = Get-EsxCli -VMHost $_
        $arguments = $esxcli.system.settings.encryption.get.CreateArgs()
        $result = $esxcli.system.settings.encryption.get.Invoke($arguments)
        if ($result.requiresecureboot -eq $true) {
            Write-Host "Secure Boot is already enabled on host $($_.Name)" -ForegroundColor Green
        }
        else {
            Write-Host "Enforcing Secure Boot on host $($_.Name)" -ForegroundColor Red
            $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
            $arguments.requiresecureboot = $true
            $esxcli.system.settings.encryption.set.Invoke($arguments)
            Write-Host "Secure Boot has been enforced on host $($_.Name)" -ForegroundColor Green
        }
    }
}

# Evacuate the host and gracefully reboot for changes to take effect.
Write-Host "Host needs to reboot for changes to take effect"
fn_PressAnyKey

#reboot Hosts
$VMHosts | ForEach-Object {
    Write-Host "Restarting the host $($_.Name)"
    Restart-VMHost -VMHost $_ -Confirm:$false
}
#Disconnect from the vCenter server
    Disconnect-VIServer -Confirm:$false