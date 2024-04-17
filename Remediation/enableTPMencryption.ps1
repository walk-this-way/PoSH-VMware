
<#
This script enables TPM encryption on the ESXi host.
#>

Write-Host "This is a remediation for ESXI-70-000094, the ESXi Host must require TPM-based configuration encryption"

# Connect to the vCenter server
$vcenter = Read-Host -Prompt "Enter vCenter you want to connect to"
Connect-VIServer $vcenter 

$Location = Read-Host -Prompt "Enter the cluster of the ESXi hosts you want to configure audit logs for"

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

Write-Host "Setting up the audit logs for the following ESXi hosts:"
$VMHosts | Select-Object Name

#Check if the TPM encryption is already enabled
foreach ($VMHost in $VMHosts){
    $vmhost = Get-VMHost -Name ; $esxcli = Get-EsxCli -VMHost $vmhost -V2; 
    $esxcli.system.settings.encryption.get.invoke() | Select-Object -ExpandProperty Mode 
    }   
#Enable TPM encryption
$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.settings.encryption.set.CreateArgs()
$arguments.mode = "TPM"
$esxcli.system.settings.encryption.set.Invoke($arguments)

# Evacuate the host and gracefully reboot for changes to take effect.
Write-Host "Host needs to reboot for changes to take effect"
Function fn_PressAnyKey {
    Write-Host "Press " -ForegroundColor Yellow -NoNewLine
    Write-Host "[Enter]" -ForegroundColor Red -NoNewLine
    Write-Host " to Continue..." -ForegroundColor Yellow -NoNewLine
    Read-Host
}
fn_PressAnyKey
#Reboot the host
foreach ($VMHost in $VMHosts){
    Write-Host "Restarting the host $VMHost"
    Restart-VMHost -VMHost $VMHost -Confirm:$false
}

Write-Host
Write-Host
Write-Host "TPM encryption has been enabled for the ESXi hosts in the location $selectedHosts"
Write-Host
Write-Host
