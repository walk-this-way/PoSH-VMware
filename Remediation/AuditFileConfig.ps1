
<# This script will do the following:
	- connect to the vCenter server
	- get all the ESXi hosts in a specific location
    - enable audit logging on the ESXi hosts
    - disconnect vCenter server
 #>

Function fn_ConfigureAuditLogs {

    Write-Host "This is a remediation for ESXI-70-000084, the ESXi Host must enable audit logging" 
    Write-Host "This modification does not require a reboot of the ESXi host."
    Write-Host 


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

    if ($vCenterVersion -eq "6.7") {
        Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level | Set-AdvancedSetting -Value "info"
        Write-Host "Complete"
        Disconnect-VIServer -Confirm:$false
    }
    elseif ($vCenterVersion -eq "7.0") {
        Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level | Set-AdvancedSetting -Value "info"
        Write-Host "Complete"
        Disconnect-VIServer -Confirm:$false
    }
    elseif ($vCenterVersion -eq "8") {
        Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level | Set-AdvancedSetting -Value "info"
        Write-Host "Complete"
        Disconnect-VIServer -Confirm:$false
    }
    else {
        Write-Host "This script is not supported on vCenter version $vCenterVersion, check audit log status."
        Disconnect-VIServer -Confirm:$false
        exit
    }
    Write-Host
    Write-Host
	Write-Host "Audit logs have been set up for the ESXi hosts in the location $selectedHosts"
    Write-Host
    Write-Host
    Write-Host "Disconnecting from the vCenter server..."

    Disconnect-VIServer -Confirm:$false
}

fn_ConfigureAuditLogs