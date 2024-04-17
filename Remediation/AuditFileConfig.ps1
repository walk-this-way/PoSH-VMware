
<# This script will do the following:
	- connect to the vCenter server
	- get all the ESXi hosts in a specific location
    - prompt for audit log path
	- set up the audit logs for each ESXi host in the location
    - disconnect vCenter server
 #>

 Function fn_PressAnyKey {
    Write-Host "Press " -ForegroundColor Yellow -NoNewLine
    Write-Host "[Enter]" -ForegroundColor Red -NoNewLine
    Write-Host " to Continue..." -ForegroundColor Yellow -NoNewLine
    Read-Host
}
Function fn_ConfigureAuditLogs {

    Write-Host "This is a remediation for ESXI-70-000084, the ESXi Host must enable audit logging" 

    Write-Host -ForegroundColor Green "ESXi offers both local and remote audit recordkeeping 
    to meet the requirements of the NIAP Virtualization Protection Profile 
    and Server Virtualization Extended Package. Local records are stored on any accessible local or VMFS path. 
    Remote records are sent to the global syslog servers configured elsewhere.
    To operate in the NIAP validated state, ESXi must enable and properly configure this audit system. 

    Optional: Set the audit log location to persistent storage. 
    This is set to /scratch/auditLog by default and does not normally need to be changed.

    This system is disabled by default."
    Write-Host -ForegroundColor DarkYellow "Note: Audit records can be viewed locally via the /bin/auditLogReader utility over SSH or at the ESXi shell."
    Write-Host
    Write-Host -ForegroundColor DarkYellow "This modification does not require a reboot of the ESXi host."
    Write-Host 


	# Connect to the vCenter server
	$vcenter = Read-Host -Prompt "Enter vCenter you want to connect to"
	Connect-VIServer $vcenter 

	<#
   "Authentication	 /var/log/auth.log	Contains all events related to authentication for the local system.

    ESXi host agent log	 /var/log/hostd.log	Contains information about the agent that manages and configures the ESXi host and its virtual machines.

    Shell log	/var/log/shell.log	Contains a record of all commands typed into the ESXi Shell and shell events (for example, when the shell was enabled).

    System messages	/var/log/syslog.log	Contains all general log messages and can be used for troubleshooting. This information was formerly located in the messages log file.

    vCenter Server agent log	/var/log/vpxa.log	Contains information about the agent that communicates with vCenter Server (if the host is managed by vCenter Server).

    Virtual machines	The same directory as the affected virtual machine's configuration files, named vmware.log and vmware*.log. For example, /vmfs/volumes/datastore/virtual machine/vwmare.log	Contains virtual machine power events, system failure information, tools status and activity, time sync, virtual hardware changes, vMotion migrations, machine clones, and so on.
    
    VMkernel	/var/log/vmkernel.log	Records activities related to virtual machines and ESXi.
    
    VMkernel summary	/var/log/vmksummary.log	Used to determine uptime and availability statistics for ESXi (comma separated).
   
    VMkernel warnings	/var/log/vmkwarning.log	Records activities related to virtual machines.
    
    Quick Boot	/var/log/loadESX.log	Contains all events related to restarting an ESXi host through Quick Boot.
    
    Trusted infrastructure agent	/var/run/log/kmxa.log	Records activities related to the Client Service on the ESXi Trusted Host.
    
    Key Provider Service	/var/run/log/kmxd.log	Records activities related to the vSphere Trust Authority Key Provider Service.
    
    Attestation Service	/var/run/log/attestd.log	Records activities related to the vSphere Trust Authority Attestation Service.
    
    ESX Token Service	/var/run/log/esxtokend.log	Records activities related to the vSphere Trust Authority ESX Token Service.
    
    ESX API Forwarder	/var/run/log/esxapiadapter.log	Records activities related to the vSphere Trust Authority API forwarder."

    #>

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

    
    # Set up the audit logs for each ESXi host in the location
    #$arguments.directory = Read-Host -Prompt "Define the audit log path" #error here

	foreach ($VMHost in $VMHosts) {
		Write-Host "Setting up the audit logs for $VMHost"
		$esxcli = Get-EsxCli -VMHost $VMHost -v2
		$arguments = $esxcli.system.auditrecords.local.set.CreateArgs()
        Write-Host string($arguments.directory)
        fn_PressAnyKey
		#$arguments.directory = $arguments.directory #this is throwing errors
		$arguments.size="100"
		$esxcli.system.auditrecords.local.set.Invoke($arguments)
		$esxcli.system.auditrecords.local.enable.Invoke()
		$esxcli.system.auditrecords.remote.enable.Invoke()
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