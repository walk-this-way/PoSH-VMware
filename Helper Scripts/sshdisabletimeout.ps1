Powershell script to disable ssh timeout in vcenter

Function fn_disableSSHtimeout {

    Write-Host -ForegroundColor RED "If you haven't created a host_list.txt file, stop now and create"
	$host_list = Get-Content "host_list.txt"

    # Connect to vCenter Server
    $vcenter = Read-Host -Prompt "Enter vCenter you want to connect to"
	Connect-VIServer $vcenter 

    # Disable SSH shell timeout for each host in host_list.txt
    foreach($hosts in $host_list){
		Write-Host -ForegroundColor GREEN "Modifying shell timeout for  " -NoNewline
		Write-Host -ForegroundColor YELLOW "$VMhost"
        Get-VMHost $hosts| Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 0 -Confirm:$false
    }
	   

    #disable ssh in vcsa
    #/etc/profile.d/tmout.sh

    #Disable interactive shell timeout for each host in host_list.txt
    foreach($hosts in $host_list){
		Write-Host -ForegroundColor GREEN "Modifying shell interactive timeout for  " -NoNewline
		Write-Host -ForegroundColor YELLOW "$VMhost"	
        Get-VMHost $hosts | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 0 -Confirm:$false
    }

  Disconnect-VIServer -Server $vcenter -Confirm:$false
}
    

fn_disableSSHtimeout