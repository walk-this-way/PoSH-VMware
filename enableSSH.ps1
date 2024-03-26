
Function fn_EnableSSHandShell {

	#Create a file to store the list of ESXi hosts
	Write-Host -ForegroundColor RED "Creating the host_list.txt file of all ESXi hosts in the vCenter..."
	$vcenter = Read-Host -Prompt "Enter vCenter you want to connect to"
	Connect-VIServer $vcenter 
	
	Write-Host -ForegroundColor GREEN "Do you want to enable SSH and Shell on all ESXi hosts in the vCenter? (Y/N)"
	$answer = Read-Host
	if($answer -eq "N"){
		Write-Host -ForegroundColor RED "What host do you want to enable SSH and Shell on?"
		$VMhost = Read-Host
		$VMhost | Out-File host_list.txt
		exit
	}
	if($answer -eq "Y"){
		Write-Host -ForegroundColor GREEN "Creating the host_list.txt file of all ESXi hosts in the vCenter..."
	}

	Get-VMHost | Select Name | Out-File host_list.txt
		$host_list = Get-Content "host_list.txt"
	
	#enable SSH, do not prompt for user confirmation (-confirm:$false)
	foreach($hosts in $host_list){
		Write-Host -ForegroundColor GREEN "Starting SSH service on " -NoNewline
		Write-Host -ForegroundColor YELLOW "$VMhost"
		Get-VMHostService -VMHost $hosts | Where-Object {($_.Key -eq "TSM-SSH") -and ($_.Running -eq $False)} | Start-VMHostService -confirm:$false
		}

	#enable bash shell, do not prompt for user confirmation (-confirm:$false)
	foreach($hosts in $host_list){
		Write-Host -ForegroundColor GREEN "Starting shell service on " -NoNewline
		Write-Host -ForegroundColor YELLOW "$VMhost"
		Get-VMHostService -VMHost $hosts | Where-Object {($_.Key -eq "TSM") -and ($_.Running -eq $False)} | Start-VMHostService -confirm:$false
	}

	Disconnect-VIServer * -confirm:$false 

}

fn_EnableSSHandShell
