
Function fn_EnableSSHandShell {

	$host_list = Get-Content "host_list.txt"
	$vcenter = Read-Host -Prompt "Enter vCenter you want to connect to"

	Connect-VIServer $vcenter 

	#enable SSH, do not prompt for user confirmation (-confirm:$false)
	foreach($hosts in $host_list){
		Write-Host -ForegroundColor GREEN "Starting SSH service on " -NoNewline
		Write-Host -ForegroundColor YELLOW "$VMhost"
		Get-VMHostService -VMHost $hosts | Where-Object {($_.Key -eq "TSM-SSH") -and ($_.Running -eq $False)} | Start-VMHostService -confirm:$false
		}

	#enable bash shell
	foreach($hosts in $host_list){
		Write-Host -ForegroundColor GREEN "Starting shell service on " -NoNewline
		Write-Host -ForegroundColor YELLOW "$VMhost"
		Get-VMHostService -VMHost $hosts | Where-Object {($_.Key -eq "TSM") -and ($_.Running -eq $False)} | Start-VMHostService -confirm:$false
	}

	Disconnect-VIServer * -confirm:$false 

}

fn_EnableSSHandShell
