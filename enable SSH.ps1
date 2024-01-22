
Function fn_EnableSSHandShell {

$host_list = Get-Content "host_list.txt"
$vcenter = Read-Host -Prompt "Enter vCenter you want to connect to"

Connect-VIServer $vcenter 

#enable SSH, do not prompt for user confirmation (-confirm:$false)
foreach($hosts in $host_list){
	Get-VMHostService -VMHost $hosts | Where-Object {$_.Key -eq "TSM-SSH" } | Start-VMHostService -confirm:$false 
}

#enable bash shell
foreach($hosts in $host_list){
	Get-VMHost $hosts | Get-VMHostService | Where { $_.Key -eq "TSM" } | Start-VMHostService
	Get-VMHostService -VMHost $hosts | Where-Object {$_.Key -eq "TSM" } | Start-VMHostService -confirm:$false 
}

Disconnect-VIServer * -confirm:$false 

}
fn_EnableSSHandShell
