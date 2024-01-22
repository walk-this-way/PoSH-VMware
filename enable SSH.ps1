
Function fn_EnableSSHandShell {

$host_list = Get-Content "host_list.txt"


Connect-VIServer $vcenter 

#enable SSH
foreach($hosts in $host_list){
	Get-VMHostService -VMHost $hosts | Where-Object {$_.Key -eq "TSM-SSH" } | Start-VMHostService -confirm:$false 
}

#enable bash shell
foreach($hosts in $host_list){
	Get-VMHostService -VMHost $hosts | Where-Object {$_.Key -eq "TSM" } | Start-VMHostService -confirm:$false 
}

Disconnect-VIServer * -confirm:$false 

}
fn_EnableSSHandShell
