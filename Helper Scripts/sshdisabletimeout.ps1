write a powershell script to disable ssh timeout in vcenter
# Connect to vCenter Server
Connect-VIServer -Server <vCenter_Server_FQDN> -User <username> -Password <password>

# Disable SSH timeout
$esxiShellTimeout = Get-VMHostAdvancedSetting -Name UserVars.ESXiShellTimeOut
$esxiShellTimeout.Value = 0
Set-VMHostAdvancedSetting -Entity $esxiShellTimeout.Entity -Name $esxiShellTimeout.Name -Value 0


#disable ssh in vcsa
#/etc/profile.d/tmout.sh