<#
This script enforces secure boot on an ESXi host.
#>

Write-Host -ForegroundColor DarkRed "This script requires the host to reboot"

"This setting cannot be configured until Secure Boot is properly enabled in the BIOS.

From an ESXi shell, run the following command:

# esxcli system settings encryption set --require-secure-boot=true

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.settings.encryption.set.CreateArgs()
$arguments.requiresecureboot = $true
$esxcli.system.settings.encryption.set.Invoke($arguments)

Evacuate the host and gracefully reboot for changes to take effect."