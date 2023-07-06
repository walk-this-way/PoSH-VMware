<#
[Match]
Name=e*

[Network]
Address=10.0.0.95/24
Gateway=10.0.0.250
DNS=10.0.0.250
Domain=

#>
Function fn_getInfo {
  $global:IP = Read-Host "IP Address"
  $global:CIDR = Read-Host "CIRD Mask (ie '24')"  
  $global:Gateway = Read-Host "Gateway"
  $global:DNS = Read-Host "DNS"
  $global:Domain = Read-Host "Domain Suffix"
}
Function fn_BuildNetFile {  
    $global:file = '/etc/systemd/network/10-static-en.network'
    if ((Test-Path -Path $global:file -PathType Leaf)) {
      Write-Host "Networkfile Exists."
      Write-Host "Moving File to BAK"
      $command = 'mv /etc/systemd/network/10-static-en.network /etc/systemd/network/10-static-en.bak'
      Invoke-Expression $command
      Write-Host "File moved"
    }
  Add-Content  -Path $global:file -Value "[Match]"
  Add-Content  -Path $global:file -Value "Name=e*"
  Add-Content  -Path $global:file -Value ""
  Add-Content  -Path $global:file -Value "[Network]"
  Add-Content  -Path $global:file -Value "Address=$global:IP/$global:CIDR"
  Add-Content  -Path $global:file -Value "Gateway=$global:Gateway"
  Add-Content  -Path $global:file -Value "DNS=$global:DNS"
  Add-Content  -Path $global:file -Value "Domain=$global:Domain"
}

Function fn_restartServices {
  $command = "chown systemd-network:systemd-network $global:file"
  Write-Host "Set chown"
  Invoke-Expression $command
  $command = "systemctl restart systemd-networkd"
  Invoke-Expression $command
  Write-Host "Restarted Network Service"
  $comand = "systemctl start sshd"
  Invoke-Expression $command
  Write-Host "SSH Service Started"
}

Clear-Host
fn_getInfo
fn_BuildNetFile
fn_restartServices
exit
