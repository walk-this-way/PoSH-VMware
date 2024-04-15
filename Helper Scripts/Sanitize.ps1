<#Function fn_ClearNetwork {
    $file = '/etc/systemd/network/10-static-en.network'
    $command = 'rm $file'
    Invoke-Expression $command
    Add-Content  -Path $file -Value "[Match]"
    Add-Content  -Path $file -Value "Name=e*"
    Add-Content  -Path $file -Value ""
    Add-Content  -Path $file -Value "[Network]"
    Add-Content  -Path $file -Value "Address="
    Add-Content  -Path $file -Value "Gateway="
    Add-Content  -Path $file -Value "DNS="
    Add-Content  -Path $file -Value "Domain="
    Write-Host "Network File Cleared."
}
#>

Function fn_ClearNetwork {
    $file = '/etc/systemd/network/10-static-en.network'
    $command = 'cp $file /etc/systemd/network/10-static-en.network.bak'
    Invoke-Expression $command
    Write-Host "Old network file moved to 10-static-en.network.bak"
    $command = 'echo -e "[Match]"\nName=e*\n\n[Network]\nAddress=\nGateway=\nDNS=\nDomain=\n" >> /etc/systemd/network/10-static-en.network'
    Write-Host "Network File Cleared" 
}

Function fn_clearHostsFile {
    $file = '/etc/hosts*'
    $command = 'rm $file'
    Invoke-Expression $command
    Add-Content  -Path $file -Value "# Begin /etc/hosts (network card version)"
    Add-Content  -Path $file -Value ""
    Add-Content  -Path $file -Value "::1         ipv6-localhost ipv6-loopback"
    Add-Content  -Path $file -Value "[Network]"
    Add-Content  -Path $file -Value "127.0.0.1   localhost.localdomain"
    Add-Content  -Path $file -Value "127.0.0.1   localhost"
    Add-Content  -Path $file -Value "127.0.0.1   Photon5"
    Add-Content  -Path $file -Value ""
    Add-Content  -Path $file -Value "# End /etc/hosts (network card version)"
    Write-Host "Host File Restored."
}

Function fn_ClearOVAFiles {
   $command = "rm /root/ran_customization"
    Invoke-Expression $command
    Write-Host "ran_customization Cleared."
    $command = "rm /root/results/* && rm /results/*"
    Invoke-Expression $command
    Write-Host "Results Cleared."
    $command = "history -c"
    Invoke-Expression $command
    Write-Host "History Cleared."
}

Clear-Host
fn_ClearNetwork
fn_clearHostsFile
fn_ClearOVAFiles
Write-Host "Shutdown Appliance & Export OVF"