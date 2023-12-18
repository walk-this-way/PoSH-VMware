Function fn_GetvCenterCreds {
    # Clear-Host
    
    # If connected to a vCenter give option to switch. 
      if ($global:defaultVIServer -ne "Not Connected") {
        Write-Host "Currently connected to: " -ForegroundColor Green -NoNewline
        Write-Host $global:defaultVIServer -ForegroundColor Yellow 
        Write-Host
        $ChangevCenter = Read-Host "Stay connected to this vCenter (Y/N)?"
        if ($ChangevCenter -eq 'N') {
          Disconnect-VIServer -Server $global:defaultVIServer
          $global:defaultVIServer = "Not Connected"
          fn_GetvCenterCreds
        }
      }
    
      if ($global:DefaultVIServer -eq "Not Connected") {
        Clear-Host
        Write-Host "vCenter Information:" -ForegroundColor Green
        Write-Host
        $vServer = Read-Host "Enter the FQDN of the vCenter Server " 
        Write-Host "Testing ability to find $vServer..."
        Write-Host
        if (!(Test-Connection -ComputerName $vServer -Quiet -Count 2)) {
          Write-Host "Unable to find $vServer" -ForegroundColor Red
          Write-Host "Verify correct FQDN, DNS, and IP Configuration and try again." -ForegroundColor Red
          Write-host
          fn_PressAnyKey
          fn_GetvCenterCreds
        } 
        Write-Host "Connectivity to $vServer verified." -ForegroundColor Green
        Write-Host
        Write-Host "Enter vCenter SSO Admin Credentials (administrator@vsphere.local): " -ForegroundColor Green -NoNewline
        $global:VCcreds = Get-Credential
        Connect-VIserver -Server $vServer -Credential $global:VCcreds
        $global:VCuser= $global:VCcreds.UserName.ToString()
        $global:VCpass = $global:VCcreds.GetNetworkCredential().password
        if ($global:DefaultVIServer -eq "Not Connected") {fn_GetvCenterCreds}
    
      # Set Inspec ENV Vars
        $env:VISERVER=$global:defaultVIServer
        $env:VISERVER_USERNAME=$global:VCuser
        $env:VISERVER_PASSWORD=$global:VCpass
        $env:NO_COLOR=$true
        #Connect-SsoAdminServer -server $env:VISERVER -user $env:VISERVER_USERNAME -password $env:VISERVER_PASSWORD -SkipCertificateCheck
      }
    # Re-Do Bad Login
      if (!$defaultVIServer) {
      Clear-Host
      Write-Host "Invalid Login" -ForegroundColor red | fn_PressAnyKey | fn_GetvCenterCreds
      }
    
    # Confirm Credentials
      Write-Host "vCenter Credentials Verified." -ForegroundColor Green
    
    # Get vCenter Version
      $global:vCVersion = $global:DefaultVIServer.Version
      Write-Host "vCenter Version: "$global:vCVersion
    
    # Get vCenter API Token
      $command = "curl -s -k -X POST -H 'Accept: application/json' --basic -u "+$global:VCuser+":"+$global:VCpass+" https://$global:defaultVIServer/rest/com/vmware/cis/session"
      $global:vCAPIToken = Invoke-Expression $command
      $global:vCAPIToken = $global:vCAPIToken.Remove(0,9) -replace ".{1}$"
      $global:vCAPIToken = $global:vCAPIToken -replace '[""]','' 

    # Confirm vCenter API token
      Write-Host "vCenter Version: " $gloval:vCAPIToken
    
    # Get and set SSH Service on vCenter
      <#if ($global:vCVersion -lt '8') {
        $apipath = "api/appliance/access/ssh"
      }
      if ($global:vCVersion -lt '7.0.2') {
        $apipath = "rest/appliance/access/ssh"
      }
      $command = "curl -s -k -H 'vmware-api-session-id: $global:vCAPIToken' https://$global:defaultVIServer/$apipath"
      $vCSSH= Invoke-Expression $command
      Write-Host "vCenter SSH Status: "$vCSSH -ForegroundColor Green
      if (!$vCSSH) {
        $command = "curl -k -s -X PUT -H 'vmware-api-session-id: $global:vCAPIToken' -H 'Content-Type: application/json' -d '{""enabled"":true}' https://$global:defaultVIServer/api/appliance/access/ssh"
        Write-Host "Enabeling SSH on vCenter "$global:DefaultVIServer -ForegroundColor Green
        Invoke-Expression $command
        $command = "curl -s -k -H 'vmware-api-session-id: $global:vCAPIToken' https://$global:defaultVIServer/api/appliance/access/ssh"
        $vCSSH= Invoke-Expression $command    
      }
    #>
    
      DO {
      #  Clear-Host
      #  Write-Host "vCenter SSH for "$defaultVIServer" is "$vCSSH
      #  Write-Host "vC SSH Connection: "$global:vCSSSHConnection.Connected
    
    # Get vCenter SSH Creds for root
        Get-SSHTrustedHost | Remove-SSHTrustedHost #removes saved trusted keys
        Write-Host "Enter vCenter SSH Credentials (root): " -ForegroundColor Green
        $global:VCSSHcreds = Get-Credential
        $global:VCSSHuser= $global:VCSSHCreds.UserName.ToString()
        $global:VCSSHpass = $global:VCSSHCreds.GetNetworkCredential().password
    
    # Enable SHELL for Root
     <#   Write-Host "Enabeling Shell for root"
        if ($global:vCVersion -eq "7") {
        $command = "curl -k -s -o -X PUT -H 'vmware-api-session-id: $global:vCAPIToken' -H 'Content-Type: application/json' -d '{""enabled"":true}' https://$global:defaultVIServer/api/appliance/access/shell"
        }
        if ($global:vCVersion -eq "8") {
        $command = "curl -k -s -o -X PUT -H 'vmware-api-session-id: $global:vCAPIToken' -H 'Content-Type: application/json' -d '{""config"":{""enabled"":true,""timeout"":10}}' https://$global:defaultVIServer/rest/appliance/access/shell"
        }
        # Write-Host "With Command: "$command
        Invoke-Expression $command
        Write-Host
     #>
    # Test vCenter SSH
        Write-Host "Testing SSH connection to "$global:defaultVIServer
        $global:vCSSSHConnection = New-SSHSession -ComputerName $global:defaultVIServer -Credential $global:VCSSHCreds -AcceptKey:$true -ErrorAction ignore
        Write-Host "Session : " $global:vCSSSHConnection
        if (!$global:vCSSSHConnection.Connected) {
          Write-Host "SSH Credentials Failed for vCenter." -ForegroundColor Red
          Write-Host "Configure SSH services on VC and try again" -ForegroundColor Red
          fn_PressAnyKey  
          fn_GetvCenterCreds
        } 
      } while (!$global:vCSSSHConnection.Connected)
      Write-Host "vCenter SSH bin/bash Test Successful " $result -ForegroundColor Green
      Write-Host
      fn_PressAnyKey
    }
    
    Function fn_GetESXCreds {
    # Clear-Host
    # Determine if ESX Credentials are Valid
    
    Write-Host "Enter ESX SSH Credentials"
    <#  if ($global:ESXSSHuser -ne 'blank') { 
        Write-Host "Currently using: " -ForegroundColor Green -NoNewline
        Write-Host $global:ESXSSHuser -ForegroundColor Yellow 
        $passlength = ($global:ESXSSHpass.Length)-4
        $obs_SSHPass = $global:ESXSSHpass.substring(0,2) 
        For ($i = 0; $i -lt $passlength; $i++) {
              $obs_SSHPass += "*"
            }
        $obs_SSHPass = $obs_SSHPass.Substring($passlength,-2)
        Write-Host "With password: "$obs_SSHPass ForegroundColor Yellow -NoNewline
        Write-Host
        $ChangeESXCreds = Read-Host "Continue with this SSH Account (Y/N)?" -ForegroundColor Green -NoNewline
        if ($ChangeESXCreds -eq 'N') {
          $global:ESXSSHCreds = 'blank'
          fn_GetESXCreds
        } else {
      #>
        Write-Host "ESX Host Information:" -ForegroundColor Green
        Write-Host
        Write-Host "This process requires SSH ROOT access to the ESX Hosts " -ForegroundColor Green -NoNewLine
        Write-Host "!!" -ForegroundColor Red
        Write-Host
        Write-Host "Enter the root Credentials for the ESX Hosts" -ForegroundColor Green -NoNewLine
        $global:ESXSSHCreds = Get-Credential
        $global:ESXSSHuser= $global:ESXSSHCreds.UserName.ToString()
        $global:ESXSSHpass = $global:ESXSSHCreds.GetNetworkCredential().password
        $env:VISERVER=$global:DefaultVIServer
        $env:VISERVER_USERNAME=$global:VCuser
        $env:VISERVER_PASSWORD=$global:VCpass
        Write-Host
        Write-Host "Verifying SSH Connectivity to Hosts..." -ForegroundColor Yellow
        Write-Host
        $allHosts = Get-VMHost | Sort-Object Name
          foreach ($VMHost in $allHosts) {
              $result = "x"
              $command = 'pwd'
              $color = "Green"
              if(!(fn_SSH_Check))
              {
                $sshon = 0
                fn_SSH_ON
              }
            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true -ErrorAction ignore
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output
            $result |  Out-File -FilePath /results/ssh_results.txt -Append Get-Content -Path /results/ssh_results.txt
            if ($result -eq "x") {
              Write-Host $VMHost "- FAIL" -ForegroundColor Red
              
            } else {
              Write-Host $VMHost "- $result Passed" -ForegroundColor Green
            }
            if ($sshon -eq 0) {fn_SSH_OFF}
          }
          fn_PressAnyKey
        }   
    
    fn_GetvCenterCreds
    fn_GetESXCreds