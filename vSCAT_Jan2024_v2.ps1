<#
Version Notes
Teri's updates : NSX 4.x hard coded, added controls to main menu (VM, Host scans)
#>

# Set / Clear all variables 
$global:date = (Get-date).tostring('dd-MM-yyyy-hh-mm')
$UserDomain = ""
$global:allVM = ""
$global:UnnecessaryHardware = "VirtualUSBController|VirtualUSBXHCIController|VirtualParallelPort|VirtualFloppy|VirtualSerialPort|VirtualHdAudioCard|VirtualAHCIController|VirtualEnsoniq1371|VirtualCdrom"
$global:SDDCmgr = "Not Connected"
$global:sddcCreds = ""
$global:defaultVIServer = "Not Connected"
$global:DefaultVIServers = ""
$global:VCcreds = ""
$global:NSXmgr = ""
$global:ESXSSHCreds = ""
$global:ESXSSHuser = "blank"


Function fn_GetAppIP {
  If (Test-Path -Path /etc/systemd/network) {
# Pull IP Address from Photon OS Appliance for SSH Firewall  
  $global:AppIPaddress = Invoke-Expression "cat /etc/systemd/network/*.network | grep Address"
  $global:AppIPAddress = ($global:AppIPaddress |  Select-String -Pattern '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' -AllMatches).Matches.Value
  # Write-Host "IP=" $global:AppIPaddress
  }
}

Function fn_Welcome {
    Clear-Host
    Write-Host "
This tool will scan selected VMware Appliance settings and determine if these settings 
are configured to meet VMware's Best Practices for Security, NIST 800-53 Configurations, 
and DISA STIG Compliance. 

The following information will be required to complete the assessment. 

Environment Services:
	- DNS must be configured for all appliances being assessed
	- NTP Server (IP or FQDN) 
	- SysLog Server (IP or FQDN) [use vCenter info if unavailable]
	- SFTP Server (IP or FQDN) [use vCenter info if unavailable]

vCenter:
  - IP Address or FQDN of vCenter Server
  - SSO Administrtor Account Credentials (administrator@vsphere.local)
  - root account credentials for SSH operations.
  - root BASH shell configured (https://kb.vmware.com/s/article/2100508)
  - Enable root login over SSH 
  (https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/v2v_guide/preparation_before_the_p2v_migration-enable_root_login_over_ssh)
	
vSphere (ESX):
	- root credentials for SSH operations
  - all Hosts must have the same root password

VMware Cloud Foundations (vCF):

	- IP Address or FQDN of SDDC Manager
	- SSH enabled on SDDC Manager
	- root account credentials for SSH operations
	- SDDC Manager SSO Administrtor Account Credentials (administrator@vsphere.local)

NSX-T:
	- IP Address or FQDN of NSX-T Manager
	- SSH enabled on NSX Managers
	- root account credentials for SSH operations
	- admin account credentials for API operations
    " -ForegroundColor Green
    fn_PressAnyKey
}

Function fn_Lockdown_off {
    Write-Host "Disabling Lockdown Mode"
    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {
      Write-Host $VMHost
      ($VMhost | Get-View).ExitLockdownMode()
    }
}

Function fn_Lockdown_on {
    Write-Host "Enabling Lockdown Mode"
    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {
      Write-Host $VMHost
      ($VMhost | Get-View).EnterLockdownMode()
    }
}


#########################################################################
####################      STIG SCAN FUNCTIONS      #######################
#########################################################################

Function fn_sddcscanner { 
  Write-Host "Running scan of VCF Environment:"
  $jsonOutput = "/results/VCF_Scan_"+$global:SDDCmgr+"_"+$global:date+".json"
  Write-Host "Saving results to: "$jsonOutput
  $profilePath = '/root/dod-compliance-and-automation/vcf/4.x/inspec/vmware-vcf-sddcmgr-4x-stig-baseline'
  $command = "inspec exec $profilePath/. -t ssh://'$global:SDDCuser'@'$global:SDDCmgr' --password '$global:SDDCpass' --input-file='$profilePath/inputs-vcf-sddc-mgr-4x.yml' --show-progress --reporter=cli json:.$jsonOutput"
  Invoke-Expression $command
  Write-Host "VCF Scan Complete!"
  }

Function fn_ESXiscanner { 
  Write-Host "Running ESX Host Scan:"
    $env:VISERVER=$global:defaultVIServer
    $env:VISERVER_USERNAME=$global:VCuser
    $env:VISERVER_PASSWORD=$global:VCpass
    $env:NO_COLOR=$true
    $jsonOutput = "/results/ESX_Scan_"+$global:defaultVIServer+"_"+$global:date+".json"
  Write-Host "Saving results to: "$jsonOutput
  $profilePath ="/root/dod-compliance-and-automation/vsphere/"+$global:vCVersion[0]+".0/vsphere/inspec/vmware-vsphere-"+$global:vCVersion[0]+".0-stig-baseline/esxi"
  $command ="inspec exec $profilePath/. -t vmware:// --input-file $profilePath/inputs-example.yml --show-progress --reporter=cli json:$jsonOutput"  
  Invoke-Expression $command
  Write-Host "ESX Scan Complete!"
}

Function fn_VMscanner { 
    Write-Host "Running VM Host Scan:"
      $env:VISERVER=$global:defaultVIServer
      $env:VISERVER_USERNAME=$global:VCuser
      $env:VISERVER_PASSWORD=$global:VCpass
      $env:NO_COLOR=$true
    $jsonOutput = "/results/VM_"+$global:defaultVIServer+"_"+$global:date+".json"
    Write-Host "Saving results to: "$jsonOutput
    $profilePath ="/root/dod-compliance-and-automation/vsphere/"+$global:vCVersion[0]+".0/vsphere/inspec/vmware-vsphere-"+$global:vCVersion[0]+".0-stig-baseline/vm"
    $command ="inspec exec $profilePath/. --show-progress -t ssh://"+$global:NSXRootUser+"@"+$global:NSXmgr+" --password '"+$global:NSXRootPass+"' --input-file /root/dod-compliance-and-automation/nsx/3.x/inspec/vmware-nsxt-3.x-stig-baseline-master/inputs-nsxt-3.x.yml --reporter=cli json:$jsonOutput" 
    Invoke-Expression $command
    Write-Host "VM Scan Complete!"
  }

Function fn_nsxscanner { 

  <#
  Need to write if/then check for NSX version
  #>
  Write-Host "Running scan of NSX Environment:"
  $jsonOutput = "/results/NSX_Scan_"+$global:NSXmgr+"_"+$global:defaultVIServer+"_"+$global:date
  Write-Host "Saving results to: "$jsonOutput
  $profilePath = '/root/dod-compliance-and-automation/nsx/3.x/inspec/vmware-nsxt-3.x-stig-baseline-master'
  $command ="inspec exec $profilePath/. --show-progress -t ssh://"+$global:NSXRootUser+"@"+$global:NSXmgr+" --password '"+$global:NSXRootPass+"' --input-file /root/dod-compliance-and-automation/nsx/3.x/inspec/vmware-nsxt-3.x-stig-baseline-master/inputs-nsxt-3.x.yml --show-progress --reporter=cli json:$jsonOutput"
  Invoke-Expression $command
  Write-Host "NSX-T Scan Complete!"
}
  
Function fn_vCscanner { 
  Write-Host "Running vCenter Scan Environment:"
  $jsonOutput = "/results/vCenter_Scan_"+$global:DefaultVIServer+"_"+$global:date+".json"
  Write-Host "Saving results to: "$jsonOutput
  $profilePath ="/root/dod-compliance-and-automation/vsphere/"+$global:vCVersion[0]+".0/vsphere/inspec/vmware-vsphere-"+$global:vCVersion[0]+".0-stig-baseline/vcenter"
  $command ="inspec exec $profilePath/. -t ssh://"+$global:VCSSHuser+"@"+$global:DefaultVIServer+" --password '"+$global:VCSSHpass+"' --show-progress --reporter=cli json:"+$jsonOutput
  Invoke-Expression $command
  Write-Host "vCenter Scan Complete!"
}

Function fn_SSH_Check {
# Check to see if SSH is already on and set a variable to leave it on after command is run.
  $serviceStatus = Get-VMHostService -VMHost $VMHost | Where-Object {$_.Key -eq "TSM-SSH"} | Select-Object Running
  if ($serviceStatus.Running) {return $true} else {return $false}
}

Function fn_SSH_ON {
# Turn ESX Host SSH Service on
  $VMhost | Get-VmHostService | Where-Object {$_.key -eq "TSM-SSH"} | Start-VMHostService -Confirm:$false | Out-Null
}

Function fn_SSH_OFF {
# Turn ESX Host SSH Service OFF
  $VMhost | Get-VmHostService | Where-Object {$_.key -eq "TSM-SSH"} | Stop-VMHostService -Confirm:$false | Out-Null
}

Function fn_SSH_Firewall_AddIP {
# Add vSCAT Applicane IP to Host SSH Firewall
  fn_GetAppIP
  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {
    Write-Host "Adding IP to $VMHost"

# Check if Host SSH Firewall Enabled
    $SSHFirewall = (Get-VMHost -Name $VMHost) | Get-VMHostFirewallException  | Where {$_.Name -eq "SSH Server"} | Select-Object -ExpandProperty Enabled
    $esxcli = Get-Esxcli -VMHost $VMHost

# Check if SSH Firewall is Enabled is there and IP Allowed List
    If ($SSHFirewall -eq "True") {
      $AllowedIPs = $esxcli.network.firewall.ruleset.allowedip.list("sshServer").AllowedIPAddresses
      if ($AllowedIPs -eq "All") {
        # If All IPs Allowed- do nothing
          Write-Host "Allowed IPs: $AllowedIPs - No Changes Made"
      }
      if ($AllowedIPs -match $global:AppIPaddress) {
          # If the appliance is already there- do nothing
          Write-Host "$global:AppIPaddress already exists in Allowed IPs - No Changes Made" -ForegroundColor Green
      } else {
          # Add the appliance IP to the Allowed IP Address List.  
          $esxcli.network.firewall.ruleset.allowedip.add("$global:AppIPaddress", "sshServer") | Out-Null
          Start-Sleep -Seconds 2
      }
    }
  }
}

Function fn_SSH_Firewall_RemoveIP {
  fn_GetAppIP
  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {
# Check if Host SSH Firewall Enabled
    $SSHFirewall = (Get-VMHost -Name $VMHost) | Get-VMHostFirewallException  | Where {$_.Name -eq "SSH Server"} | Select-Object -ExpandProperty Enabled
    $esxcli = Get-Esxcli -VMHost $VMHost

# If SSH Firewall is Enabled is there and IP Allowed List
    If ($SSHFirewall -eq "True") {
      $AllowedIPs = $esxcli.network.firewall.ruleset.allowedip.list("sshServer").AllowedIPAddresses
      if ($AllowedIPs -eq "All") {
        # If All IPs Allowed- do nothing
          Write-Host "Allowed IPs: $AllowedIPs - No Changes Made"
      }
      if ($AllowedIPs -match $global:AppIPaddress) {
        # If the appliance is listed remove it from the list. 
          Write-Host "Removing $global:AppIPaddress from $VMHost Firewall" -ForegroundColor Green
          $esxcli.network.firewall.ruleset.allowedip.remove("$global:AppIPaddress", "sshServer") | Out-Null
          Start-Sleep -Seconds 2
      } else {
        # If the appliance isn't on the list- do nothing
          Write-Host "$global:AppIPaddress does not exists in Allowed IPs - No Changes Made" -ForegroundColor Green
          }
      }
    }
}

Function fn_Write_Results_to_CSV {
  $csv = Import-Csv $global:csvFile
# Loop through all the CSV rows and insert a new column and array data (if available)
  for ($i = 0; $i -lt $csv.Count; $i++) {
      $value = if ($i -lt $global:result_array.Count) { $global:result_array[$i] } else { $null }
      $csv[$i] | Add-Member -MemberType NoteProperty -Name $global:result_array[0] -Value $value -Force
  }
# Export the updated CSV file
  $csv | Export-Csv -Path $global:csvFile -NoTypeInformation -Force
}

#########################################################################
################      vCENTER CONTROL FUNCTIONS      ####################
#########################################################################

Function GET-vCENTER-VERSION {
  $global:VMWConfig='vCenter Version'
  $global:description='Determine Version'
  $global:NISTcit='N/A'
  $global:finding='Less than 7'
  $global:xResult='7'
  $global:command='$Global:DefaultVIServers.version'
  fn_Print_vCenter_Control_Info
  $result = Invoke-Expression $global:command.tostring()
  Write-Host $Global:DefaultVIServers -NoNewLine
  if ($result -lt $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result
  Write-Host `t`t`t$result -ForegroundColor $fgColor
  $global:result_array = $global:result_array+$result
}

Function GET-vCENTER-BUILD {
  $global:VMWConfig='vCenter Build'
  $global:description='Determine Build Number'
  $global:NISTcit='N/A'
  $global:finding='Consistant'
  $global:xResult='Consistant'
  $global:command='$Global:DefaultVIServers.build'
  fn_Print_vCenter_Control_Info
  $result = Invoke-Expression $global:command.tostring()
  Write-Host $Global:DefaultVIServers -NoNewLine
  if ($result -lt $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result
  Write-Host `t`t`t$result -ForegroundColor $fgColor
  $global:result_array = $global:result_array+$result
}

Function VMCH-70-000007 {
    $global:VMWConfig='VMCH-70-000007'
    $global:description='Host Guest File System (HGFS) file transfers must be disabled on the virtual machine (VM).'
    $global:NISTcit='CM-6 b'
    $global:finding='If the virtual machine advanced setting "isolation.tools.hgfsServerSet.disable" does not exist or is not set to "true", this is a finding.'
    $global:xResult='"isolation.tools.hgfsServerSet.disable" value set to "true"'
    $global:command='Get-VM "VM Name" | New-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable -Value true'
    fn_Print_VM_Control_Info

    if($global:allVM )
    {
        foreach ($VM in $global:allVM ) {   
        $result = Invoke-Expression $global:command.tostring()
  
        if (!$result) {$result = "Not Set"}
  
       Write-Host $VM -NoNewLine
  
        if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  
  
        if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result
  
        Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor
  
        $global:result_array = $global:result_array+$result
     } 
   }
  }

  Function VMCH-70-000013 {
    $global:VMWConfig='VMCH-70-000013'
    $global:description='By default, more than one user at a time can connect to remote console sessions. When multiple sessions are activated, each terminal window receives a notification about the new session. If an administrator in the VM logs in using a VMware remote console during their session, a nonadministrator in the VM might connect to the console and observe the administrators actions.'
    $global:NISTcit='CM-6 b'
    $global:finding='If the virtual machine advanced setting "RemoteDisplay.maxConnections" does not exist or is not set to "1", this is a finding.'
    $global:xResult='Find the "RemoteDisplay.maxConnections" value and set it to "1"'
    $global:command='Get-VM "VM Name" | New-AdvancedSetting -Name RemoteDisplay.maxConnections -Value 1'
    fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   } 
 }
  }

  Function VMCH-70-000020 {
    $global:VMWConfig='VMCH-70-000020'
    $global:description='System administrators must use templates to deploy virtual machines (VMs) whenever possible.'
    $global:NISTcit='CM-6 b'
    $global:finding='Ask the system administrator if hardened, patched templates are used for VM creation and properly configured operating system deployments, including applications dependent and nondependent on VM-specific configurations.'
    $global:xResult='This check is a manual or policy based check'
    $global:command='Get-VM "VM Name"'
    fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   } 
 }
  }

  Function VMCH-70-000021 {
    $global:VMWConfig='VMCH-70-000021'
    $global:description='The VM console enables a connection to the console of a virtual machine, in effect seeing what a monitor on a physical server would show. The VM console also provides power management and removable device connectivity controls, which could allow a malicious user to bring down a VM. In addition, it impacts performance on the service console, especially if many VM console sessions are open simultaneously check, Remote management services, such as terminal services and Secure Shell (SSH), must be used to interact with VMs.'
    $global:NISTcit='CM-6 b'
    $global:finding='If a VM console is used to perform VM management tasks other than for troubleshooting VM issues, this is a finding. If SSH and/or terminal management services are exclusively used to perform management tasks, this is not a finding.'
    $global:xResult='This check is a manual or policy based check'
    $global:command='Get-VM "VM Name"'
    fn_Print_VM_Control_Info

    if($global:allVM )
    {
        foreach ($VM in $global:allVM ) {   
        $result = Invoke-Expression $global:command.tostring()
  
        if (!$result) {$result = "Not Set"}
  
       Write-Host $VM -NoNewLine
  
        if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  
  
        if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result
  
        Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor
  
        $global:result_array = $global:result_array+$result
     } 
   }
  }

  Function VMCH-70-000025 {
    $global:VMWConfig='VMCH-70-000025'
    $global:description='Logging must be enabled on the virtual machine (VM).'
    $global:NISTcit='CM-6 b'
    $global:finding='logging is not enable'
    $global:xResult='Ensure that the checkbox next to "Enable logging" is checked.'
    $global:command='Get-VM | Where {$_.ExtensionData.Config.Flags.EnableLogging -ne "True"}'
    fn_Print_VM_Control_Info

    if($global:allVM )
    {
        foreach ($VM in $global:allVM ) {   
        $result = Invoke-Expression $global:command.tostring()
  
        if (!$result) {$result = "Not Set"}
  
       Write-Host $VM -NoNewLine
  
        if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  
  
        if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result
  
        Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor
  
        $global:result_array = $global:result_array+$result
     } 
   }
}
Function NIST800-53-VI-VC-CFG-00415 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-00415'
  $global:description='Verify Users and Roles'
  $global:NISTcit='AC-6'
  $global:finding='The vCenter Server users must have the correct roles assigned.'
  $global:xResult='Limit Administrative roles to specific users'
  $global:command='Get-VIPermission | Sort Role | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto'
  fn_Print_vCenter_Control_Info
  Get-VIPermission | Sort-Object Role | Select-Object Role,Principal,Entity,Propagate,IsGroup | Out-File "./results/$($defaultVIServer) - $($date) - vC VIPUserList.txt"
  Write-Host $Global:DefaultVIServers -NoNewLine
  $result="See vC VIPUserList.txt"
  Write-Host `t`t`t$result
  $global:result_array = $global:result_array+$result
}

Function NIST800-53-VI-VC-CFG-00404 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-00404'
  $global:description='The vCenter Server must produce audit records containing information to establish what type of events occurred.'
  $global:NISTcit='AU-3'
  $global:finding='If the log level is not set to info, this is a finding.'
  $global:xResult='info'
  $global:command='(Get-AdvancedSetting -Entity $Global:DefaultVIServers -Name config.log.level | Select Value).value'
  fn_Print_vCenter_Control_Info
  $result = Invoke-Expression $global:command.tostring()
  Write-Host $Global:DefaultVIServers -NoNewLine
  if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result
  Write-Host `t`t`t$result -ForegroundColor $fgColor
  $global:result_array = $global:result_array+$result
}

Function NIST800-53-VI-VC-CFG-00405 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-00405'
  $global:description='The vCenter Server must set the distributed port group Promiscuous Mode policy to reject.'
  $global:NISTcit='AC-4'
  $global:finding='If the "Promiscuous Mode" policy is set to accept, this is a finding.'
  $global:xResult='False'
  $global:command='Get-VDSwitch | Get-VDSecurityPolicy & Get-VDPortgroup | Get-VDSecurityPolicy'
  fn_Print_vCenter_Control_Info
  $VDSTitle =  "Distributed Switches:"
  $dataFeed = '="'+$VDSTitle+'"&CHAR(10)&"'
  Write-Host $VDSTitle
  $allVDS = Get-VDSwitch | Sort-Object Name
  foreach ($VDS in $allVDS) {
    $VDS = $VDS.tostring()
    Write-Host $VDS":" -NoNewline
    $result = Get-VDSwitch -Name $VDS | Get-VDSecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous
    $VDS = $VDS.tostring()
    if ($result -eq "True") {$fgColor = "Red"} else {$fgColor = "White"}
    if ($VDS.length -lt 11) {Write-Host `t -NoNewLine}
    if ($VDS.length -lt 8) {Write-Host  `t -NoNewline}
    Write-Host `t`t`t $result -ForegroundColor $fgColor
    $dataFeed += " -"+$VDS+':  '+$result+'"&CHAR(10)&"'
  }
  Write-Host 
  $dataFeed += '---"&CHAR(10)&'
  $VDPGTitle = "Distributed Port Groups:"
  Write-Host $VDPHTitle
  $dataFeed += '"'+$VDPGTitle+'"&CHAR(10)&"'
  $allVPG = Get-VDPortgroup | Sort-Object Name
  foreach ($VDPG in $allVPG) {
    Write-Host $VDPG":" -NoNewline
    $result = Get-VDPortgroup -Name $VDPG | Get-VDSecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous
    $VDPG = $VDPG.tostring()
    if ($result -eq "True") {$fgColor = "Red"} else {$fgColor = "White"}
    if ($VDPG.length -lt 20) {Write-Host  `t -NoNewline}
    if ($VDPG.length -lt 11) {Write-Host  `t -NoNewline}
    if ($VDPG.length -lt 8) {Write-Host  `t -NoNewline}
    Write-Host `t`t $result -ForegroundColor $fgColor
    $dataFeed += " -"+$VDPG+':  '+$result+'"&CHAR(10)&"'
  }
  $dataFeed += '---"'
  $global:result_array = $global:result_array+$dataFeed
}

Function NIST800-53-VI-VC-CFG-00407 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-00407'
  $global:description='The vCenter Server must set the distributed port group MAC Address Change policy to reject.'
  $global:NISTcit='AC-4'
  $global:finding='If the "MAC Address Changes" policy is set to accept, this is a finding.'
  $global:xResult='False'
  $global:command='Get-VDSwitch | Get-VDSecurityPolicy & Get-VDPortgroup | Get-VDSecurityPolicy'
  fn_Print_vCenter_Control_Info
  $VDSTitle =  "Distributed Switches:"
  $dataFeed = '="'+$VDSTitle+'"&CHAR(10)&"'
  Write-Host $VDSTitle
  $allVDS = Get-VDSwitch | Sort-Object Name
  foreach ($VDS in $allVDS) {
    $VDS = $VDS.tostring()
    Write-Host $VDS":" -NoNewline
    $result = Get-VDSwitch -Name $VDS | Get-VDSecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous
    $VDS = $VDS.tostring()
    if ($result -eq "True") {$fgColor = "Red"} else {$fgColor = "White"}
    if ($VDS.length -lt 11) {Write-Host `t -NoNewLine}
    if ($VDS.length -lt 8) {Write-Host  `t -NoNewline}
    Write-Host `t`t`t $result -ForegroundColor $fgColor
    $dataFeed += " -"+$VDS+':  '+$result+'"&CHAR(10)&"'
  }
  Write-Host 
  $dataFeed += '---"&CHAR(10)&'
  $VDPGTitle = "Distributed Port Groups:"
  Write-Host $VDPHTitle
  $dataFeed += '"'+$VDPGTitle+'"&CHAR(10)&"' 
  $allVPG = Get-VDPortgroup | Sort-Object Name
  foreach ($VDPG in $allVPG) {
    Write-Host $VDPG":" -NoNewline
    $result = Get-VDPortgroup -Name $VDPG | Get-VDSecurityPolicy | Select-Object -ExpandProperty MacChanges
    $VDPG = $VDPG.tostring()
    if ($result -eq "True") {$fgColor = "Red"} else {$fgColor = "White"}
    if ($VDPG.length -lt 20) {Write-Host  `t -NoNewline}
    if ($VDPG.length -lt 11) {Write-Host  `t -NoNewline}
    if ($VDPG.length -lt 8) {Write-Host  `t -NoNewline}
    Write-Host `t`t $result -ForegroundColor $fgColor
    $dataFeed += " -"+$VDPG+':  '+$result+'"&CHAR(10)&"'
  }
  $dataFeed += '---"' 
  $global:result_array = $global:result_array+$dataFeed
}

Function NIST800-53-VI-VC-CFG-00417 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-00417'
  $global:description='The vCenter Server must only send NetFlow traffic to authorized collectors.'
  $global:NISTcit='AC-4'
  $global:finding='The vCenter Server must only send NetFlow traffic to authorized collectors.'
  $global:xResult='Site Specific'
  $global:command='(Get-VDSwitch -Name <VDS>).ExtensionData.config.IpfixConfig.CollectorIpAddress '
  fn_Print_vCenter_Control_Info
  $VDSTitle =  "Distributed Switches:"
  $dataFeed = '="'+$VDSTitle+'"&CHAR(10)&"'
  Write-Host $VDSTitle
  $allVDS = Get-VDSwitch | Sort-Object Name
  foreach ($VDS in $allVDS) {
    $VDS = $VDS.tostring()
    Write-Host $VDS":" -NoNewline
    $result = (Get-VDSwitch -Name $VDS).ExtensionData.config.IpfixConfig.CollectorIpAddress 
    $VDS = $VDS.tostring()
    if (!$result) {$result = "Not Set"}
    if ($VDS.length -lt 11) {Write-Host `t -NoNewLine}
    if ($VDS.length -lt 8) {Write-Host  `t -NoNewline}
    Write-Host `t`t`t $result
    $dataFeed += " -"+$VDS+':  '+$result+'"&CHAR(10)&"'
  }
  Write-Host 
  $dataFeed += '---"&CHAR(10)&'
  $VDPGTitle = "Distributed Port Groups:"
  Write-Host $VDPHTitle
  $dataFeed += '"'+$VDPGTitle+'"&CHAR(10)&"' 
  $allVPG = Get-VDPortgroup | Sort-Object Name
  foreach ($VDPG in $allVPG) {
    Write-Host $VDPG":" -NoNewline
    $result = (Get-VDPortgroup -Name $VDPG).ExtensionData.config.IpfixConfig.CollectorIpAddress 
    $VDPG = $VDPG.tostring()
    if (!$result) {$result = "Not Set"}
    if ($VDPG.length -lt 20) {Write-Host  `t -NoNewline}
    if ($VDPG.length -lt 11) {Write-Host  `t -NoNewline}
    if ($VDPG.length -lt 8) {Write-Host  `t -NoNewline}
    Write-Host `t`t $result 
    $dataFeed += " -"+$VDPG+':  '+$result+'"&CHAR(10)&"'
  }
  $dataFeed += '---"'
  $global:result_array = $global:result_array+$dataFeed
}

Function NIST800-53-VI-VC-CFG-00420 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-00420'
  $global:description='The vCenter Server must configure the vSAN Datastore name to a unique name.'
  $global:NISTcit='CM-6b.'
  $global:finding='Name with "vsanDatastore"'
  $global:xResult='No Name with "vsanDatastore"'
  $global:command='Get-Cluster | Where-Object {$_.VsanEnabled} | Get-Datastore | Where-Object {$_.type -match "vsan"}'
  fn_Print_vCenter_Control_Info
  If($(Get-Cluster | Where-Object {$_.VsanEnabled} | Measure-Object).Count -gt 0){
    $result = "vSAN Enabled Cluster found. See NIST800-53-VI-VC-CFG-00420.txt file."
    (Get-Cluster | Where-Object {$_.VsanEnabled} | Get-Datastore | Where-Object {$_.type -match "vsan"}) >> ./results/NIST800-53-VI-VC-CFG-00420.txt
    }
    else { 
      $result = "vSAN is not enabled, this finding is not applicable" 
  }
  Write-Host "Result: "$result
  $global:result_array = $global:result_array+$result
}

Function NIST800-53-VI-VC-CFG-00450 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-00450'
  $global:description='The vCenter Server must set the distributed port group Forged Transmits policy to reject.'
  $global:NISTcit='AC-4'
  $global:finding='If the "Forged Transmits" policy is set to accept, this is a finding.'
  $global:xResult='False'
  $global:command='Get-VDSwitch | Get-VDSecurityPolicy & Get-VDPortgroup | Get-VDSecurityPolicy'
  fn_Print_vCenter_Control_Info
  $VDSTitle =  "Distributed Switches:"
  $dataFeed = '="'+$VDSTitle+'"&CHAR(10)&"'
  Write-Host $VDSTitle
  $allVDS = Get-VDSwitch | Sort-Object Name
  foreach ($VDS in $allVDS) {
    $VDS = $VDS.tostring()
    Write-Host $VDS":" -NoNewline
    $result = Get-VDSwitch -Name $VDS | Get-VDSecurityPolicy | Select-Object -ExpandProperty ForgedTransmits
    $VDS = $VDS.tostring()
    if ($result -eq "True") {$fgColor = "Red"} else {$fgColor = "White"}
    if ($VDS.length -lt 11) {Write-Host `t -NoNewLine}
    if ($VDS.length -lt 8) {Write-Host  `t -NoNewline}
    Write-Host `t`t`t $result -ForegroundColor $fgColor
    $dataFeed += " -"+$VDS+':  '+$result+'"&CHAR(10)&"'
  }
  Write-Host 
  $dataFeed += '---"&CHAR(10)&'
  $VDPGTitle = "Distributed Port Groups:"
  Write-Host $VDPHTitle
  $dataFeed += '"'+$VDPGTitle+'"&CHAR(10)&"'
  $allVPG = Get-VDPortgroup | Sort-Object Name
  foreach ($VDPG in $allVPG) {
    Write-Host $VDPG":" -NoNewline
    $result = Get-VDPortgroup -Name $VDPG | Get-VDSecurityPolicy | Select-Object -ExpandProperty ForgedTransmits
    $VDPG = $VDPG.tostring()
    if ($result -eq "True") {$fgColor = "Red"} else {$fgColor = "White"}
    if ($VDPG.length -lt 20) {Write-Host  `t -NoNewline}
    if ($VDPG.length -lt 11) {Write-Host  `t -NoNewline}
    if ($VDPG.length -lt 8) {Write-Host  `t -NoNewline}
    Write-Host `t`t $result -ForegroundColor $fgColor
    $dataFeed += " -"+$VDPG+':  '+$result+'"&CHAR(10)&"'
  }
  $dataFeed += '---"' 
  $global:result_array = $global:result_array+$dataFeed
}

Function NIST800-53-VI-VC-CFG-00428 { 
  $global:VMWConfig='NIST800-53-VI-VC-CFG-00428'
  $global:description='The vCenter Server must configure the vpxuser auto-password to be changed periodically.'
  $global:NISTcit='IA-5f.'
  $global:finding='If the "VirtualCenter.VimPasswordExpirationInDays" is set to a value other than 30 days or does not exist, this is a finding.'
  $global:xResult='30'
  $global:command='(Get-AdvancedSetting -Entity $Global:DefaultVIServers -Name VirtualCenter.VimPasswordExpirationInDays).value'
  fn_Print_vCenter_Control_Info
  $result = Invoke-Expression $global:command.tostring()
  Write-Host $Global:DefaultVIServers -NoNewLine
  if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result
  Write-Host `t`t`t$result -ForegroundColor $fgColor
  $global:result_array = $global:result_array+$result
}

Function NIST800-53-VI-VC-CFG-01200 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-01200'
  $global:description='The vCenter Server must disable the distributed virtual switch health check.'
  $global:NISTcit='CM-6b.'
  $global:finding='If the health check feature is enabled on distributed switches and is not on temporarily for troubleshooting purposes, this is a finding.'
  $global:xResult='False'
  $global:command='((Get-VDSwitch -Name $VDS).ExtensionData.Config.HealthCheckConfig) | Select-Object -ExpandProperty Enable'
  fn_Print_vCenter_Control_Info
  $VDSTitle =  "Distributed Switches:"
  $dataFeed = '="'+$VDSTitle+'"&CHAR(10)&"'
  Write-Host $VDSTitle
  $allVDS = Get-VDSwitch | Sort-Object Name
  foreach ($VDS in $allVDS) {
    $VDS = $VDS.tostring()
    Write-Host $VDS":" -NoNewline
    $result = Get-VDSwitch -Name $VDS | Get-VDSecurityPolicy | Select-Object -ExpandProperty ForgedTransmits
    $VDS = $VDS.tostring()
    if ($result -eq "True") {$fgColor = "Red"} else {$fgColor = "White"}
    if ($VDS.length -lt 11) {Write-Host `t -NoNewLine}
    if ($VDS.length -lt 8) {Write-Host  `t -NoNewline}
    Write-Host `t`t`t $result -ForegroundColor $fgColor
    $dataFeed += " -"+$VDS+':  '+$result+'"&CHAR(10)&"'
  }
  $dataFeed +='"'
  $global:result_array = $global:result_array+$dataFeed
}

Function NIST800-53-VI-VC-CFG-01201 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-01201'
  $global:description='Configure all port groups to a value different from the value of the native VLAN.'
  $global:NISTcit='CM-6b.'
  $global:finding='If any port group is configured with the native VLAN of the ESXi hosts attached physical switch, this is a finding.'
  $global:xResult='Site Specific'
  $global:command='(Get-VDPortgroup | Select-Object -ExpandProperty VlanConfiguration).value'
  fn_Print_vCenter_Control_Info

  $VDPGTitle = "Distributed Port Groups:"
  Write-Host $VDPHTitle
  $dataFeed += '="'+$VDPGTitle+'"&CHAR(10)&"'
 
    $allVPG = Get-VDPortgroup | Sort-Object Name
    foreach ($VDPG in $allVPG) {

      Write-Host $VDPG":" -NoNewline

      $result = (Get-VDPortgroup | Select-Object -ExpandProperty VlanConfiguration)
      $VDPG = $VDPG.tostring()
      if ($result -eq "") {$fgColor = "Red"; $result = "Not Set"} else {$fgColor = "White"}
      if ($VDPG.length -lt 20) {Write-Host  `t -NoNewline}
      if ($VDPG.length -lt 11) {Write-Host  `t -NoNewline}
      if ($VDPG.length -lt 8) {Write-Host  `t -NoNewline}
      Write-Host `t`t $result -ForegroundColor $fgColor

      $dataFeed += " -"+$VDPG+':  '+$result+'"&CHAR(10)&"'
    }
  $dataFeed +='"' 
  $global:result_array = $global:result_array+$dataFeed
}

Function NIST800-53-VI-VC-CFG-01202 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-01202'
  $global:description='Configure all port groups to VLAN values not reserved by upstream physical switches.'
  $global:NISTcit='AC-4'
  $global:finding='If any port group is configured with a reserved VLAN ID, this is a finding.'
  $global:xResult='Site Specific'
  $global:command='(Get-VDPortgroup | Select-Object -ExpandProperty VlanConfiguration).value'
  fn_Print_vCenter_Control_Info

  $VDPGTitle = "Distributed Port Groups:"
  Write-Host $VDPHTitle
  $dataFeed += '="'+$VDPGTitle+'"&CHAR(10)&"'
 
    $allVPG = Get-VDPortgroup | Sort-Object Name
    foreach ($VDPG in $allVPG) {

      Write-Host $VDPG":" -NoNewline

      $result = (Get-VDPortgroup | Select-Object -ExpandProperty VlanConfiguration)
      $VDPG = $VDPG.tostring()
      if ($result -eq "") {$fgColor = "Red"; $result = "Not Set"} else {$fgColor = "White"}
      if ($VDPG.length -lt 20) {Write-Host  `t -NoNewline}
      if ($VDPG.length -lt 11) {Write-Host  `t -NoNewline}
      if ($VDPG.length -lt 8) {Write-Host  `t -NoNewline}
      Write-Host `t`t $result -ForegroundColor $fgColor

      $dataFeed += " -"+$VDPG+':  '+$result+'"&CHAR(10)&"'
    }
  $dataFeed +='"' 
  $global:result_array = $global:result_array+$dataFeed
}

Function NIST800-53-VI-VC-CFG-01203 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-01203'
  $global:description='Disable the managed object browser when not required for the purpose of troubleshooting or maintenance of managed objects.'
  $global:NISTcit='CM-6b'
  $global:finding='If the MOB is currently enabled, ask the SA if it is being used for troubleshooting or active development. If no, this a finding.'
  $global:xResult='Site Specific'
  $global:command='Add/Modify <enableDebugBrowse>false</enableDebugBrowse> in the <vpxd> secition of the etc/vmware-vpx/vpxd-cfg file'
  fn_Print_vCenter_Control_Info

  Write-Host "Managed Object Browser"
  $result = "Mannually Check and Document"
  
  $global:result_array = $global:result_array+$result
}

Function NIST800-53-VI-VC-CFG-01204 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-01204'
  $global:description='The vCenter Server must enable TLS 1.2 exclusively.'
  $global:NISTcit='SC-23'
  $global:finding='If the output indicates versions of TLS other than 1.2 are enabled, this is a finding.'
  $global:xResult='Site Specific'
  $global:command='/usr/lib/vmware-TlsReconfigurator/VcTlsReconfigurator/reconfigureVc scan'
  fn_Print_vCenter_Control_Info

  Write-Host "TLS 1.2 Exclusively Used"
  $result = "Mannually Check and Document"
  
  $global:result_array = $global:result_array+$result
}

Function NIST800-53-VI-VC-CFG-01205 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-01205'
  $global:description='The vCenter Server Machine SSL certificate must be issued by an appropriate certificate authority.'
  $global:NISTcit='SC-12(3)'
  $global:finding='If the issuer specified is not an approved certificate authority, this is a finding.'
  $global:xResult='Site Specific'
  $global:command='curl https://'+$global:DefaultVIServer+' -vI --stderr - | grep "issuer"'
  fn_Print_vCenter_Control_Info

  Write-Host "Verify SSL Certificate" -NoNewLine
  $result = Invoke-Expression $global:command.tostring()
  Write-Host `t`t`t$result

  $global:result_array = $global:result_array+$result
}

Function NIST800-53-VI-VC-CFG-01209 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-01209'
  $global:description='Configure a  message.'
  $global:NISTcit='AC-8a'
  $global:finding='If selection boxes next to "Show login message" is disabled or if "Details of login message" is not configured to an approved standard User Agreement, this is a finding.'
  $global:xResult='Site Specific'
  $global:command='From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Login Message'
  fn_Print_vCenter_Control_Info

  Write-Host "Verify Logon Message" -NoNewLine
  $result = "Mannually Check and Document"
  Write-Host `t`t`t$result

  $global:result_array = $global:result_array+$result
}

Function NIST800-53-VI-VC-CFG-01210 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-01210'
  $global:description='The vCenter Server must restrict access to cryptographic role.'
  $global:NISTcit='AC-17(2)'
  $global:finding='If there are any users other than Solution Users with the "Administrator" role that are not explicitly designated for cryptographic operations, this is a finding.'
  $global:xResult='Limit Administrative roles to specific users'
  $global:command='Get-VIPermission | Where {$_.Role -eq "Admin"} | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto'

  fn_Print_vCenter_Control_Info

  Get-VIPermission | Where {$_.Role -eq 'Admin'} | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto | Out-File "./results/$($defaultVIServer) - $($date) - vC CryptoUserList.txt"

  Write-Host $Global:DefaultVIServers -NoNewLine

  $result="See vC CryptoUserList.txt"
  Write-Host `t`t`t$result

  $global:result_array = $global:result_array+$result

}
Function NIST800-53-VI-VC-CFG-01211 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-01211'
  $global:description='vCenter Server must restrict access to cryptographic permissions.'
  $global:NISTcit='AC-17(2)'
  $global:finding='If there are any users other than Solution Users with the "Administrator" role that are not explicitly designated for cryptographic operations, this is a finding.'
  $global:xResult='Verify that only the Administrator and any site-specific cryptographic group(s) have the following permissions: Cryptographic Operations privileges, Global.Diagnostics, Host.Inventory.Add host to cluster, Host.Inventory.Add standalone host, Host.Local operations.Manage user groups'
  $global:command='$roles = Get-VIRole : ForEach($role in $roles){$privileges = $role.PrivilegeList If($privileges -match "Crypto*" -or $privileges -match "Global.Diagnostics" -or $privileges -match "Host.Inventory.Add*" -or $privileges -match "Host.Local operations.Manage user groups"){Write-Host "$role has Cryptographic privileges"}}'

  fn_Print_vCenter_Control_Info

  Write-Host $Global:DefaultVIServers -NoNewLine

  $roles = Get-VIRole
  ForEach($role in $roles){
      $privileges = $role.PrivilegeList
      If($privileges -match "Crypto*" -or $privileges -match "Global.Diagnostics" -or $privileges -match "Host.Inventory.Add*" -or $privileges -match "Host.Local operations.Manage user groups"){
      Write-Host "$role has Cryptographic privileges"
      
      }
  }

  Write-Host $Global:DefaultVIServers -NoNewLine

  $result="See vC CryptoUserList.txt"
  Write-Host `t`t`t$result

  $global:result_array = $global:result_array+$result

}

Function NIST800-53-VI-VC-CFG-01212 {
  $global:VMWConfig='NIST800-53-VI-VC-CFG-01212'
  $global:description='Configure Mutual CHAP for vSAN iSCSI targets.'
  $global:NISTcit='CM-6b'
  $global:finding='If the Authentication method is not set to "CHAP_Mutual" for any iSCSI target, this is a finding.'
  $global:xResult='For each iSCSI target review the value in the "Authentication" column.'
  $global:command='Go to Host and Clusters >> Select a vSAN Enabled Cluster >> Configure >> vSAN >> iSCSI Target Service.'

  fn_Print_vCenter_Control_Info

  Write-Host $Global:DefaultVIServers -NoNewLine

  $result = "Mannually Check and Document"
  Write-Host `t`t`t$result

  $global:result_array = $global:result_array+$result

}


                                              #######################################################################
                                              ################       ESX CONTROL FUNCTIONS       ####################
                                              #######################################################################

Function GET-ESX-Version {

  $VMWConfig='ESX Version'
    $description='Check ESX Version'
    $NISTcit='N/A'
    $finding='Variation of Versions'
    $xresult='Site Specific'
    $global:command='($VMHost.version)'

    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {
      $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      Write-Host `t`t`t$result

      $global:result_array = $global:result_array+$result

    }
}

Function GET-ESX-Build {

  $VMWConfig='ESX Build'
    $description='Check ESX Build'
    $NISTcit='N/A'
    $finding='Variation of Build Versions'
    $xresult='Site Specific'
    $global:command='($VMHost.build)'

    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {
      $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      Write-Host `t`t`t$result

      $global:result_array = $global:result_array+$result

    }
}

Function GET-ESX-Datacenter {

  $VMWConfig='Datacenter'
    $description='N/A'
    $NISTcit='N/A'
    $finding='N/A'
    $xresult='Site Specific'
    $global:command='Get-Datacenter -VMHost $VMHost | Select-Object -ExpandProperty  Name'

    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {
      $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      Write-Host `t`t`t$result 

      $global:result_array = $global:result_array+$result

    }
}

Function GET-ESX-Cluster {

  $VMWConfig='Cluster'
    $description='N/A'
    $NISTcit='N/A'
    $finding='N/A'
    $xresult='Site Specific'
    $global:command='Get-Cluster -VMHost $VMHost | Select-Object -ExpandProperty  Name'

    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {
      $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      Write-Host `t`t`t$result

      $global:result_array = $global:result_array+$result

    }
}
Function NIST800-53-VI-ESXi-CFG-00003 {
    $VMWConfig='NIST800-53-VI-ESXi-CFG-00003'
    $description='ESXi host SSH daemon ignores .rhosts files.'
    $NISTcit='CM-6b.'
    $finding='SSH ignore .rhosts no'
    $xresult='ignorerhosts yes'
    $command='/usr/lib/vmware/openssh/bin/sshd -T | grep ignorerhosts'

    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {
      if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

         } else {

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor
         }
        
       $global:result_array = $global:result_array+$result
    }
    
  }
Function NIST800-53-VI-ESXi-CFG-00004 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00004'
  $global:description='ESXi host SSH daemon does not allow host-based authentication.'
  $global:NISTcit='CM-6b.'
  $global:finding='Should not be set to hostbasedauthentication YES'
  $global:xResult='hostbasedauthentication no'
  $global:command='/usr/lib/vmware/openssh/bin/sshd -T | grep hostbasedauthentication'
  fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON
          

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

      else
      {
    
          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output

          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

       $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00005 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00005'
  $global:description='The ESXi host SSH daemon must not permit root logins.'
  $global:NISTcit='CM-6b.'
  $global:finding='Should not be set to permitrootlogin yes'
  $global:xResult='permitrootlogin no'
  $global:command='/usr/lib/vmware/openssh/bin/sshd -T | grep permitrootlogin'
  fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

       $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00006 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00006'
  $global:description='ESXi host SSH daemon rejects authentication using an empty password.'
  $global:NISTcit='ESXi host SSH daemon rejects authentication using an empty password.'
  $global:finding='If SSH Permits Empty Passwords'
  $global:xResult='permitemptypasswords no'
  $global:command='/usr/lib/vmware/openssh/bin/sshd -T | grep permitemptypasswords'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    if(!(fn_SSH_Check))
    {
        fn_SSH_ON

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

       
    }

    else
    {
  

        $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
        $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


        Write-Host $VMHost -NoNewLine

        if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

    }

     $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00007 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00007'
  $global:description='ESXi host SSH daemon does not permit user environment settings.'
  $global:NISTcit='CM-6b.'
  $global:finding='SSH Permits User Env Settings'
  $global:xResult='permituserenvironment no'
  $global:command='/usr/lib/vmware/openssh/bin/sshd -T | grep permituserenvironment'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    if(!(fn_SSH_Check))
    {
        fn_SSH_ON

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

    }

    else
    {
  

        $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
        $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


        Write-Host $VMHost -NoNewLine

        if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

    }

     $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00011 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00011'
  $global:description='ESXi host SSH daemon performs strict mode checking of home directory configuration files.'
  $global:NISTcit='CM-6b.'
  $global:finding='Stricmode set to NO'
  $global:xResult='strictmodes yes'
  $global:command='/usr/lib/vmware/openssh/bin/sshd -T | grep strictmodes'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    if(!(fn_SSH_Check))
    {
        fn_SSH_ON

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

    }

    else
    {
  

        $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
        $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


        Write-Host $VMHost -NoNewLine

        if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

    }

     $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00012 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00012'
  $global:description='Disallow compression for the ESXi host SSH daemon.'
  $global:NISTcit='Disallow compression for the ESXi host SSH daemon.'
  $global:finding='Compression set to YES'
  $global:xResult='compression no'
  $global:command=' /usr/lib/vmware/openssh/bin/sshd -T | grep compression'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    if(!(fn_SSH_Check))
    {
        fn_SSH_ON

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor
        
    }

    else
    {
  

        $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
        $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


        Write-Host $VMHost -NoNewLine

        if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

    }

     $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00013 {
    $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00013'
    $global:description='ESXi host SSH daemon does not contain gateway ports.'
    $global:NISTcit='CM-6b.'
    $global:finding='Allow Gatewayports set to YES'
    $global:xResult='gatewayports no'
    $global:command='/usr/lib/vmware/openssh/bin/sshd -T | grep gatewayports'
    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

        $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00014 {
    $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00014'
    $global:description='ESXi host SSH daemon refuses X11 forwarding.'
    $global:NISTcit='CM-6b.'
    $global:finding='SSH x11forwarding set to YES'
    $global:xResult='x11forwarding no'
    $global:command='/usr/lib/vmware/openssh/bin/sshd -T | grep x11forwardin'
    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

        $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00016 {
    $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00016'
    $global:description='ESXi host SSH daemon refuses tunnels.'
    $global:NISTcit='CM-6b.'
    $global:finding='SSH permittunnel set to YES'
    $global:xResult='permittunnel no'
    $global:command='/usr/lib/vmware/openssh/bin/sshd -T| grep permittunnel'
    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

          
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

        $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00017 {
    $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00017'
    $global:description='ESXi host SSH daemon sets an idle session timeout count.'
    $global:NISTcit=''
    $global:finding='SSH clientalivecountmax not 3'
    $global:xResult='clientalivecountmax 3'
    $global:command='/usr/lib/vmware/openssh/bin/sshd -T | grep clientalivecountmax'
    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

          
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

        $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00018 {
    $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00018'
    $global:description='ESXi host SSH daemon sets an idle session timeout interval.'
    $global:NISTcit='CM-6b.'
    $global:finding='SSH clientaliveinterval > 300'
    $global:xResult='clientaliveinterval 300'
    $global:command=' /usr/lib/vmware/openssh/bin/sshd -T | grep clientaliveinterval'
    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

        $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00028 {
    $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00028'
    $global:description='Configure the ESXi hosts firewall to only allow traffic from the ESXi management network.'
    $global:NISTcit='SC-7(5)'
    $global:finding='AllIPEnabled for SSH is TRUE'
    $global:xResult='False'
    $global:command='(Get-VMHostFirewallException $VMHost -Name "SSH Server").ExtensionData.AllowedHosts.AllIp'
    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00030 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00030'
  $global:description='Show warnings in the vSphere Client if local or remote shell sessions are enabled on the ESXi hosts.'
  $global:NISTcit='CM-11(1)'
  $global:finding='Suppress Shell Warning set to 0'
  $global:xResult= '1'
  $global:command='($VMHost| Get-AdvancedSetting -Name UserVars.SuppressShellWarning).Value'
  fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00031 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00031'
  $global:description='Enable Normal lockdown mode on the host.'
  $global:NISTcit='AC-17(4)(a)'
  $global:finding='Lockdown Mode Disabled'
  $global:xResult='lockdownEnabled'
  $global:command='($VMHost | Get-View).Config.LockdownMode'
  fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00034 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00034'
  $global:description='Set the maximum number of failed login attempts before an account is locked.'
  $global:NISTcit='AC-7a.'
  $global:finding='Greater than 3'
  $global:xResult='3'
  $global:command='($VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures).value'
  fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -gt $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00038 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00038'
  $global:description='Configure the inactivity timeout to automatically terminate idle shell sessions.'
  $global:NISTcit='AC-12 Control'
  $global:finding='Greater than 600 Seconds'
  $global:xResult='600'
  $global:command='($VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut).value'
  fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -gt $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00043 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00043'
  $global:description='Enable the Bridge Protocol Data Unit (BPDU) filter.'
  $global:NISTcit='CM-6b.'
  $global:finding='0'
  $global:xResult='1'
  $global:command='($VMHost | Get-AdvancedSetting -Name Net.BlockGuestBPDU).value'
  fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00105 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00105'
  $global:description='The ESXi host must configure the firewall to block incoming network traffic by default.'
  $global:NISTcit='SC-7(5)'
  $global:finding='Incoming Policy set to TRUE'
  $global:xResult='FALSE'
  $global:Compare='equal'
  $global:command='(Get-VMHostFirewallDefaultPolicy $VMHost).IncomingEnabled'
  fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00106 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00106'
  $global:description='The ESXi host must configure the firewall to block outgoing network traffic by default.'
  $global:NISTcit='SC-7(5)'
  $global:finding='Outgoing Policy set to TRUE'
  $global:xResult='FALSE'
  $global:command='(Get-VMHostFirewallDefaultPolicy $VMHost).OutgoingEnabled'
  fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
}

Function NIST800-53-VI-ESXi-CFG-00109 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00109'
  $global:description='Configure the password history setting to restrict the reuse of passwords.'
  $global:NISTcit='IA-5(1)(e)'
  $global:finding='Less than 5'
  $global:xResult='5'
  $global:command='($VMHost | Get-AdvancedSetting -Name Security.PasswordHistory).value'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -gt $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-00110 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00110'
  $global:description='The password hashes stored on the ESXi host must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm.'
  $global:NISTcit='SC-13 Control'
  $global:finding='Non FIPS 140-2 Compliant Hash'
  $global:xResult='sha512'
  $global:command='grep -i "^password" /etc/pam.d/passwd | grep sufficient'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    if(!(fn_SSH_Check))
    {
        fn_SSH_ON

        $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
        $result1 = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output
        $result2 = Out-String -InputObject $result1
        $result3 = $result2.trim()
        $result = ($result3.substring($result3.Length - 6))


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

    }

    else
    {
  

        $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
        $result1 = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output
        $result2 = Out-String -InputObject $result1
        $result3 = $result2.trim()
        $result = ($result3.substring($result3.Length - 6))


        Write-Host $VMHost -NoNewLine

        if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

    }

      $global:result_array = $global:result_array+$result
  }
}
Function NIST800-53-VI-ESXi-CFG-00112a {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00112a'
  $global:description='Stop the ESXi shell service.'
  $global:NISTcit='CM-7a'
  $global:finding='ESX Shell Running'
  $global:xresult="False"
  $global:command='Get-VMHostService $VMHost | Where-Object {$_.Label -eq "ESXi Shell"} | Select-Object -ExpandProperty Running'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      #if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result
      if ($result -eq $False) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-00112b {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00112b'
  $global:description='Set the ESXi shell service startup policy to OFF.'
  $global:NISTcit='CM-7a'
  $global:finding='ESX Shell Startup Policy ON'
  $global:xresult='off'
  $global:command='Get-VMHostService $VMHost | Where-Object {$_.Label -eq "ESXi Shell"} | Select-Object -ExpandProperty Policy'

  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-00114 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00114'
  $global:description='Join ESXi hosts to an Active Directory (AD) domain to eliminate the need to create and maintain multiple local user accounts.'
  $global:NISTcit='IA-2 Control'
  $global:finding='Not AD Joined or DomainMembershipStatus not "Ok'
  $global:xResult=$UserDomain+' Ok'
  $global:command= 'Get-VMHostAuthentication $VMHost | Select-Object -ExpandProperty Domain'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {
    $result = Get-VMHostAuthentication $VMHost | Select-Object -ExpandProperty Domain
    $result2 = Get-VMHostAuthentication $VMHost | Select-Object -ExpandProperty DomainMembershipStatus

    Write-Host $VMHost -NoNewline

    if (!$result) {$result = 'None'}
    if (!$result2) {$result2 = '-'}

    if ($result -like $UserDomain) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

    Write-Host  `t`t`t $result -ForegroundColor $fgColor -NoNewline

    if ($result2 -eq 'Ok') {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

    Write-Host  " "$result2 -ForegroundColor $fgColor

    $result = $result+' ['+$result2+']'

    $global:result_array = $global:result_array+$result
  }

}
Function NIST800-53-VI-ESXi-CFG-00122 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00122'
  $global:description='Configure the login banner for the DCUI of the ESXi host.'
  $global:NISTcit='AC-8a.'
  $global:finding='If Annotations.WelcomeMessage is not set to the specified banner, this is a finding.'
  $global:xResult='Not Blank'
  $global:command='($VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage).value'
  fn_Print_ESX_Control_Info
  $allHosts = Get-VMHost | Sort-Object Name

  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()
    if (!$result) {$result="BLANK"}

      Write-Host $VMHost -NoNewLine

      if ($result -eq "BLANK") {$fgColor="Red"} else {$fgColor="White"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}
Function NIST800-53-VI-ESXi-CFG-00123 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00123'
  $global:description='Configure the login banner for SSH Connections.'
  $global:NISTcit='AC-8a.'
  $global:finding='If Config.Etc.issue is not set to the specified banner, this is a finding.'
  $global:xResult='Set'
  $global:command='((Get-AdvancedSetting $VMHost -Name Config.Etc.issue).value)'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $command.tostring()
    Write-Host $VMHost -NoNewline

    if (!$result) {$result = 'Not Set'} else {$result = 'Set'}

    if ($result -eq 'Not Set') {$fgColor="Red"} else {$fgColor="White"} #Set Warning Color for screen utput based on expected result

    Write-Host  `t`t`t $result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-00124 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00124'
  $global:description='The ESXi host SSH daemon must be configured with an approved login banner.'
  $global:NISTcit='AC-8a.'
  $global:finding='Not Set'
  $global:xResult='banner /etc/issue'
  $global:command='/usr/lib/vmware/openssh/bin/sshd -T | grep banner'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    if(!(fn_SSH_Check))
    {
        fn_SSH_ON

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

    }

    else
    {
  

        $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
        $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


        Write-Host $VMHost -NoNewLine

        if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

    }

      $global:result_array = $global:result_array+$result
  }
}
Function NIST800-53-VI-ESXi-CFG-00125 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00125'
  $global:description='The ESXi host must verify the exception users list for lockdown mode.'
  $global:NISTcit='AC-6(1)'
  $global:finding='Non essential users'
  $global:xResult='root'
  $global:command='(Get-View -Id (Get-VMHost -Name $VMHost | Get-View).ConfigManager.HostAccessManager).QueryLockdownExceptions()'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}
Function NIST800-53-VI-ESXi-CFG-00129 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00129'
  $global:description='Install Security Patches and Updates for ESXi hosts.'
  $global:NISTcit='CM-6'
  $global:finding='Outdated Patches'
  $global:xResult='Site Specific'
  $global:command=''
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name

    $allHosts = Get-VMHost | Sort-Object Name
    $List = @()

    foreach ($VMHost in $allHosts) {

        $VMHostName = $VMhost.Name
        $Cluster = $VMhost.Parent
        $esxcli = $VMHost | Get-EsxCli

        $List += $esxcli.software.vib.list() | Select-Object @{N="VMHostName"; E={$VMHostName}},@{N="Cluster"; E={$Cluster}},*
        $result="See ESXi Patches.csv"
        Write-Host $VMHost -NoNewLine
        Write-Host `t`t`t$result 
        $global:result_array = $global:result_array+$result


    $List | Export-Csv -Path "./results/$($defaultVIServer) - $($date) - ESXi Patches.csv" -NoTypeInformation

  }
}


Function NIST800-53-VI-ESXi-CFG-00136 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00136'
  $global:description='Configure a persistent log location for all locally stored logs'
  $global:NISTcit='AU-9 Control'
  $global:finding='Configure a persistent log location for all locally stored logs'
  $global:xResult= 'true'
  $global:command='(Get-EsxCLI -v2 -VMHost $VMHost).system.syslog.config.get.Invoke()| Select-Object -ExpandProperty LocalLogOutputIsPersistent'
 
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -ne $null) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-00137 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00137'
  $global:description='Use an Active Directory group instead of the default "ESX Admins"'
  $global:NISTcit='IA-2 Control'
  $global:finding='Use an Active Directory group instead of the default ESX Admins'
  $global:xResult= 'ESX Admins'
  $global:command='(Get-VMHost -Name $VMHost)| Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Select-Object -ExpandProperty Value'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -ne $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}


Function NIST800-53-VI-ESXi-CFG-00138 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00138'
  $global:description='The ESXi host must disable Inter-VM transparent page sharing'
  $global:NISTcit='IA-2 Control'
  $global:finding='The ESXi host must disable Inter-VM transparent page sharing'
  $global:xResult= '2'
  $global:command='(Get-VMHost -Name $VMHost)| Get-AdvancedSetting -Name Mem.ShareForceSalting | Select-Object -ExpandProperty Value'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}


Function NIST800-53-VI-ESXi-CFG-00147 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00147'
  $global:description='The ESXi host must configure NTP Time Synchronization.'
  $global:NISTcit='AU-8(1)(a)'
  $global:finding='NTP Time Synchromization'
  $global:xResult= 'Authorized Time Source'
  $global:command='(Get-VMHost -Name $VMHost)| Get-VMHostNTPServer'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -ne $null) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-00148 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00148'
  $global:description='Verify NTP Daemon Policy is On.'
  $global:NISTcit='AU-8(1)(a)'
  $global:finding='NTP Daemon Policy'
  $global:xResult='on'
  $global:command='(Get-VMHost -Name $VMHost) | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Select-Object -ExpandProperty Policy'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}


Function NIST800-53-VI-ESXi-CFG-00149 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00149'
  $global:description='Verify NTP Daemon is running.'
  $global:NISTcit='AU-8(1)(a)'
  $global:finding='NTP Daemon Status'
  $global:xResult='True'
  $global:command='(Get-VMHost -Name $VMHost) | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Select-Object -ExpandProperty Running'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-00157 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00157'
  $global:description='The ESXi Image Profile and VIB Acceptance Levels must be verified.'
  $global:NISTcit='CM-5(3)'
  $global:finding='VIB Acceptance Level CommunitySupported'
  $global:xResult='PartnerSupported VMwareAccepted VMwareCertified'
  $global:command='(Get-EsxCli -VMHost $VMHost).software.acceptance.get()'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if($xresult.Contains($result)) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-00163 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00163'
  $global:description='ESXI Host must verify DCUI Access List.'
  $global:NISTcit='CM-6b'
  $global:finding='ESXI Host DCUI Access List'
  $global:xResult='root'
  $global:command='(Get-VMHost -Name $VMHost) | Get-AdvancedSetting -Name DCUI.Access | Select-Object -ExpandProperty Value'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-00164 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00164'
  $global:description='Configure a remote log server for the ESXi hosts'
  $global:NISTcit='AU-9(2)'
  $global:finding='Configure a remote log server for the ESXi hosts'
  $global:xResult= 'Configured Syslog Servers'
  $global:command='(Get-VMHost -Name $VMHost)| Get-AdvancedSetting -Name Syslog.global.logHost | Select-Object -ExpandProperty Value'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -ne $null) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}


Function NIST800-53-VI-ESXi-CFG-00165 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00165'
  $global:description='The ESXi host must enforce an unlock timeout after a user account is locked out'
  $global:NISTcit='AC-7b'
  $global:finding='Unlock TImeout after user account is locked out'
  $global:xResult= '900'
  $global:command='(Get-VMHost -Name $VMHost)| Get-AdvancedSetting -Name Security.AccountUnlockTime | Select-Object -ExpandProperty Value'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}


Function NIST800-53-VI-ESXi-CFG-00166 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00166'
  $global:description='The ESXi host must disable the Managed Object Browser (MOB).'
  $global:NISTcit='CM-7a.'
  $global:finding='MOB Enabled'
  $global:xResult='False'
  $global:command='(Get-AdvancedSetting $VMHost -Name Config.HostAgent.plugins.solo.enableMob).Value'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $False) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-00168 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00168'
  $global:description='Set a timeout to automatically terminate idle DCUI sessions'
  $global:NISTcit='AC-12 Control'
  $global:finding='Timeout configured to automatically terminate idle DCUI sessions'
  $global:xResult= '600'
  $global:command='(Get-VMHost -Name $VMHost)| Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Select-Object -ExpandProperty Value'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-00169 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00169'
  $global:description='Use of the dvFilter network APIs must be restricted'
  $global:NISTcit='CM-7a'
  $global:finding='Use of the dvFilter network APIs must be restricted'
  $global:xResult= ''
  $global:command='(Get-VMHost -Name $VMHost)| Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Select-Object -ExpandProperty Value'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-00179 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00179'
  $global:description='ESXi host must produce audit records containing information to establish what type of events occurred'
  $global:NISTcit='AU-3 Control'
  $global:finding='Audit Records - Events Log Level'
  $global:xResult= 'info'
  $global:command='(Get-VMHost -Name $VMHost)| Get-AdvancedSetting -Name Config.HostAgent.log.level | Select-Object -ExpandProperty Value'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}


Function NIST800-53-VI-ESXi-CFG-00564 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00564'
  $global:description='ESXi host must configure host client session timeout'
  $global:NISTcit='AC-11a'
  $global:finding='ESXi host must configure host client session timeout'
  $global:xResult= '900'
  $global:command='(Get-VMHost -Name $VMHost)| Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout | Select-Object -ExpandProperty Value'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}


Function NIST800-53-VI-ESXi-CFG-01100 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-01100'
  $global:description='Verify if only FIPS-Approved ciphers are in use'
  $global:NISTcit='SC-12(2)'
  $global:finding='ESXi host SSH daemon must use FIPS 140-2 validated cryptographic modules'
  $global:xResult='FIPSMode yes'
  $global:command='grep -i "^FipsMode" /etc/ssh/sshd_config'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

       $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-01102 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-01102'
  $global:description='Enable bidirectional CHAP authentication for iSCSI traffic'
  $global:NISTcit='CM-6b'
  $global:finding='Enable bidirectional CHAP authentication for iSCSI traffic'
  $global:xResult=''
  $global:command='(Get-VMHost -Name $VMHost) | Get-VMHostHba | Where {$_.Type -eq "iscsi"} | Select AuthenticationProperties -ExpandProperty AuthenticationProperties'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}


Function NIST800-53-VI-ESXi-CFG-01106 {
    $global:VMWConfig='NIST800-53-VI-ESXi-CFG-01106'
    $global:description='Do not provide root or administrator level access to CIM-based hardware monitoring tools'
    $global:NISTcit='A.9.2.3 Control'
    $global:finding='If there is no dedicated CIM service account orthe CIM service account has more permissions than necessary, this is a finding.    '
    $global:xResult='Manual Verification'
    $global:command='From the Host Client, select the ESXi host, right click and go to "Permissions". Verify the CIM service account is assigned the "Read-only" role or a custom role as described in the discussion. '
    
    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      $result = "Manual Verification"

        Write-Host $VMHost -NoNewLine

        Write-Host `t`t`t$result

        $global:result_array = $global:result_array+$result
    }
  }

Function NIST800-53-VI-ESXi-CFG-01107 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-01107'
  $global:description='The ESXi host must exclusively enable TLS 1.2 for all endpoints'
  $global:NISTcit='SC-23'
  $global:finding='Disabled TLS Protocols'
  $global:xResult='sslv3,tlsv1,tlsv1.1'
  $global:command='(Get-VMHost -Name $VMHost) | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Select-Object -ExpandProperty value'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-01108 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-01108'
  $global:description='Enable secure boot on the host'
  $global:NISTcit='CM-6b'
  $global:finding='Enable secure boot on the host'
  $global:xResult='Enabled'
  $global:command='/usr/lib/vmware/secureboot/bin/secureBoot.py -s'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

       $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-01109 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-01109'
  $global:description='Configure the ESXi hosts to only run executable files from approved VIBs'
  $global:NISTcit='CM-6b'
  $global:finding='Configure the ESXi hosts to only run executable files from approved VIB'
  $global:xResult='True'
  $global:command='(Get-VMHost -Name $VMHost) | Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly | Select-Object -ExpandProperty Value'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-01110 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-01110'
  $global:description='The ESXi host must not suppress warnings about unmitigated hyperthreading vulnerabilities'
  $global:NISTcit='CM-11(1)'
  $global:finding='The ESXi host must not suppress warnings about unmitigated hyperthreading vulnerabilities'
  $global:xResult='0'
  $global:command='(Get-VMHost -Name $VMHost) | Get-AdvancedSetting -Name UserVars.SuppressHyperthreadWarning | Select-Object -ExpandProperty value'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-01111 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-01111'
  $global:description='Disable port forwarding for the ESXi host SSH daemon'
  $global:NISTcit='CM-6b'
  $global:finding='Disable port forwarding for the ESXi host SSH daemon'
  $global:xResult='allowtcpforwarding no'
  $global:command='/usr/lib/vmware/openssh/bin/sshd -T|grep allowtcpforwarding'
  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

       $global:result_array = $global:result_array+$result
  }
}

Function NIST800-53-VI-ESXi-CFG-01112 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-01112'
  $global:description='Disable the OpenSLP service on the host'
  $global:NISTcit='CM-6b'
  $global:finding='Disable the OpenSLP service on the host'
  $global:xResult='slpd                    off'
  $global:command='chkconfig --list | grep slpd'

  fn_Print_ESX_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output

            $result = $result -replace '\s+', '|'

            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

      }

       $global:result_array = $global:result_array+$result
  }
}


Function NIST800-53-VI-ESXi-CFG-01113 {
    $global:VMWConfig='NIST800-53-VI-ESXi-CFG-01113'
    $global:description='The ESXi host must use approved certificates'
    $global:NISTcit='Not Applicable'
    $global:finding='If the issuer is not an approved certificate authority, this is a finding. If the host will never be accessed directly '
    $global:xResult='Manual Verification'
    $global:command='Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Certificate. '
    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      $result = "Manual Verification"

        Write-Host $VMHost -NoNewLine

        if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

        Write-Host `t`t`t$result

        $global:result_array = $global:result_array+$result
    }#
  }

  Function NIST800-53-VI-ESXi-CFG-00022 {
    $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00022'
    $global:description='The ESXi host must enforce password complexity.'
    $global:NISTcit='IA-5(1)(a)'
    $global:finding='If the Security.PasswordQualityControl setting is not set to "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15", this is a finding.'
    $global:xResult='similar=deny retry=3 min=disabled,disabled,disabled,disabled,15'
    $global:command='(Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl).value'
    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
  }

  Function NIST800-53-VI-ESXi-CFG-01114 {
    $global:VMWConfig='NIST800-53-VI-ESXi-CFG-01114'
    $global:description='SNMP must be configured properly on the ESXi host.'
    $global:NISTcit='CM-7a'
    $global:finding='If SNMP is not in use and is enabled, is enabled and read only communities is set to "public", or is enabled and is not using v3 targets, this is a finding.'
    $global:xResult='Site Specific'
    $global:command='Get-VMHostSnmp | Select *'

    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
  }

  Function NIST800-53-VI-ESXi-CFG-01115 {
    $global:VMWConfig='NIST800-53-VI-ESXi-CFG-01115'
    $global:description='The ESXi host must verify certificates for SSL syslog endpoints.'
    $global:NISTcit='SC-17'
    $global:finding='If the "Syslog.global.logCheckSSLCerts" setting is not set to "true", this is a finding.'
    $global:xResult='TRUE'
    $global:command='(Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logCheckSSLCerts).value'

    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
  }

  Function NIST800-53-VI-ESXi-CFG-01116 {
    $global:VMWConfig='NIST800-53-VI-ESXi-CFG-01116'
    $global:description='The ESXi host must configure a session timeout for the vSphere API.'
    $global:NISTcit='SC-12'
    $global:finding='If the "Config.HostAgent.vmacore.soap.sessionTimeout" setting is not set to "30", this is a finding.'
    $global:xResult='30'
    $global:command='(Get-VMHost $VMHost | Get-AdvancedSetting -Name Config.HostAgent.vmacore.soap.sessionTimeout).value'

    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
  }

  Function NIST800-53-VI-ESXi-CFG-01117 {
    $global:VMWConfig='NIST800-53-VI-ESXi-CFG-01117'
    $global:description='The ESXi host rhttpproxy daemon must use FIPS 140-2 validated cryptographic modules to protect the confidentiality of remote access sessions.'
    $global:NISTcit='SC-23(5)'
    $global:finding='If the output does not match the expected result, this is a finding.'
    $global:xResult='Enabled: TRUE'
    $global:command='(Get-EsxCLI -v2 -VMHost $VMHost).system.security.fips140.rhttpproxy.get.invoke() | Select-Object -ExpandProperty Enabled'

    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
  }

  Function NIST800-53-VI-ESXi-CFG-01118 {
    $VMWConfig='NIST800-53-VI-ESXi-CFG-01118'
    $description='The ESXi host must not be configured to override virtual machine configurations.'
    $NISTcit='N/A'
    $finding='If the output does not match the expected result, this is a finding.'
    $xresult='0'
    $command='stat -c "%s" /etc/vmware/settings'

    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {
      if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true

            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output

            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

      } else {

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor
         }
        
       $global:result_array = $global:result_array+$result
    }
    
  }

  Function NIST800-53-VI-ESXi-CFG-01119 {
    $VMWConfig='NIST800-53-VI-ESXi-CFG-01119'
    $description='The ESXi host must not be configured to override virtual machine logger settings.'
    $NISTcit='N/A'
    $finding='If the command produces any output, this is a finding.'
    $xresult='NULL'
    $command='grep "^vmx\.log" /etc/vmware/config'

    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {
      if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

      } else {

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor
         }
        
       $global:result_array = $global:result_array+$result
    }  
  }

  Function ESXI-70-000274 {
    $VMWConfig='ESXI-70-000274'
    $description='ESXi host SSH daemon must be configured to only use FIPS 140-2 validated ciphers'
    $NISTcit='SC-13'
    $finding='output does not match the expected result, this is a finding.'
    $xresult='ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'
    $command='/usr/lib/vmware/openssh/bin/sshd -T|grep ciphers'

    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {
      if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

      } else {

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor
         }
        
       $global:result_array = $global:result_array+$result
    }
   
    

    
  }
  Function ESXI-70-000038 {
    $VMWConfig='ESXI-70-000038'
    $description='ESXi hosts using Host Profiles and/or Auto Deploy must use the vSphere Authentication Proxy to protect passwords when adding themselves to Active Directory'
    $NISTcit='IA-2'
    $finding='If the organization is not using Host Profiles to join Active Directory, this is not applicable. If "JoinADEnabled" is "True" and "JoinDomainMethod" is not "FixedCAMConfigOption", this is a finding.'
    $xresult='"Join Domain Method" to "Use vSphere Authentication Proxy to add the host to domain" and provide the IP address of the vSphere Authentication Proxy server'
    $command='Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}'

    fn_Print_ESX_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {
      if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

      } else {

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:ESXSSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor
         }
        
       $global:result_array = $global:result_array+$result
    }
   
    

    
  }


#######################################################################
#################       VM CONTROL FUNCTIONS       ####################
#######################################################################
  
Function NIST800-53-VI-VC-CFG-00065{

    $global:VMWConfig='NIST800-53-VI-VC-CFG-00065 - 67 & 00156'
    $global:description='Remove unnecessary virtual hardware devices from the VM.'
    $global:NISTcit='P0'
    $global:finding='Ensure that no device is connected to a virtual machine if it is not required. For example, serial and parallel ports are rarely used for virtual machines in a datacenter environment, and CD/DVD drives are usually connected only temporarily during software installation. USB devices, sound cards, and other unnecessary hardware may be introduced with migrations from VMware Workstation, Fusion, or through other tools. Any enabled or connected device represents a potential attack channel, through the possibility of device drivers that contain vulnerabilities, by granting the ability to introduce software or exfiltrate data to or from a protected environment.'
    $global:xResult='Review and disable/remove any unnecessary hardware'
    $global:command='(Get-VM $VM | Get-View).Config.Hardware.Device | Where-Object {$_.GetType().Name -match $UnnecessaryHardware} | Foreach-Object {$_.DeviceInfo.Label}'

    fn_Print_VM_Control_Info

    if($global:allVM)
    {
        foreach ($VM in $global:allVM ) {   
        $result = Invoke-Expression $global:command.tostring()

        if (!$result) {$result = "Not Set"}

       Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

        if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

        Write-Host `t`t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
  }
}

Function NIST800-53-VI-VC-CFG-00155{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00155'
  $global:description='Unauthorized floppy devices must be disconnected on the virtual machine.'
  $global:NISTcit='P1 - MP-7 Control'
  $global:finding='If a virtual machine has a floppy drive connected, this is a finding.' 
  $global:xResult='Review and disable/remove any unnecessary hardware'
  $global:command='Get-VM -Name $VM | Get-FloppyDrive | Select Parent, Name, ConnectionState'

  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

    if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}
}

Function NIST800-53-VI-VC-CFG-00068{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00068'
  $global:description='Shared salt values must be disabled on the virtual machine.'
  $global:NISTcit='P2 - CM-6b'
  $global:finding='If the virtual machine advanced setting "sched.mem.pshare.salt" exists, this is a finding.'
  $global:xResult='Not Set'
  $global:command='Get-VM -Name $VM | Get-AdvancedSetting -Name sched.mem.pshare.salt'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

      Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
    }
  }
}

Function NIST800-53-VI-VC-CFG-00070{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00070'
  $global:description='Disable drag & drop console functionality.'
  $global:NISTcit='P2'
  $global:finding='When this is set to TRUE a user at the console of a VM (Web Console, VMRC, or other) will not be able to drag and drop data between the VM and the local client. As the default is the desired state you can audit by verifying that the parameter is either unset, or that it is set to the suggested value.'
  $global:xResult='TRUE'
  $global:command='Get-VM -Name $VM | Get-AdvancedSetting isolation.tools.dnd.disable'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}
}

Function NIST800-53-VI-VC-CFG-00071{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00071'
  $global:description='Explicitly disable console copy operations.'
  $global:NISTcit='P2'
  $global:finding='When this is set to TRUE a user at the console of a VM (Web Console, VMRC, or other) will not be able to copy data between the VM and the local client. As the default is the desired state you can audit by verifying that the parameter is either unset, or that it is set to the suggested value.'
  $global:xResult='TRUE'
  $global:command='Get-VM -Name $VM | Get-AdvancedSetting isolation.tools.copy.disable'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   } 
 }
}

Function NIST800-53-VI-VC-CFG-00073{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00073'
  $global:description='Explicitly disable paste operations.'
  $global:NISTcit='P2'
  $global:finding='When this is set to TRUE a user at the console of a VM (Web Console, VMRC, or other) will not be able to paste data between the VM and the local client. As the default is the desired state you can audit by verifying that the parameter is either unset, or that it is set to the suggested value.'
  $global:xResult='TRUE'
  $global:command='Get-VM -Name $VM | Get-AdvancedSetting isolation.tools.paste.disable'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-00074{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00074'
  $global:description='Disable virtual disk shrinking.'
  $global:NISTcit='P2'
  $global:finding='Repeated disk shrinking can make a virtual disk unavailable. Limited capability is available to non-administrative users in the guest. As the default is the desired state you can audit by verifying that the parameter is either unset, or that it is set to the suggested value.'
  $global:xResult='TRUE'
  $global:command='Get-VM -Name $VM | Get-AdvancedSetting isolation.tools.diskShrink.disable'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-00075{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00075'
  $global:description='Disable virtual disk wiping.'
  $global:NISTcit='P2'
  $global:finding='Repeated disk shrinking can make a virtual disk unavailable. Limited capability is available to non-administrative users in the guest. As the default is the desired state you can audit by verifying that the parameter is either unset, or that it is set to the suggested value.'
  $global:xResult='TRUE'
  $global:command='Get-VM -Name $VM | Get-AdvancedSetting isolation.tools.diskWiper.disable'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-00076{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00076'
  $global:description='An unimplemented parameter on ESXi.'
  $global:NISTcit='P2'
  $global:finding='This parameter may be applicable to other VMware products, but is not applicable to vSphere. It is not implemented on ESXi. Setting or changing this parameter has no effect on security on ESXi.'
  $global:xResult='TRUE'
  $global:command='Get-VM -Name $VM | Get-AdvancedSetting isolation.tools.hgfsServerSet.disable'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-00097{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00097'
  $global:description='Limit the number of console connections.'
  $global:NISTcit='P0'
  $global:finding='Multiple users can connect to a single VM console and observe activity. Limiting this to 1 prevents this behavior.'
  $global:xResult='1'
  $global:command='Get-VM -Name $VM | Get-AdvancedSetting RemoteDisplay.maxConnections'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-00099{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00099'
  $global:description='Limit informational messages from the VM to the VMX file.'
  $global:NISTcit='P1'
  $global:finding='The configuration file containing these name-value pairs is limited to a size of 1 MB by default. This limit is applied even when the sizeLimit parameter is not listed in the .vmx file. Uncontrolled size for the VMX file can lead to denial of service if the datastore is filled.As the default is the desired state you can audit by verifying that the parameter is either unset, or that it is set to the suggested value.'
  $global:xResult='1048576'
  $global:command='Get-VM -Name $VM | Get-AdvancedSetting -Name tools.setInfo.sizeLimit'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-00102{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00102'
  $global:description='Do not send host information to guests.'
  $global:NISTcit='P2'
  $global:finding='By enabling a VM to get detailed information about the physical host, an adversary could potentially use this information to inform further attacks on the host. As the default is the desired state you can audit by verifying that the parameter is either unset, or that it is set to the suggested value.'
  $global:xResult='FALSE'
  $global:command = 'Get-VM $vm | Get-AdvancedSetting -Name tools.guestlib.enableHostInfo | Select-Object -Property Name, Value'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}
Function NIST800-53-VI-VC-CFG-00097{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00097'
  $global:description='Lock the VM guest session when the remote console is disconnected.'
  $global:NISTcit='P2'
  $global:finding='An attacker can take advantage of console sessions left logged in.'
  $global:xResult='TRUE'
  $global:command='(Get-VM -Name $VM | Get-AdvancedSetting tools.guest.desktop.autolock).value'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}



Function NIST800-53-VI-VC-CFG-01215{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-01215'
  $global:description='Control access to VMs through the dvfilter network APIs.'
  $global:NISTcit='P2'
  $global:finding='An attacker might compromise a VM by making use the dvFilter API. Configure only those VMs to use the API that need this access. This setting is considered an "Audit Only" guideline. If there is a value present, the admin should check it to ensure it is correct.'
  $global:xResult='TRUE'
  $global:command='Get-VM -Name $VM | Get-AdvancedSetting -Name  "ethernet*.filter*.name*" | Select Entity, Name, Value'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-01232{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-01232'
  $global:description='Lock the VM guest session when the remote console is disconnected.'
  $global:NISTcit='P2'
  $global:finding='An attacker can take advantage of console sessions left logged in.'
  $global:xResult='TRUE'
  $global:command='Get-VM -Name $VM | Get-AdvancedSetting tools.guest.desktop.autolock'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-01234{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-01234'
  $global:description='Require encryption during vMotion.'
  $global:NISTcit='P1'
  $global:finding='By default a VM uses "opportunistic" vMotion encryption, so migrations to another host use encryption if available, but if not it will vMotion without encryption. Setting this to "required" ensures that if encryption is not available the vMotion does not proceed.'
  $global:xResult='required'
  $global:command='(Get-VM $vm).ExtensionData.Config.MigrateEncryption'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-00154{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00154'
  $global:description='VMs with Independent non-persistent disks.'
  $global:NISTcit='P1'
  $global:finding='VMs with Independent non-persistent disks.'
  $global:xResult='TRUE'
  $global:command='Get-VM $vm | Get-HardDisk'
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if ($result -like "Persistent") {$result = "FALSE"} else {$result = "TRUE"}

     Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-00561{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00561'
  $global:description='Limit PCI device passthrough functionality.'
  $global:NISTcit='P1'
  $global:finding='VThe VMware DirectPath I/O features allow virtual machines to access system hardware directly. This has implications for risk mitigation features such as vMotion, DRS, and High Availability, but also may allow an attacker more privileged access to underlying hardware and the system bus. Ensure that VMs allowed to access hardware directly need this privilege and add compensating controls to ensure the guest OS security.'
  $global:xResult='Not Set'
  $global:command = 'Get-VM $vm | Get-AdvancedSetting -Name pciPassthru*.present | Select-Object -Property Name, Value'
  
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

      Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-01233{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-01233'
  $global:description='Disable 3D features if not needed.'
  $global:NISTcit='P1'
  $global:finding='It is suggested that 3D be disabled on virtual machines that do not require 3D functionality, (e.g. server or desktops not using 3D applications). This reduces attack surface.'
  $global:xResult='FALSE'
  $global:command = 'Get-VM $VM | Get-AdvancedSetting -Name mks.enable3d | Select-Object -ExpandProperty Value'
  
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

      Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-00097{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00097'
  $global:description='An unimplemented parameter on ESXi.'
  $global:NISTcit='P1'
  $global:finding='This parameter applies to an ESXi feature that is no longer present in this product version. Setting or changing this parameter has no effect on security.'
  $global:xResult='Not Set'
  $global:command = 'Get-VM -Name $VM | Get-AdvancedSetting RemoteDisplay.vnc.enabled'
  
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

      Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-01244{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-01244'
  $global:description='Require encryption for Fault Tolerance logging.'
  $global:NISTcit='P1'
  $global:finding='By default a VM uses "opportunistic" vMotion encryption, so migrations to another host use encryption if available, but if not it will vMotion without encryption. Setting this to "required" ensures that if encryption is not available the vMotion does not proceed.'
  $global:xResult='ftEncryptionOpportunistic'
  $global:command = '(Get-VM -Name $VM).ExtensionData.Config.FtEncryptionMode'
  
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

      Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-00101{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00101'
  $global:description='Disable the ability for unprivileged users to connect & disconnect virtual machine devices'
  $global:NISTcit='P1'
  $global:finding='Users and processes without root or administrator privileges within virtual machines can connect or disconnect devices, such as network adapters and CD-ROM drives, and can modify device settings. This could lead to unauthorized access, disruption of operations, and denial of service. As the default is the desired state you can audit by verifying that the parameter is either unset, or that it is set to the suggested value.'
  $global:xResult='TRUE'
  $global:command = 'Get-VM -Name $VM | Get-AdvancedSetting isolation.device.connectable.disable'
  
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

      Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-XX103{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-XX103'
  $global:description='Disable the ability for unprivileged users to connect & disconnect virtual machine devices'
  $global:NISTcit='P0'
  $global:finding='Users and processes without root or administrator privileges within virtual machines can connect or disconnect devices, such as network adapters and CD-ROM drives, and can modify device settings. This could lead to unauthorized access, disruption of operations, and denial of service.'
  $global:xResult='TRUE'
  $global:command = 'Get-VM -Name $VM | Get-AdvancedSetting isolation.device.edit.disable'
  
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

      Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-XX104{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-XX104'
  $global:description='An unimplemented parameter on ESXi.'
  $global:NISTcit='P0'
  $global:finding='This parameter may be applicable to other VMware products, but is not applicable to vSphere. It is not implemented on ESXi. Setting or changing this parameter has no effect on security on ESXi.'
  $global:xResult='Not Set'
  $global:command = 'Get-VM -Name $VM | Get-AdvancedSetting isolation.device.edit.disable'
  
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

      Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-XX105{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-XX105'
  $global:description='Disable GUI operations in a virtual machine.'
  $global:NISTcit='P2'
  $global:finding='"Copy and paste operations are disabled by default; however, by explicitly disabling this feature it will enable audit controls to check that this setting is correct. Copy, paste, drag and drop, or GUI copy/paste operations between the guest OS and the remote console could provide the means for an attacker to compromise the VM. As the default is the desired state you can audit by verifying that the parameter is either unset, or that it is set to the suggested value."'
  $global:xResult='FALSE'
  $global:command = 'Get-VM -Name $VM | Get-AdvancedSetting isolation.tools.setGUIOptions.enable'
  
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

      Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-00093{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-00093'
  $global:description='Disable drag & drop console functionality.'
  $global:NISTcit='P2'
  $global:finding='When this is set to TRUE a user at the console of a VM (Web Console, VMRC, or other) will not be able to drag and drop data between the VM and the local client. As the default is the desired state you can audit by verifying that the parameter is either unset, or that it is set to the suggested value.'
  $global:xResult='TRUE'
  $global:command = 'Get-VM -Name $VM | Get-AdvancedSetting isolation.tools.vmxDnDVersionGet.disable'
  
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

      Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-01243{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-01243'
  $global:description='Limit the number of retained VM diagnostic logs.'
  $global:NISTcit='P1'
  $global:finding='By default there is a limit of 6 old diagnostic logs. The VMware documentation recommends setting this to 10 to conserve datastore space but also enable troubleshooting should it need to occur.'
  $global:xResult='10'
  $global:command = 'Get-VM -Name $VM | Get-AdvancedSetting log.keepOld'
  
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

      Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-01242{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-01242'
  $global:description='Limit the size of VM diagnostic logs.'
  $global:NISTcit='P0'
  $global:finding='By default there is no limit on VM diagnostic log sizes, and they are rotated when the VM changes power state or live-migrates using vMotion. On long-running VMs this may consume considerable space. The VMware documentation recommends setting this no lower than 2 MB (measured in KB).'
  $global:xResult='10'
  $global:command = 'Get-VM -Name $VM | Get-AdvancedSetting log.rotateSize'
  
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

      Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-XX109{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-XX109'
  $global:description='Limits the virtual machine to VGA graphics.'
  $global:NISTcit='P2'
  $global:finding='The guidance for this parameter has changed due to serious compatibility issues with modern guest operating systems, versus the limited benefit it provided. Do not set this on new virtual machines. As the default is the desired state you can audit by verifying that the parameter is either unset, or that it is set to the suggested value.'
  $global:xResult='FALSE'
  $global:command = 'Get-VM -Name $VM | Get-AdvancedSetting svga.vgaOnly'
  
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

      Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

Function NIST800-53-VI-VC-CFG-X0415{

  $global:VMWConfig='NIST800-53-VI-VC-CFG-X0415'
  $global:description='The vCenter Server users must have the correct roles assigned.'
  $global:NISTcit='AC-6 Control'
  $global:finding='The guidance for this parameter has changed due to serious compatibility issues with modern guest operating systems, versus the limited benefit it provided. Do not set this on new virtual machines. As the default is the desired state you can audit by verifying that the parameter is either unset, or that it is set to the suggested value.'
  $global:xResult='FALSE'
  $global:command = 'Get-VM -Name $VM | Get-AdvancedSetting svga.vgaOnly'
  
  fn_Print_VM_Control_Info

  if($global:allVM )
  {
      foreach ($VM in $global:allVM ) {   
      $result = Invoke-Expression $global:command.tostring()

      if (!$result) {$result = "Not Set"}

      Write-Host $VM -NoNewLine

      if ($VM.Name.length -le 7) {Write-Host `t -NoNewLine}  

      if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

      Write-Host `t`t`t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
   }
 }
}

######################################################################################################################################################################################################################################################################################################
######################################################################################################################################################################################################################################################################################################
######################################################################################################################################################################################################################################################################################################
Function fn_RequestSDDCToken {

  Clear-Host
  Write-Host "Preparing SDDC Manager API Token..."
  Write-Host
  $uri = 'https://'+$global:SDDCmgr+'/v1/tokens' # Set URI for executing an API call to validate authentication
  $command='curl -X POST -H "Content-Type:application/json" -d ''{"username": "'+$global:VCuser+'", "password": "'+$global:VCpass+'"}'' --insecure ' +$uri
  $result = Invoke-Expression $command
  $APITokenArray = $result -split '"'
  $global:accessToken = $APITokenArray[3]
  $global:refreshToken = $APITokenArray[9]
  Write-Host "Building VCF YAML files..." -ForegroundColor Green
  $command = 'mv /root/dod-compliance-and-automation/vcf/4.x/inspec/vmware-vcf-sddcmgr-4x-stig-baseline/inputs-vcf-sddc-mgr-4x.yml /root/dod-compliance-and-automation/vcf/4.x/inspec/vmware-vcf-sddcmgr-4x-stig-baseline/inputs-vcf-sddc-mgr-4x.yml.bak'
  Invoke-Expression $command
  Add-Content  -Path /root/dod-compliance-and-automation/vcf/4.x/inspec/vmware-vcf-sddcmgr-4x-stig-baseline/inputs-vcf-sddc-mgr-4x.yml -Value "
  # NGINX
  nginx_conf_path: /etc/nginx/nginx.conf
  limit_conn_ip_limit: '100'
  limit_conn_server_limit: '1000'
  nginx_ssl_ciphers: 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'
  # Photon
  authprivlog: /var/log/audit/auth.log
  sshdcommand: ""sshd -T -C 'user=root'""
  syslogServer: 'replace.local:514'
  # SDDC Manager Application
  sddcManager: '$global:SDDCmgr'
  bearerToken: 'Bearer $global:accessToken'
  sftpBackupsEnabled: true
  sftpServer: '$global:SFTPServer'
  ntpServers: ['$global:NTPServer']
  currentVersion: '4.4.0.0-19312029' 
  myVmwareAccount: 'myvmwarevcfaccount@test.local' " 
  Write-Host "VCF YAML Files Updated."
  fn_PressAnyKey
}

Function fn_RequestNSXToken {
  Clear-Host
  Write-Host "Preparing NSX-T Manager API Token..." -ForegroundColor Green
  $uri = "https://$global:NSXmgr/api/session/create" # Set URI for executing an API call to validate authentication
  $command = "curl -k -s -c cookies.txt -D headers.txt -X POST -d 'j_username=$global:NSXTAdminUser&j_password=$global:NSXTAdminPass' $uri"
  Invoke-Expression $command
  $file_data = Get-Content headers.txt | select -first 2 -skip 1
  $global:jsessionid = $file_data[0] -replace ".*JSESSIONID=" -replace "\; Path=.*" -replace "X-XSRF.*"
  $global:xxsrftoken = $file_data[1] -replace ".*:" -replace ".*HttpOnly" -replace ".* "
  # Write-Host "JSESSION:..."$global:jsessionid -ForegroundColor Yellow
  # Write-Host "X-XSRF-TOKEN:..."$global:xxsrftoken -ForegroundColor Yellow
  $command = "rm cookies.txt"
  Invoke-Expression $command
  $command = "rm headers.txt"  
  Invoke-Expression $command
  Write-Host "Building YAML files..." -ForegroundColor Green
  $command= 'mv /root/dod-compliance-and-automation/nsx/3.x/inspec/vmware-nsxt-3.x-stig-baseline-master/inputs-nsxt-3.x.yml /root/dod-compliance-and-automation/nsx/3.x/inspec/vmware-nsxt-3.x-stig-baseline-master/inputs-nsxt-3.x.bak'
  Invoke-Expression $command
  Add-Content  -Path /root/dod-compliance-and-automation/nsx/3.x/inspec/vmware-nsxt-3.x-stig-baseline-master/inputs-nsxt-3.x.yml -Value "
  # General
  nsxManager: '$global:NSXmgr'
  sessionToken: '$global:xxsrftoken'
  sessionCookieId: 'JSESSIONID=$global:jsessionid'
  # Manager
  syslogServers:
    - 'loginsight.vmware.com'
    - 'log.test.local'
  ntpServer1: 'time.vmware.com'
  ntpServer2: 'time.vmware.com'
  nsxtVersion: '3.2.3.0'
  t0multicastlist: []
  t0mcinterfacelist: []
  t0dhcplist: []
  t1dhcplist: []
  t1multicastlist: [] "
  $command= 'mv /root/dod-compliance-and-automation/nsx/3.x/inspec/vmware-nsxt-3.x-stig-baseline-master/inspec.yml /root/dod-compliance-and-automation/nsx/3.x/inspec/vmware-nsxt-3.x-stig-baseline-master/inspec.bak'
  Invoke-Expression $command
  Add-Content  -Path /root/dod-compliance-and-automation/nsx/3.x/inspec/vmware-nsxt-3.x-stig-baseline-master/inspec.yml -Value "
  name: vmware-nsxt-3.0-stig-inspec-baseline
  title: VMware NSX-T STIG InSpec Profile
  maintainer: The Authors
  copyright: The Authors
  copyright_email: stigs@vmware.com
  license: Apache-2.0
  summary: InSpec Compliance Profile for NSX-T 3.x
  version: 1.2

  inputs:
  - name: nsxManager
    type: string
    value: '$global:NSXmgr'
    description: 'IP or FQDN of NSX-T Manager'
  # We use session based authentication in this profile to avoid username/pass   See https://developer.vmware.com/apis/1248/nsx-t on how to generate the session token and you will also need the JSESSIONID cookie
  - name: sessionToken
    type: string
    value: '$global:xxsrftoken'
    description: 'X-XSRF-TOKEN session token for authentication'
    sensitive: true
  - name: sessionCookieId
    type: string
    value: 'JSESSIONID=$global:jsessionid'
    description: 'JSESSIONID Cookie in the format JSESSIONID=ECEF0CE603677B7FC5F34523714B7F5A for example'
    sensitive: true
  - name: syslogServers
    type: array
    value: ['loginsight.vmware.com','log.test.local']
    description: 'TNDM-3X-000034 enter array of valid syslog servers'

  depends:
    - name: dfw
      path: dfw
    - name: manager
      path: manager
    - name: sdn
      path: sdn
    - name: t0fw
      path: t0fw
    - name: t0router
      path: t0router
    - name: t1fw
      path: t1fw
    - name: t1router
      path: t1router"

  Write-Host "NSX-T YAML Files Updated."
  fn_PressAnyKey
}

Function fn_getNSXCreds {
  Clear-Host
# Determine if NSX Credentials are Valid
  if ($global:NSXRootCreds -ne '') { 
    Write-Host "Currently using: " -ForegroundColor Green -NoNewline
    Write-Host $global:NSXRootUser -ForegroundColor Yellow 
    $passlength = ($global:NSXRootPass.Length)-4
    $obs_RootPass = $global:NSXRootPass.substring(0,2) 
    For ($i = 0; $i -lt $passlength; $i++) {
          $obs_RootPass += "*"
        }
    $obs_RootPass = $obs_RootPass.Substring($passlength,-2)
    Write-Host "With password: "$obs_RootPass ForegroundColor Yellow -NoNewline
    Write-Host
    $ChangeNSXCreds = Read-Host "Continue with this SSH Account (Y/N)?" -ForegroundColor Green -NoNewline
    if ($ChangeNSXCreds -eq 'N') {
      $global:NSXRootCreds = ''
      fn_getNSXCreds
    }
  }
  if ($global:NSXmgr -eq '') {
    Write-Host "NSX-T Manager Information:" -ForegroundColor Green 
    Write-Host
    Write-Host "Enter the IP Address or FQDN of the NSX-T Manager: " -ForegroundColor Green -NoNewLine
    $global:NSXmgr = Read-Host
    Write-Host
    Write-Host "Testing ability to find $global:NSXmgr..."
    if (!(Test-Connection -ComputerName $global:NSXmgr -Quiet -Count 2)) {
      Write-Host "Unable to find $global:NSXmgr " -ForegroundColor Red
      Write-Host "Verify correct FQDN, DNS, and IP Configuration and try again." -ForegroundColor Red
      Write-host
      fn_PressAnyKey
      fn_getNSXCreds
    } 
    Write-Host "Connectivity to $global:NSXmgr verified." -ForegroundColor Green
    Write-Host
  } else {
    Write-Host "You are currently connected to NSX Manager" -ForegroundColor Green -NoNewline
    Write-Host $global:NSXmgr -ForegroundColor Yellow
    Write-Host
    $ChangeNSXMgr = Read-Host "Change NSX Manager (Y/N)?" -NoNewline
    
    if ($ChangeNSXMgr -eq 'Y') {
      $global:NSXmgr = ''
      fn_GetNSXCreds
    }
  }

  DO {
    Clear-Host
    Write-Host "!! " -ForegroundColor Red -NoNewLine 
    Write-Host "This process requires ROOT for SSH and ADMIN for API access to the NSX-T Manager " -ForegroundColor Green -NoNewLine
    Write-Host "!!" -ForegroundColor Red
    Write-Host
    Write-Host "It may be necessary to edit the /etc/ssh/sshd_config on the NSX-T Manager and verify " -ForegroundColor Green -NoNewLine
    Write-Host "'PermitRootLogin'" -ForegroundColor Yellow -NoNewLine
    Write-Host " should be set to " -ForegroundColor Green -NoNewLine
    Write-Host "'yes'"-ForegroundColor Yellow
    Write-Host
    Write-Host "Enter the " -ForegroundColor Green -NoNewline
    Write-Host "ROOT" -ForegroundColor Yellow -NoNewline
    Write-Host " Credentials for $global:NSXmgr" -ForegroundColor Green
    $global:NSXRootCreds = Get-Credential
    $global:NSXRootUser= $global:NSXRootCreds.UserName.ToString()
    $global:NSXRootPass = $global:NSXRootCreds.GetNetworkCredential().password
    Write-Host
    Write-Host "Verifying SSH to NSX-T Manager $global:NSXmgr :"
    $global:NSXSSHConection = New-SSHSession -ComputerName $global:NSXmgr -Credential $global:NSXRootCreds -AcceptKey:$true -ErrorAction ignore
    if (!$global:NSXSSHConection.Connected) {
      Write-Host "SSH Credentials Failed for NSX Manager." -ForegroundColor Red
      fn_PressAnyKey  
    } 
  } while (!$global:NSXSSHConection.Connected)
  $SSHCommand = 'ls'
  Write-Host "NSX-T Manager SSH Test Successful" -ForegroundColor Green
  Write-Host "SSH Session State:" $global:NSXSSHConection.Connected
  fn_PressAnyKey
  Clear-Host
  Write-Host "Enter the " -ForegroundColor Green -NoNewline
  Write-Host "ADMIN" -ForegroundColor Yellow -NoNewline
  Write-Host " Credentials for API Processes on $global:NSXmgr" -ForegroundColor Green
  $global:NSXTAdminCreds = Get-Credential
  $global:NSXTAdminUser= $NSXTAdminCreds.UserName.ToString()
  $global:NSXTAdminPass = $NSXTAdminCreds.GetNetworkCredential().password
 # Write-Host
 fn_RequestNSXToken
 Write-Host "Back from Requesting token..."
 fn_PressAnyKey
}

Function fn_GetSddcCreds {
  Clear-Host
# Determine if vCenter Credentials are Defined
  if ($global:defaultVIServer -eq 'Not Connected') {
    Write-Host "No vCenter SSO Credentials Identified." -ForegroundColor Red
    Write-Host "You must connect to the linked vCenter Server to continue." -ForegroundColor Yellow
    fn_PressAnyKey
    fn_GetvCenterCreds
  }
# Determine if SDDC Connection Exist or Switch Manager
  if ($global:SDDCmgr -ne "Not Connected") {
    Write-Host "Currently connected to: " -ForegroundColor Green -NoNewline
    Write-Host $global:SDDCmgr -ForegroundColor Yellow 
    Write-Host
    Write-Host "Stay connected to this SDDC Manager (Y/N)?" -ForegroundColor Green -NoNewline 
    $ChangeSDDCmgr = Read-Host    
    if ($ChangeSDDCmgr -eq 'N') {
      $global:SDDCmgr = "Not Connected"
      fn_GetSddcCreds
    }
  }
# If Connected offer  
  if ($global:SDDCmgr -eq "Not Connected") {
    Write-Host "SDDC Manager Information:" -ForegroundColor Green 
    Write-Host
    Write-Host "Enter the IP Address or FQDN of the SDDC Manager " -ForegroundColor Green -NoNewLine
    $global:SDDCmgr = Read-Host 
    Write-Host
    Write-Host "Testing ability to find $global:SDDCmgr..."
    if (!(Test-Connection -ComputerName $global:SDDCmgr -Quiet -Count 2)) {
      Write-Host "Unable to find $global:SDDCmgr " -ForegroundColor Red
      Write-Host "Verify correct FQDN, DNS, and IP Configuration and try again." -ForegroundColor Red
      Write-host
      fn_PressAnyKey
      fn_GetSddcCreds
    } 
    Write-Host "Connectivity to $global:SDDCmgr verified." -ForegroundColor Green
    Write-Host
    Write-Host "!! " -ForegroundColor Red -NoNewLine 
    Write-Host "This process requires SSH ROOT access to the SDDC Manager " -ForegroundColor Green -NoNewLine
    Write-Host "!!" -ForegroundColor Red
    Write-Host
    Write-Host "It may be necessary to edit the /etc/ssh/sshd_config on the SDDC Manager and verify " -ForegroundColor Green -NoNewLine
    Write-Host "'PermitRootLogin'" -ForegroundColor Yellow -NoNewLine
    Write-Host " should be set to " -ForegroundColor Green -NoNewLine
    Write-Host "'yes'"-ForegroundColor Yellow
    Write-Host
    Write-Host
    Write-Host "Enter the root Credentials for $global:SDDCmgr" -ForegroundColor Green
    $global:sddcCreds = Get-Credential
    $global:SDDCuser= $sddcCreds.UserName.ToString()
    $global:SDDCpass = $sddcCreds.GetNetworkCredential().password
    Write-Host
    Write-Host "Verifying SSH to SDDC Manager $global:SDDCmgr :"
    $global:SddCSSHSession = New-SSHSession -ComputerName $global:SDDCmgr -Credential $global:sddcCreds -AcceptKey:$true -ErrorAction ignore
    if (!$global:SddCSSHSession.Connected) {
      Write-Host "SSH Credentials Failed." -ForegroundColor Red
      fn_PressAnyKey
      fn_GetSddcCreds
    }
    $SSHCommand = 'shell; uptime -s'
    $result = (Invoke-SSHCommand -SSHSession $global:SddCSSHSession -Command $SSHCommand).Output
    Write-Host "SDDC Manager SSH Test Successful" -ForegroundColor Green
    Write-Host "Info need for API YAML config file:" -ForegroundColor Green
    Write-Host
    Write-Host "Enter the FQDN or IP of the NTP Server: " -ForegroundColor Green -NoNewline
    $global:NTPServer = Read-Host 
    Write-Host "Enter the FQDN or IP of the SFTP Server: " -ForegroundColor Green -NoNewline
    $global:SFTPServer = Read-Host 
    Write-Host "Requesting SDDC API Token"

# Generate API Tokens for SDDC Manager
    fn_RequestSDDCToken
    Write-Host "SDDC API Token and YAML file created."
    fn_PressAnyKey
  }
}

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

# Confirm API token
  Write-Host "API token: "$global:vCAPIToken 

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
    Write-Host "This process requires SSH ROOT access to the ESX Hosts, all Hosts must have the same root password " -ForegroundColor Green -NoNewLine
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
 
        if ($result -eq "x") {
          Write-Host $VMHost "- FAIL" -ForegroundColor Red
        } else {
          Write-Host $VMHost "- $result Passed" -ForegroundColor Green
        }
        if ($sshon -eq 0) {fn_SSH_ON} #Teri turned this on
      }
      fn_PressAnyKey       
    }   
  
Function fn_MainMenu {
    $host.UI.RawUI.BackgroundColor = "Black"
    Clear-Host
    if (!($global:defaultVIServer)) {$global:defaultVIServer = "Not Connected"}
    Write-Host "Currently Connected to: " -ForegroundColor Green -NoNewLine
    Write-Host $global:defaultVIServer -ForegroundColor Yellow
    Write-Host
    Write-Host "MAIN MENU" -ForegroundColor Green
    Write-Host
    Write-Host "[1] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Scan vCenter (VMware Best Practices)" -ForegroundColor Green
    Write-Host
    Write-Host "[2] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Scan ESX Hosts (VMware Best Practices, George Extras)" -ForegroundColor Green
    Write-Host
    Write-Host "[3] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Scan VM Configurations (VMware Best Practices)" -ForegroundColor Green
    Write-Host
    Write-Host "[4] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Scan VM Configurations (George Extras)" -ForegroundColor Green
    Write-Host
    Write-Host "[A] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Add Appliance IP to SSH Firewall" -ForegroundColor Green
    Write-Host
    Write-Host "[R] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Remove Appliance IP from SSH Firewall" -ForegroundColor Green
    Write-Host
    Write-Host "[U] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Disable Lockdown Mode" -ForegroundColor Green
    Write-Host
    Write-Host "[L] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Enable Lockdown Mode" -ForegroundColor Green
    Write-Host
    Write-Host "[S] " -ForegroundColor Yellow -NoNewLine
    Write-Host "DISA STIG Report" -ForegroundColor Green
    Write-Host
    Write-Host "[Q] " -ForegroundColor Red -NoNewLine
    Write-Host "QUIT  " -ForegroundColor Red
    Write-Host
    Write-Host "Select: " -ForegroundColor Green -NoNewline
    $menu = Read-Host
    switch ($menu) {

      1 {
          Clear-Host
          fn_GetvCenterCreds
          fn_Build_vCenter_CSV
          fn_Load_vCenter_Controls
          fn_RunScan
          fn_PressAnyKey
          fn_MainMenu
        }
  
      2 {
        Clear-Host
        if ($global:DefaultVIServer -eq "Not Connected") {fn_GetvCenterCreds}
        fn_GetvCenterCreds
        fn_GetESXCreds
        fn_Build_ESX_CSV
        fn_Load_ESX_Controls
        fn_RunScan
        fn_MainMenu
        }

      3 {
        Clear-Host
        if ($global:DefaultVIServer -eq "Not Connected") {fn_GetvCenterCreds}
        fn_GetvCenterCreds
        fn_Build_VM_CSV
        fn_Load_VM_Controls
        fn_RunScan
        fn_PressAnyKey
        fn_MainMenu
        }

      4 {
        Clear-Host
        if ($global:DefaultVIServer -eq "Not Connected") {fn_GetvCenterCreds}        
        fn_Build_VM_CSV
        fn_load_New_VM_Controls
        fn_RunScan
        fn_PressAnyKey
        fn_MainMenu
        }  

        A {
          Clear-Host
          fn_SSH_Firewall_AddIP
          fn_PressAnyKey
          fn_MainMenu
          }

        R {
          Clear-Host
          fn_SSH_Firewall_RemoveIP
          fn_PressAnyKey
          fn_MainMenu
          }
  
        U {
            Clear-Host
            fn_Lockdown_off
            fn_PressAnyKey
            fn_MainMenu
          }

        L {
            Clear-Host
            fn_Lockdown_on
            fn_PressAnyKey
            fn_MainMenu
        }
		
        S {
          Clear-Host
          fn_STIGMenu
          fn_PressAnyKey
          fn_MainMenu
        }

        Q {
          fn_Quit
        }
    }

}

Function fn_STIGMenu {
    $host.UI.RawUI.BackgroundColor = "Black"
    Clear-Host
    Write-Host "DISA STIG Report MENU" -ForegroundColor Green
    Write-Host
    Write-Host "Currently Connected to vCenter: " -ForegroundColor Green -NoNewLine
    Write-Host $global:DefaultVIServer -ForegroundColor Yellow
    Write-Host
    Write-Host "[1] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Scan SDDC Manager" -ForegroundColor Green
    Write-Host
    Write-Host "[2] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Scan vCenter (vCenter + OS)" -ForegroundColor Green
    Write-Host
    Write-Host "[3] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Scan ESXi" -ForegroundColor Green
    Write-Host
    Write-Host "[4] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Scan NSX Manager" -ForegroundColor Green
    Write-Host
    Write-Host "[5] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Scan Virtual Machines" -ForegroundColor Green
    Write-Host
    Write-Host "[X] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Main Menu" -ForegroundColor Green
    Write-Host
    Write-Host
    Write-Host "[Q] " -ForegroundColor Red -NoNewLine
    Write-Host "QUIT  " -ForegroundColor Red
    Write-Host
    Write-Host "Select: " -ForegroundColor Green -NoNewline
    $menu = Read-Host
    switch ($menu) {

      1 {
          Clear-Host
          if ($global:DefaultVIServer -eq "Not Connected") {fn_GetvCenterCreds}
          fn_GetSddcCreds
          fn_sddcscanner
          fn_PressAnyKey
          fn_STIGMenu
        }

      2 {
        Clear-Host
        if ($global:DefaultVIServer -eq "Not Connected") {fn_GetvCenterCreds}
        fn_vCscanner
        fn_PressAnyKey
        fn_STIGMenu
      }  

      3 {
        Clear-Host
        if ($global:DefaultVIServer -eq "Not Connected") {fn_GetvCenterCreds}
        fn_GetESXCreds
        fn_ESXiscanner
        fn_PressAnyKey
        fn_STIGMenu
      }  

      4 {
        Clear-Host
        fn_getNSXCreds
        fn_nsxscanner
        fn_PressAnyKey
        fn_STIGMenu
      }  

      5 {
        Clear-Host
        if ($global:DefaultVIServer -eq "Not Connected") {fn_GetvCenterCreds}
        fn_GetESXCreds
        fn_VMscanner
        fn_PressAnyKey
        fn_STIGMenu
      }  
     
      X {
        Clear-Host
        fn_MainMenu
      }  

        Q {
          fn_Quit
        }
    }

}


Function fn_PressAnyKey {
    Write-Host "Press " -ForegroundColor Yellow -NoNewLine
    Write-Host "[Enter]" -ForegroundColor Red -NoNewLine
    Write-Host " to Continue..." -ForegroundColor Yellow -NoNewLine
    Read-Host
}

Function fn_Quit  {
    Disconnect-VIServer -Server * -Force -Confirm:$false
    Write-Host "Finished"
    exit
}

Function fn_Load_vCenter_Controls {
  # Build Control Array for vCenter Scan
  $global:Control_Array = @(
    'GET-vCENTER-VERSION',
    'GET-vCENTER-BUILD',
    'NIST800-53-VI-VC-CFG-00415',
    'NIST800-53-VI-VC-CFG-00415',
    'NIST800-53-VI-VC-CFG-00404',
    'NIST800-53-VI-VC-CFG-00405',
    'NIST800-53-VI-VC-CFG-00407',
    'NIST800-53-VI-VC-CFG-00417',
    'NIST800-53-VI-VC-CFG-00420',
    'NIST800-53-VI-VC-CFG-00450',
    'NIST800-53-VI-VC-CFG-00428',
    'NIST800-53-VI-VC-CFG-01200',
    'NIST800-53-VI-VC-CFG-01201',
    'NIST800-53-VI-VC-CFG-01202',
    'NIST800-53-VI-VC-CFG-01203',
    'NIST800-53-VI-VC-CFG-01204',
    'NIST800-53-VI-VC-CFG-01205',
    'NIST800-53-VI-VC-CFG-01209',
    'NIST800-53-VI-VC-CFG-01210',
    'NIST800-53-VI-VC-CFG-01211',
    'NIST800-53-VI-VC-CFG-01212'
  
  )
}
function fn_load_New_VM_Controls {
$global:Control_Array = @(
    'VMCH-70-000007',
    'VMCH-70-0000013',
    'VMCH-70-000020',
    'VMCH-70-000021',
    'VMCH-70-000025'
    )
    
}

Function fn_Load_ESX_Controls {
  # Build Control Array for vCenter 7x
  $global:Control_Array = @(
    'GET-ESX-Version',
    'GET-ESX-Build',
    'GET-ESX-Datacenter',
    'GET-ESX-Cluster',
    'NIST800-53-VI-ESXi-CFG-00003', 
    'NIST800-53-VI-ESXi-CFG-00004',
    'NIST800-53-VI-ESXi-CFG-00005',
    'ESXI-70-000274',
    'ESXI-70-000038',
    'NIST800-53-VI-ESXi-CFG-00006',
    'NIST800-53-VI-ESXi-CFG-00007',
    'NIST800-53-VI-ESXi-CFG-00011',
    'NIST800-53-VI-ESXi-CFG-00012',
    'NIST800-53-VI-ESXi-CFG-00013',
    'NIST800-53-VI-ESXi-CFG-00014',
    'NIST800-53-VI-ESXi-CFG-00016',
    'NIST800-53-VI-ESXi-CFG-00017',
    'NIST800-53-VI-ESXi-CFG-00018',
    'NIST800-53-VI-ESXi-CFG-00028',
    'NIST800-53-VI-ESXi-CFG-00030',
    'NIST800-53-VI-ESXi-CFG-00031',
    'NIST800-53-VI-ESXi-CFG-00034',
    'NIST800-53-VI-ESXi-CFG-00038',
    'NIST800-53-VI-ESXi-CFG-00043',
    'NIST800-53-VI-ESXi-CFG-00105',
    'NIST800-53-VI-ESXi-CFG-00106',
    'NIST800-53-VI-ESXi-CFG-00109', 
    'NIST800-53-VI-ESXi-CFG-00110',
    'NIST800-53-VI-ESXi-CFG-00112a',
    'NIST800-53-VI-ESXi-CFG-00112b',
    'NIST800-53-VI-ESXi-CFG-00114',
    'NIST800-53-VI-ESXi-CFG-00122',
    'NIST800-53-VI-ESXi-CFG-00123',
    'NIST800-53-VI-ESXi-CFG-00124',
    'NIST800-53-VI-ESXi-CFG-00125',
    'NIST800-53-VI-ESXi-CFG-00129',
    'NIST800-53-VI-ESXi-CFG-00136',
    'NIST800-53-VI-ESXi-CFG-00137',
    'NIST800-53-VI-ESXi-CFG-00138',
    'NIST800-53-VI-ESXi-CFG-00147',
    'NIST800-53-VI-ESXi-CFG-00148',
    'NIST800-53-VI-ESXi-CFG-00149',
    'NIST800-53-VI-ESXi-CFG-00157',
    'NIST800-53-VI-ESXi-CFG-00163',
    'NIST800-53-VI-ESXi-CFG-00164',
    'NIST800-53-VI-ESXi-CFG-00165',
    'NIST800-53-VI-ESXi-CFG-00166',
    'NIST800-53-VI-ESXi-CFG-00168',
    'NIST800-53-VI-ESXi-CFG-00169',
    'NIST800-53-VI-ESXi-CFG-00179',
    'NIST800-53-VI-ESXi-CFG-00564',
    'NIST800-53-VI-ESXi-CFG-01100',
    'NIST800-53-VI-ESXi-CFG-01102', 
    'NIST800-53-VI-ESXi-CFG-01106', 
    'NIST800-53-VI-ESXi-CFG-01107'
    'NIST800-53-VI-ESXi-CFG-01108',
    'NIST800-53-VI-ESXi-CFG-01109',
    'NIST800-53-VI-ESXi-CFG-01110',
    'NIST800-53-VI-ESXi-CFG-01111',
    'NIST800-53-VI-ESXi-CFG-01112',
    'NIST800-53-VI-ESXi-CFG-01113',
    'NIST800-53-VI-ESXi-CFG-00022',
    'NIST800-53-VI-ESXi-CFG-01114',
    'NIST800-53-VI-ESXi-CFG-01115',
    'NIST800-53-VI-ESXi-CFG-01116',
    'NIST800-53-VI-ESXi-CFG-01117',
    'NIST800-53-VI-ESXi-CFG-01118',
    'NIST800-53-VI-ESXi-CFG-01119'

  )
}

Function fn_Load_VM_Controls {
  # Build Control Array for VM Scan
  $global:Control_Array = @(
    'NIST800-53-VI-VC-CFG-01244',
    'NIST800-53-VI-VC-CFG-XX103',
    #'NIST800-53-VI-VC-CFG-XX104',
    'NIST800-53-VI-VC-CFG-00065', # Inludes 00066, 00067, and 00156
    'NIST800-53-VI-VC-CFG-00155',
    'NIST800-53-VI-VC-CFG-00068', 
    'NIST800-53-VI-VC-CFG-00070',
    'NIST800-53-VI-VC-CFG-00071',
    'NIST800-53-VI-VC-CFG-00073',
    'NIST800-53-VI-VC-CFG-00074',
    'NIST800-53-VI-VC-CFG-00075',
    'NIST800-53-VI-VC-CFG-00096',
    #'NIST800-53-VI-VC-CFG-00097',
    'NIST800-53-VI-VC-CFG-00099',
    'NIST800-53-VI-VC-CFG-00101',
    'NIST800-53-VI-VC-CFG-00102',
    'NIST800-53-VI-VC-CFG-00561',
    'NIST800-53-VI-VC-CFG-01215',
    'NIST800-53-VI-VC-CFG-01232',
    'NIST800-53-VI-VC-CFG-01233', 
    'NIST800-53-VI-VC-CFG-01234',
    'NIST800-53-VI-VC-CFG-XX105',
    'NIST800-53-VI-VC-CFG-00093',
    'NIST800-53-VI-VC-CFG-01243',
    'NIST800-53-VI-VC-CFG-01242',
    'NIST800-53-VI-VC-CFG-XX109',
    'NIST800-53-VI-VC-CFG-00154',
    'NIST800-53-VI-VC-CFG-X0415'
  )
}

Function fn_Print_vCenter_Control_Info{
  Write-Host
  Write-Host
  Write-Host "VMware Configuration: " -ForegroundColor Green -NoNewline
  Write-Host $VMWConfig -ForegroundColor Yellow
  Write-Host
  Write-Host "Description: " -ForegroundColor Green -NoNewline
  Write-Host $description -ForegroundColor White
  Write-Host
  Write-Host "NIST800-53 Citation: " -ForegroundColor Green -NoNewline
  Write-Host $NISTcit -ForegroundColor Cyan
  Write-Host "Command: " -ForegroundColor Green -NoNewline
  Write-Host $command -ForegroundColor Blue
  Write-Host "Finding Value: " -ForegroundColor Green -NoNewline
  Write-Host $finding -ForegroundColor DarkMagenta
  Write-Host 'Expected Result:'`t`t`t$xresult -ForegroundColor Green
  Write-Host
  $global:result_array=@($VMWConfig,$NISTcit,$description,$finding,$xresult,' ')
}
Function fn_Print_ESX_Control_Info{
      Write-Host
      Write-Host
      Write-Host "VMware Configuration: " -ForegroundColor Green -NoNewline
      Write-Host $VMWConfig -ForegroundColor Yellow
      Write-Host
      Write-Host "Description: " -ForegroundColor Green -NoNewline
      Write-Host $description -ForegroundColor White
      Write-Host
      Write-Host "NIST800-53 Citation: " -ForegroundColor Green -NoNewline
      Write-Host $NISTcit -ForegroundColor White
      Write-Host "Command: " -ForegroundColor Green -NoNewline
      Write-Host $command -ForegroundColor Yellow
      Write-Host "Finding Value: " -ForegroundColor Green -NoNewline
      Write-Host $finding -ForegroundColor Yellow
      Write-Host 'Expected Result:'`t`t`t$xresult -ForegroundColor Green
      Write-Host
      $global:result_array=@($VMWConfig,$NISTcit,$description,$finding,$xresult,' ')
}
Function fn_Print_VM_Control_Info{
  Write-Host
  Write-Host
  Write-Host "VMware Configuration: " -ForegroundColor Green -NoNewline
  Write-Host $VMWConfig -ForegroundColor Yellow
  Write-Host
  Write-Host "Description: " -ForegroundColor Green -NoNewline
  Write-Host $description -ForegroundColor White
  Write-Host
  Write-Host "Priority: " -ForegroundColor Green -NoNewline
  Write-Host $NISTcit -ForegroundColor Cyan
  Write-Host "Command: " -ForegroundColor Green -NoNewline
  Write-Host $command -ForegroundColor Blue
  Write-Host "Finding Value: "$finding -ForegroundColor DarkMagenta
  Write-Host 'Expected Result:'`t`t`t$xresult -ForegroundColor Green
  Write-Host
  $global:result_array=@($VMWConfig,$NISTcit,$description,$finding,$xresult,' ')
}

Function fn_RunScan {

    foreach ($control in $global:Control_Array) {
        & $control

        fn_Write_Results_to_CSV
        Write-Host
        Write-Host "-------------------------------------"
        Write-Host

    }

}

Function fn_Build_ESX_CSV {
  $date = (Get-date).tostring("dd-MM-yyyy-hh-mm")
  $global:csvFile = "./results/$($defaultVIServer) - $($date) - ESX Scan.csv"

  # Build first Column of report

  $allHosts = Get-VMHost | Sort-Object 

  $FirstColumn = @('VMware ID', 'Nist Citation', 'Description', 'Finding', 'Expected Result',' ') # Meta-Data Headers



  $FirstColumn += $allHosts

  $FirstColumn | ForEach-Object {@{N=$_}} | Export-Csv $global:csvFile -NoTypeInformation -Force

}

Function fn_Build_VM_CSV {
  $date = (Get-date).tostring("dd-MM-yyyy-hh-mm")
  $global:csvFile = "./results/$($defaultVIServer) - $($date) - VM Scan.csv"

   # Derrill added this

   Write-Host "You can filter the names of the VMs being tested" -ForegroundColor Green
   Write-Host "Enter the search string to filter or just press Enter to not filter" -ForegroundColor Green
   Write-Host "Filtering must have a * wildcard at the front or back (or both) to match multiple VMs" -ForegroundColor Green
   Write-Host "Enter Optional Hostname Filter  " -ForegroundColor Yellow -NoNewLine
   $global:filter = Read-Host

  # Build first Column of report

  $FirstColumn = @('VMware ID', 'Priority', 'Description', 'Finding', 'Expected Result',' ') # Meta-Data Headers

  $global:allVM = Get-VM | Sort-Object | Where-Object {$_.Name -notlike "vCLS-*"}

  if ($global:filter) {
    $global:allVM = Get-VM | Sort-Object | Where-Object {$_.Name -like $global:filter}
 }

  $FirstColumn += $global:allVM

  $FirstColumn | ForEach-Object {@{N=$_}} | Export-Csv $global:csvFile -NoTypeInformation -Force
}

Function fn_Build_vCenter_CSV {
  $date = (Get-date).tostring("dd-MM-yyyy-hh-mm")
  $global:csvFile = "./results/$($defaultVIServer) - $($date) - vC.csv"

  $FirstColumn = @('VMware ID', 'Priority', 'Description', 'Finding', 'Expected Result',' ') # Meta-Data Headers

  $FirstColumn += $Global:DefaultVIServers.Name 

  $FirstColumn | ForEach-Object {@{N=$_}} | Export-Csv $global:csvFile -NoTypeInformation -Force
}

Clear-Host
$host.UI.RawUI.ForegroundColor = "White"
$host.UI.RawUI.BackgroundColor = "Black"
fn_Welcome
fn_MainMenu
fn_GetAppIP 
fn_Collector