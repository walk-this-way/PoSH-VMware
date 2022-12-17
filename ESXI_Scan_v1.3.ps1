<#
Version Notes

v1.1 includes the Get-Credentials changes to allow for better password handling

v1.2 
Updated all functions requiring SSH to use Posh-SSH Module
Updated Logic for Turning SSH On/Off by adding a new function fn_SSH_Check
Updated logic for Function NIST800-53-VI-ESXi-CFG-00110
Corrected typo with $global:Control_Array variable name
Commented fn_Finalize_CSV in line 2118 in order to work around formatting issues. Please uncomment if needed.
Deleted "Function Nothing" and "Function fn_Writer" as they were unused

v1.3
Updated to configure SSH Firewall to add and remove Appiance IP if necessary.


Set Environment Vars
#>

#$plink = ''  # Location of plink # Not required as Posh-SSH is now used instead

$date = (Get-date).tostring('dd-MM-yyyy-hh-mm')

$location =""

$UserDomain = ""

$ScanLoop = 0
<#
CONTROL LIBRARY
  Each Control Funcition Sets the variables to collect the data for that control.
    - Some controlls check multiple setting. Enter the commands seperately as command_1 and command_2
    - The expected results are entered as xResult_1 and xResult_2 or the corresponding command.
    - Enter all the acceptable results in the string seperated by a comma ['good result,another good result']
    -
#>
<#
Function NIST800-53-VI-ESXi-BLANK {
  $global:VMWConfig=''
  $global:description=''
  $global:NISTcit=''
  $global:finding=''
  $global:xResult=''
  $global:command=''
  $global:SSH_Required=$false
}
#>

Function fn_HostProgress_Bar {
        $HostLoop += 1
        $HCount = ($allHosts.count)
        $Hstep = (100/$HCount)
        $HPercentScan = $Hstep*$HostLoop
        $HPercentScan = [math]::Round($HPercentScan)
        Write-Progress -Id 2  -ParentId 1 -Activity "Host Progress : $VMHost" -Status "$HPercentScan%" -PercentComplete $HPercentScan -CurrentOperation InnerLoop
}

Function fn_ScanProgress_Bar {
      $ScanLoop += 1
      $Count = ($global:Control_Array.count)
      $step = (100/$Count)
      $PercentScan = $step*$ScanLoop
      $PercentScan = [math]::Round($PercentScan)
      Write-Progress -Id 1 -Activity "$control : Scan Progress:" -Status "$PercentScan% Complete" -PercentComplete $PercentScan -CurrentOperation OuterLoop
      Write-Host
}

Function fn_GetAppIP {
  # Pull IP Address from Photon OS Appliance
  $global:AppIPaddress = Invoke-Expression "cat /etc/systemd/network/*.network | grep Address"
  $global:AppIPAddress = ($global:AppIPaddress |  Select-String -Pattern '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' -AllMatches).Matches.Value
  Write-Host "IP=" $global:AppIPaddress

  # Set this variable when using the scipt stand-alone: 
  # $global:AppIPaddress = "10.1.0.43"
}
Function fn_SSH_Check {
    # Check to see if SSH is already on and set a variable to leave it on after command is run.
    $serviceStatus = Get-VMHostService -VMHost $VMHost | Where-Object {$_.Key -eq "TSM-SSH"} | Select-Object Running
    if ($serviceStatus.Running) {return $true} else {return $false}
    
    }

Function fn_SSH_ON {

        $VMhost | Get-VmHostService | Where-Object {$_.key -eq "TSM-SSH"} | Start-VMHostService -Confirm:$false | Out-Null

    }

Function fn_SSH_OFF {
    
        $VMhost | Get-VmHostService | Where-Object {$_.key -eq "TSM-SSH"} | Stop-VMHostService -Confirm:$false | Out-Null
    
}

Function fn_SSH_Firewall_AddIP {

  $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      Write-Host "Adding IP to $VMHost"
      # Is SSH Firewall Enabled
      $SSHFirewall = (Get-VMHost -Name $VMHost) | Get-VMHostFirewallException  | Where {$_.Name -eq "SSH Server"} | Select-Object -ExpandProperty Enabled
      $esxcli = Get-Esxcli -VMHost $VMHost
      # If SSH Firewall is Enabled is there and IP Allowed List
      If ($SSHFirewall -eq "True") {

          $AllowedIPs = $esxcli.network.firewall.ruleset.allowedip.list("sshServer").AllowedIPAddresses

          if ($AllowedIPs -eq "All") {
              Write-Host "Allowed IPs: $AllowedIPs - No Changes Made"
          }
          if ($AllowedIPs -match $global:AppIPaddress) {
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
 
  $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      # Is SSH Firewall Enabled
      $SSHFirewall = (Get-VMHost -Name $VMHost) | Get-VMHostFirewallException  | Where {$_.Name -eq "SSH Server"} | Select-Object -ExpandProperty Enabled
      $esxcli = Get-Esxcli -VMHost $VMHost
      # If SSH Firewall is Enabled is there and IP Allowed List
      If ($SSHFirewall -eq "True") {

          $AllowedIPs = $esxcli.network.firewall.ruleset.allowedip.list("sshServer").AllowedIPAddresses

          if ($AllowedIPs -eq "All") {
              Write-Host "Allowed IPs: $AllowedIPs - No Changes Made"
          }
          if ($AllowedIPs -match $global:AppIPaddress) {
              Write-Host "Removing $global:AppIPaddress from $VMHost Firewall" -ForegroundColor Green
              $esxcli.network.firewall.ruleset.allowedip.remove("$global:AppIPaddress", "sshServer") | Out-Null
              Start-Sleep -Seconds 2
          } else {
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

    # Export CSV file
    $csv | Export-Csv -Path $global:csvFile -NoTypeInformation -Force
}
Function fn_Finalize_CSV {
    $skipone = get-content $global:csvFile |
        select -skip 1 |
    convertfrom-csv

    $skipone | export-csv $global:csvFile -notypeinformation
}

##################################################################
###############       CONTROL FUNCTIONS       ####################
##################################################################


Function NIST800-53-VI-ESXi-CFG-00003 {
    $VMWConfig='NIST800-53-VI-ESXi-CFG-00003'
    $description='ESXi host SSH daemon ignores .rhosts files.'
    $NISTcit='CM-6b.'
    $finding='SSH ignore .rhosts no'
    $xresult='ignorerhosts yes'
    $command='/usr/lib/vmware/openssh/bin/sshd -T | grep ignorerhosts'

    fn_Print_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {
      if(!(fn_SSH_Check))
      {
          fn_SSH_ON

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

        fn_SSH_OFF
      } else {

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
  fn_Print_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON
          

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

          fn_SSH_OFF
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
  fn_Print_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON
          fn_SSH_Firewall_AddIP

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

          fn_SSH_OFF
          fn_SSH_Firewall_RemoveIP
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
  fn_Print_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    if(!(fn_SSH_Check))
    {
        fn_SSH_ON
        fn_SSH_Firewall_AddIP

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

        fn_SSH_OFF
        fn_SSH_Firewall_RemoveIP
    }

    else
    {
  

        $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
  fn_Print_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    if(!(fn_SSH_Check))
    {
        fn_SSH_ON
        fn_SSH_Firewall_AddIP

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

        fn_SSH_OFF
        fn_SSH_Firewall_RemoveIP
    }

    else
    {
  

        $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
  fn_Print_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    if(!(fn_SSH_Check))
    {
        fn_SSH_ON
        fn_SSH_Firewall_AddIP

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

        fn_SSH_OFF
        fn_SSH_Firewall_RemoveIP
    }

    else
    {
  

        $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
  fn_Print_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    if(!(fn_SSH_Check))
    {
        fn_SSH_ON
        fn_SSH_Firewall_AddIP

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

        fn_SSH_OFF
        fn_SSH_Firewall_RemoveIP
    }

    else
    {
  

        $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
    fn_Print_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON
          fn_SSH_Firewall_AddIP

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

          fn_SSH_OFF
          fn_SSH_Firewall_RemoveIP
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
    fn_Print_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON
          fn_SSH_Firewall_AddIP

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

          fn_SSH_OFF
          fn_SSH_Firewall_RemoveIP
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
    fn_Print_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON
          fn_SSH_Firewall_AddIP

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

          fn_SSH_OFF
          fn_SSH_Firewall_RemoveIP
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
    $global:finding='SSH clientalivecountmax higher than 0'
    $global:xResult='clientalivecountmax 0'
    $global:command='/usr/lib/vmware/openssh/bin/sshd -T | grep clientalivecountmax'
    fn_Print_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON
          fn_SSH_Firewall_AddIP

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

          fn_SSH_OFF
          fn_SSH_Firewall_RemoveIP
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
    fn_Print_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON
          fn_SSH_Firewall_AddIP

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

          fn_SSH_OFF
          fn_SSH_Firewall_RemoveIP
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
    fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  $global:finding='Incoming Policy set to FALSE'
  $global:xResult='True'
  $global:Compare='equal'
  $global:command='(Get-VMHostFirewallDefaultPolicy $VMHost).IncomingEnabled'
  fn_Print_Control_Info

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
  $global:finding='Outgoing Policy set to FALSE'
  $global:xResult='True'
  $global:command='(Get-VMHostFirewallDefaultPolicy $VMHost).OutgoingEnabled'
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    if(!(fn_SSH_Check))
    {
        fn_SSH_ON
        fn_SSH_Firewall_AddIP

        $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
        $result1 = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output
        $result2 = Out-String -InputObject $result1
        $result3 = $result2.trim()
        $result = ($result3.substring($result3.Length - 6))


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

        fn_SSH_OFF
        fn_SSH_Firewall_RemoveIP
    }

    else
    {
  

        $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
  fn_Print_Control_Info

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

  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info
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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    if(!(fn_SSH_Check))
    {
        fn_SSH_ON
        fn_SSH_Firewall_AddIP

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
          $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


          Write-Host $VMHost -NoNewLine

          if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

          Write-Host `t`t`t$result -ForegroundColor $fgColor

        fn_SSH_OFF
        fn_SSH_Firewall_RemoveIP
    }

    else
    {
  

        $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
  fn_Print_Control_Info

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
  $global:NISTcit=''
  $global:finding=''
  $global:xResult=''
  $global:command=''
  fn_Print_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
  foreach ($VMHost in $allHosts) {

    $result = Invoke-Expression $global:command.tostring()

      Write-Host $VMHost -NoNewLine

      if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

      Write-Host `t`t`t$result -ForegroundColor $fgColor

      $global:result_array = $global:result_array+$result
  }
}


Function NIST800-53-VI-ESXi-CFG-00136 {
  $global:VMWConfig='NIST800-53-VI-ESXi-CFG-00136'
  $global:description='Configure a persistent log location for all locally stored logs'
  $global:NISTcit='AU-9 Control'
  $global:finding='Configure a persistent log location for all locally stored logs'
  $global:xResult= 'true'
  $global:command='(Get-ESXCli -v2 -VMHost $VMHost).system.syslog.config.get.Invoke() | Select-Object -ExpandProperty LocalLogOutputIsPersistent'
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON
          fn_SSH_Firewall_AddIP

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

          fn_SSH_OFF
          fn_SSH_Firewall_RemoveIP
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
  fn_Print_Control_Info

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
    $global:finding='CIm Service Account Permissions'
    $global:xResult=''
    $global:command=''
    fn_Print_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

        if(!(fn_SSH_Check))
      {
          fn_SSH_ON
          fn_SSH_Firewall_AddIP

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

          fn_SSH_OFF
          fn_SSH_Firewall_RemoveIP
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

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
  fn_Print_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      if(!(fn_SSH_Check))
      {
          fn_SSH_ON
          fn_SSH_Firewall_AddIP

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

          fn_SSH_OFF
          fn_SSH_Firewall_RemoveIP
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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

  fn_Print_Control_Info

  $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      if(!(fn_SSH_Check))
      {
          fn_SSH_ON
          fn_SSH_Firewall_AddIP

            $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
            $result = (Invoke-SSHCommand -SSHSession $SSHCommand -Command $command).Output


            Write-Host $VMHost -NoNewLine

            if ($result -eq $xresult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen utput based on expected result

            Write-Host `t`t`t$result -ForegroundColor $fgColor

          fn_SSH_OFF
          fn_SSH_Firewall_RemoveIP
      }

      else
      {
    

          $SSHCommand = New-SSHSession -ComputerName $VMHost -Credential $global:SSHCreds -AcceptKey:$true
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
    $global:finding='The ESXi host must use approved certificates'
    $global:xResult=''
    $global:command=''
    fn_Print_Control_Info

    $allHosts = Get-VMHost | Sort-Object Name
    foreach ($VMHost in $allHosts) {

      $result = Invoke-Expression $global:command.tostring()

        Write-Host $VMHost -NoNewLine

        if ($result -eq $global:xResult) {$fgColor="White"} else {$fgColor="Red"} #Set Warning Color for screen output based on expected result

        Write-Host `t`t`t$result -ForegroundColor $fgColor

        $global:result_array = $global:result_array+$result
    }
  }




Function fn_Login {
  Clear-Host
  if (!$defaultVIServer) {
     Write-Host "vCenter Server: " -ForegroundColor Green -NoNewline
     $vServer = Read-Host

		 Write-Host "Enter vCenter Admin Credentials"
     $credential = Get-Credential
     Connect-VIserver -Server $vServer -Credential $credential
		 if (!$defaultVIServer) {
 			Clear-Host
 			Write-Host "Invalid Login" -ForegroundColor red | fn_PressAnyKey | fn_Login
 			}
		 Write-Host
		 Write-Host
		 Write-Host "Enter ESXi SSH (root) Credentials" -ForegroundColor Green
		 $global:SSHCreds = Get-Credential
		 #$SSHUser = $global:SSHCreds.GetNetworkCredential().Username
		 #$global:SSHPass = $global:SSHCreds.GetNetworkCredential().Password

		 $allVIServers=$global:DefaultVIServers

      }
      Clear-Host

      fn_MainMenu

}

Function fn_MainMenu {
    $host.UI.RawUI.BackgroundColor = "Black"
    Clear-Host
    Write-Host "Currently Connected to: " -ForegroundColor Green -NoNewLine
    Write-Host $defaultVIServer -ForegroundColor Yellow
    Write-Host
    Write-Host
    Write-Host "MAIN MENU" -ForegroundColor Green
    Write-Host
    Write-Host "[1] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Scan vCenter $defaultVIServer" -ForegroundColor Green
    Write-Host
    Write-Host "[2] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Switch vCenter     " -ForegroundColor Green
    Write-Host
    Write-Host "[A] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Add Appliance IP to SSH Firewall     " -ForegroundColor Green
    Write-Host
    Write-Host "[R] " -ForegroundColor Yellow -NoNewLine
    Write-Host "Remove Appliance IP from SSH Firewall     " -ForegroundColor Green
    Write-Host
    Write-Host "[Q] " -ForegroundColor Red -NoNewLine
    Write-Host "QUIT  " -ForegroundColor Red
    Write-Host
    Write-Host "Select: " -ForegroundColor Green -NoNewline
    $menu = Read-Host
    switch ($menu) {


        1 {
        Clear-Host
        fn_BuildXLS
        fn_Load_Controls
        fn_RunScan
        fn_MainMenu
        }

        2 {
        Clear-Host
        fn_SwitchVcenter
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

Function fn_SwitchVcenter {
  Clear-Host
  $VCArray =@()
  $allVIServers | ForEach-Object { $VCArray  += $_.Name }
  Write-Host "vCenter Servers:" -ForegroundColor Green
  Write-Host
  For ($i = 0; $i -lt $VCArray.Length; $i++ ) { Write-Output "[$i] $($VCArray[$i])"}
  Write-Host
  Write-Host "Select the vCenter to connect to: " -ForegroundColor Green -NoNewLine
  $selectedVC = Read-Host
  Write-Host "Connecting to "$VCArray[$selectedVC]
  $vServer = $VCArray[$selectedVC]

  Connect-VIserver -Server $vServer -AllLinked  -user $userName -Password $plainPwd | Out-Null

  Clear-Host
  fn_MainMenu
}

Function fn_Load_Controls {
  # Build Control Array for vCenter 7x
  $global:Control_Array = @(
    'NIST800-53-VI-ESXi-CFG-00003', 
    'NIST800-53-VI-ESXi-CFG-00004',
    'NIST800-53-VI-ESXi-CFG-00005',
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
   #'NIST800-53-VI-ESXi-CFG-00129', # Function needs to be configured
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
    #'NIST800-53-VI-ESXi-CFG-01102', # Need validation of Expected Result for iSCSI CHAP Authentication
    #'NIST800-53-VI-ESXi-CFG-01106', # Function needs to be configured
    'NIST800-53-VI-ESXi-CFG-01107',
    'NIST800-53-VI-ESXi-CFG-01108',
    'NIST800-53-VI-ESXi-CFG-01109',
    'NIST800-53-VI-ESXi-CFG-01110',
    'NIST800-53-VI-ESXi-CFG-01111',
    'NIST800-53-VI-ESXi-CFG-01112'
    #'NIST800-53-VI-ESXi-CFG-01113' # Function needs to be configured 
  )
}

Function fn_Print_Control_Info{
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

    #fn_Finalize_CSV

}

Function fn_BuildXLS {
    $date = (Get-date).tostring("dd-MM-yyyy-hh-mm")
    $global:csvFile = "$($defaultVIServer) - $($date).csv"

    # Build first Column of report
    $allHosts = Get-VMHost | Sort-Object Name

    $FirstColumn = @('VMware ID', 'Nist Citation', 'Description', 'Finding', 'Expected Result',' ') # Meta-Data Headers

    $FirstColumn += $allHosts

    $FirstColumn | ForEach-Object {@{N=$_}} | Export-Csv $global:csvFile -NoTypeInformation -Force

}

Clear-Host
$host.UI.RawUI.ForegroundColor = "White"
$host.UI.RawUI.BackgroundColor = "Black"
fn_GetAppIP 
fn_Login
