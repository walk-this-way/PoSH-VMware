## Name
PSO-security assessments script

## Description
This code checks envirnoment variables against DISA STIG, NIST 800-53 standards, and vmware best practices to determine security risk to associated VMware components. 

## Feature Backlog
- [x] Disable/Enable LockDownMode 
- [x] change command output to different color (currently Blue)
- [ ] fix 4 NIST functions that are currently commented out
- [x] verify SSH enabled on hosts prior to running code
- [X] show clusters available to scan
- [X] allow selection of clusters to scan
- [X] combine scripts
- [X] update menu 
- [X] integrated https://github.com/vmware/dod-compliance-and-automation for VCF/NSX STIG compliance scanning
- [X] fix $global.*creds variables 
- [X] added Heimdall docker for quick visualization report of scans.json output 

## Visuals
Pending creation

## Installation
This script runs successfully on VSCAT_230705.ova (PhotonOS with required dependencies)

## Support
There is no official support for this code. Please reach out to authors if you need assistance.

## Roadmap
Fix deployment script, have vSCAT.ps1 start on boot instead of shell access

## Contributing
If you would like to contribute to this product, please reach out directly to the authors below. 

## Authors and acknowledgment
wteri@vmware.com

kstiegler@vmware.com

## License
This script is used for the PSO Security Assessments of VCF, NSX, VCenter, and ESXi components. Not intended for commerical use or distribution. 

## Project status

