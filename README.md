## Name
HealthCare VCF security assessment script

## Description
This code checks envirnoment variables against DISA STIG, NIST 800-53 standards, and vmware best practices to determine security posture of associated VMware components. 

## Feature Backlog
- [ ] connect to new vcenter without dumping script
- [ ] connect to multiple vcenter to scan vcenter applicance (vm BB)
- [ ] fix input file disa stig scan line 115 get-esxi commandlet, use v2 parameter
- [X] VM with VM name not found, under george extras
- [ ] NSX scan 4124, 4128 error OBS_rootpass ???
- [ ] for NSX scan, update "$version.x" like esx check
- [ ] pass "$user.name" for all appliances SSHing into, just ask for passwords

## Visuals
Pending creation

## Installation
This script runs successfully on VSCAT_230705.ova (PhotonOS with required dependencies)

## Support
There is no official support for this code. Please reach out to the authors if you need assistance.

## Roadmap
Fix the deployment script, have vSCAT.ps1 start on boot instead of shell access

## Contributing
If you would like to contribute to this product, please reach out directly to the authors below. 
<b> PLEASE DO NOT MERGE TO DIRECTLY TRUNK</b>

## Authors and acknowledgment
teri.walker@broadcom.com

kevin.stiegler@broadcom.com

## License
This script is used for the PSO Security Assessments of VCF and vSphere components. Not intended for commercial use or distribution. 

## Project status

