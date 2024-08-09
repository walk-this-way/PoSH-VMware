## Name
HealthCare VCF security assessment script

## Description
This code checks environment variables against DISA STIG, NIST 800-53 standards, and vmware best practices to determine security posture of associated components. 

## Feature Backlog
- [ ] finish Aria scanner function
- [ ] fix Aria switch menu for file directory paths
- [ ] fix input file disa stig scan line 115 get-esxi commandlet, use v2 parameter
- [ ] pass "$user.name" for all appliances SSHing into, just ask for passwords

## Visuals
Pending creation

## Installation
This script runs successfully on VSCAT_240809.ova (PhotonOS with required dependencies)

## Support
There is no official support for this code. Please reach out to the authors if you need assistance.

## Roadmap
Continue to build out the Aria audit function and integrate remediation scripts. 

## Contributing
If you would like to contribute to this product, please reach out directly to the authors below. 
<b> PLEASE DO NOT MERGE TO DIRECTLY TRUNK</b>

## Authors and acknowledgment
teri.walker@broadcom.com

kevin.stiegler@broadcom.com

## License
This script is used for the PSO Security Assessments of VCF and vSphere components and is not intended for commercial use or distribution. 

## Project status

