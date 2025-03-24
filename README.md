![alt text](m-ray-light.png)
# M-RAY   
The (M)ainf(RAY)me Vulnerability Scanner

M-RAY is designed to be an extensible tool for pentesters that can:
- Identify misconfigurations and and vulnerabilities in z/OS 
- Simplify the process of running REXX scripts

## Installation
- Clone the repository
- Change directories into the m-RAY directory
- Install dependencies with `pip install -r requirements.txt`

## Usage
### TSO and RACF Misconfigurations
Use `tso` option.\
Provide user credentials for SSH, can be a password or a private key. 

### USS Misconfigurations
Use `unix` option.\
Provide user credentials for SSH, can be a password or a private key. 

### Recon
Use `recon` option.\
Provide user credentials for SSH, can be a password or a private key. \
Provides information about the User Catalog.

### Run Scripts
Use `enum` option.\
Provide user credentials for SSH, can be a password or a private key. \
Select each script you would like to run. Script will be uploaded to a directory of 
the user's choice, executed, results returned, and the script removed from the upload directory. 

## Sources
- Soldier of Fortran's Mainframe Enum Script: https://github.com/mainframed/Enumeration
- Jim Taylor's SETRRCVT Script: https://github.com/lnlyssg/zos/blob/main/SETRRCVT.rexx 
