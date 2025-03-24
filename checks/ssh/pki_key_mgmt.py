# IBM z/OS, for PKI-based authentication, must use the ICSF or ESM for key management.
# https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223811
# If keys are stored in UNIX files, the identity of users is not properly mapped to the key for 
# forensic purposes. 

from utilities import colorprint


def pki_key_mgmt(mainframe, client):
    """
    Check if keys are being stored in UNIX files rather than ICSF or ESM being used for key management. 

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    print("Check: ICSF or ESM used for key management")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223811")

    finding = False

    cmd = "find / -name *.kdb"
    result = mainframe.c_send(client, cmd)
    result = result.strip()

    if result != "":
        finding = True

    cmd = "find / -name *.jks"
    result = mainframe.c_send(client, cmd)
    result = result.strip()

    if result != "":
        finding = True

    if finding:
        display = "[+] Keys are managed by UNIX files, not properly mapped to identities"
    else:
        display = "[-] Keys are managed properly by ICSF or an external security manager"

    colorprint(display)
    print()