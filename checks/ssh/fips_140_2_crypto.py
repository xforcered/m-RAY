# The IBM RACF SSH daemon must be configured to use a FIPS 140-2 compliant 
# cryptographic algorithm to protect confidential information and remote access sessions.
# https://www.stigviewer.com/stigs/ibm_zos_racf/2023-12-27/finding/V-223807
# Ciphers list in sshd_config should not contain any ciphers not starting with 3des or aes
# MACs line should only use hmac-sha1 or higher
# zos_sshd_config should contain the following lines:
#   FIPSMODE=YES
#   CiphersSource=ICSF
#   MACsSource=ICSF 

from utilities import colorprint


def fips_140_2_crypto(mainframe, client):
    """
    Check ciphers used by SSH daemon.

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    print("Check: SSH daemon uses secure ciphers")
    print("       Severity if present: HIGH")
    print("       Context: https://www.stigviewer.com/stigs/ibm_zos_racf/2023-12-27/finding/V-223807")

    # Build a list of ciphers
    cmd = "grep -v '^\s*$\|^\s*\#' /etc/ssh/sshd_config | grep Ciphers"
    result = mainframe.c_send(client, cmd)
    result = result.strip()
    if result == "":
        display = "[+] SSH daemon does not restrict cryptographic algorithms"
    else:
        result = result.split(" ")[1].split(",")
        secure = True
        for cipher in result:
            if cipher[0:4] != "3des" and cipher[0:3] != "aes":
                secure = False
        
        if secure:
            display = "[-] SSH daemon enforces secure cryptographic algorithms"
        else:
            display = "[+] SSH daemon allows insecure cryptographic algorithms"

    colorprint(display)
    print()

    # TODO: MAC
    # TODO: zos_sshd_config
                
    