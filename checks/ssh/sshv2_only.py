# IBM z/OS SSH daemon must be configured to only use the SSHv2 protocol
# https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223810
# If SSH daemon is not active, this is not a finding. Since this check runs via SSH,
# this condition will never apply.

from utilities import colorprint


def sshv2_only(mainframe, client):
    """
    Check what version of SSH the z/OS SSH Daemon is using.

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    print("Check: SSH daemon allows SSHv1")
    print("       Severity if present: HIGH")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223810")
    
    cmd = "cat /etc/ssh/sshd_config | grep Protocol"
    result = mainframe.c_send(client, cmd)
    result = result.strip()

    # Default is v2, so a blank result, commented out line, or Protocol 2 indicates secure configuration
    if result == "" or result[0] == "#" or result == "Protocol 2":
        display = "[-] SSH daemon uses SSHv2"
    elif result == "Protocol 2,1" or result == "Protocol 1":
        display = "[+] SSH daemon allows SSHv1"
    else:
        display = "[?] Unable to determine SSH daemon version"

    colorprint(display)
    print()