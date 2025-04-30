# IBM z/OS TCP/IP resources must be properly protected.
# https://www.stigviewer.com/stigs/ibm_zos_racf/2023-12-27/finding/V-223823
# Sev = med

from utilities import colorprint

def tcp_ip_res_protected(mainframe, client):
    """
    Ensure resources for TCP/IP are protected with proper access control.

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    print("Check: Protections on TCP/IP resources")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stigs/ibm_zos_racf/2023-12-27/finding/V-223823")

    cmd = "RLIST SERVAUTH * ALL "
    result = mainframe.c_send(client, cmd)
    # There will be a lot of results and a lot to parse

    print()