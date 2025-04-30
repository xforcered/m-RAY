# IBM Z/OS TSOAUTH resources must be restricted to authorized users.
# https://www.stigviewer.com/stigs/ibm_zos_racf/2023-12-27/finding/V-223836
# Sev = med

from utilities import colorprint

def restricted_tsoauth_users(mainframe, client):
    """
    TSOAUTH resources should be restricted to the proper users.

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    print("Check: TSOAUTH resources are restricted to the proper users")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stigs/ibm_zos_racf/2023-12-27/finding/V-223836")

    cmd = "RLIST SURROGAT *"
    result = mainframe.c_send(client, cmd)
    # Parse the results of each type of authorization and print out who has access
    # In most cases will be system programmers/sec personnel, we don't know who
    # those are for the company
    

    print()