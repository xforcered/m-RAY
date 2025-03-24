# IBM z/OS UNIX resources must be protected in accordance with security requirements
# https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223844
# Sev = med

from utilities import colorprint

def unix_res_protected(mainframe, client):
    """
    Check that access is appropriately restricted

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    print("Check: UNIX environment access is appropriately restricted")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223844")

    cmd = "tsocmd RL SURROGAT BPX.SRV AUTHUSER"
    result = mainframe.c_send(client, cmd)
    result = result.split("\n")

    line = False
    for i in result:
        if line == True:
            print(i.strip())
        if "USER      ACCESS" in i:
            line = True
            print("WRITE access should be restricted to system programmers.")
            print("The following accounts have access to the ACP data set rules for APF libraries:")
            print(i.strip())
        if i.strip() == "":
            line = False
    
    print()