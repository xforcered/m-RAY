# IBM z/OS UNIX security parameters in /etc/profile must be properly specified
# https://www.stigviewer.com/stigs/ibm_zos_racf/2023-12-27/finding/V-223842
# umask should be set to 077
# LOGNAME variable should be set to readonly

from utilities import colorprint


def umask_default(mainframe, client):
    """
    Check the default umask value in /etc/profile.

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    print("Check: umask command set to 077")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stigs/ibm_zos_racf/2023-12-27/finding/V-223842")
    
    cmd = "cat /etc/profile | grep umask"
    result = mainframe.c_send(client, cmd)
    result = result.split("\n")

    umask = True
    for i in result:
        if i.split(" ")[0] == "umask":
            if i.split(" ")[1] != "077":
                umask = False

    cmd = 'grep "readonly LOGNAME" /etc/profile'
    result = mainframe.c_send(client, cmd)

    logname = True
    if result.strip() != "readonly LOGNAME":
        logname = False

    if not umask and not logname:
        display = "[+] umask is not set to 077 and LOGNAME not set to readonly"
    elif not umask:
        display = "[+] umask is not set to 077"
    elif not logname:
        display = "[+] LOGNAME not set to readonly"
    else:
        display = "[-] umask set to 077 and LOGNAME set to readonly"

    colorprint(display)
    print()