# {NAME OF VULNERABILITY}
# {LINK TO SOURCE FOR MORE INFORMATION}
# {ADDITIONAL DESCRIPTIONS}

from utilities import colorprint


def NAME_OF_VULN(mainframe, client):
    """
    {NAME OF VULN TO CHECK FOR}

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    # Information to display with a vulnerability check
    print("Check: {NAME OF MISCONFIGURATION OR VULN}")
    print("       Severity if present: {HIGH, MEDIUM, LOW}")
    print("       Context: {ADD A LINK IF NEEDED}")
    
    cmd = "{OMVS / UNIX COMMAND TO RUN}"
    result = mainframe.c_send(client, cmd)
    result = result.strip()

    # Do any necessary output parsing

    # [+], [-], [?] determine color of output
    # [?] is optional
    if result == "{Vuln not present condition}":
        display = "[-] {VULN NOT FOUND}"
    elif result == "{Vuln present condition}":
        display = "[+] {VULN FOUND}"
    else:
        display = "[?] {UNSURE IF VULN IS FOUND}"

    colorprint(display)
    print()