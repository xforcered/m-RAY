# IBM z/OS UNIX security parameters for restricted network services in /etc/inetd.conf
# must be properly specified
# https://www.stigviewer.com/stigs/ibm_zos_racf/2023-12-27/finding/V-223855

from utilities import colorprint


def inetd_services(mainframe, client):
    """
    Only essential network services should be in use.

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    print("Check: Restricted network protocols in use")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stigs/ibm_zos_racf/2023-12-27/finding/V-223855")
    
    cmd = "cat /etc/inetd.conf"
    result = mainframe.c_send(client, cmd)
    result = result.split("\n")

    restricted = ["chargen", "daytime", "discard", "echo", "exec", "finger", " shell", "talk", "qotd",
                  "time", "login", "smtp", "timed", "nameserver", "systat", "uucp", "netstat", "tftp"]

    start_chk = False
    protos = list()
    for i in result:
        if "=====" in i: start_chk = True
        if start_chk and i != "":
            service = i.lstrip().split(" ")[0]
            if i[0] != "#" and service in restricted:
                protos.append(service)

    if not protos:
        display = "[-] No restricted network protocols enabled"
    else:
        protos_str = ", ".join(protos)
        display = "[+] The following restricted protocols are enabled: " + protos_str



    colorprint(display)
    print()