from utilities import print_logo, gather_info
from checks.run_ssh_checks import ssh_checks
from checks.run_tso_checks import tso_checks
from checks.run_racf_checks import racf_checks
from checks.run_recon import recon
from ext.run_external_scripts import enum_scripts
from connection.ssh_connect import Ssh
from connection.nje_connect import Nje

def start():
    """
    Set up connection based on connection type and initiate scans.
    """
    print_logo()
    (host, conn) = gather_info()

    # Set up SSH connection (Change if using additional protocols)
    mainframe = Ssh()
    conn_type = input("Password (p) or Key (k) auth: ")
    client = mainframe.c_connect(host, conn_type)
    print()

    if conn == "unix":
        # Checks for misconfigurations in USS files and configs
        ssh_checks(mainframe, client)
        mainframe.c_close(client)
    elif conn == "tso":
        # Checks for misconfigurations in RACF and systems queried
        # by TSO commands
        tso_checks(mainframe, client)
        racf_checks(mainframe, client)
        mainframe.c_close(client)
        """ mainframe = Zowe()
        client = mainframe.c_connect(host)
        print()
        zowe_checks(mainframe, client) """
    elif conn == "enum":
        # Run enumeration scripts
        enum_scripts(mainframe, client)
        mainframe.c_close(client)
    elif conn == "nje":
        mainframe = Nje()
    elif conn == "recon":
        # Gather information through recon commands
        recon(mainframe, client)
        mainframe.c_close(client)


start()