
from .tso.restricted_tsoauth_users import *
from .tso.tcp_ip_res_protected import *
from .tso.unix_res_protected import *

def tso_checks(mainframe, client):
    """
    Perform the checks that the user wants to run

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    option = input("Run all TSO checks (a) or select checks (s): ")
    if option == "a":
        # restricted_tsoauth_users(mainframe, client)   # Enable if fully implemented
        # tcp_ip_res_protected(mainframe, client)       # Enable if fully implemented
        unix_res_protected(mainframe, client)
    else:
        if input("TSOAUTH access properly restricted (y/N): ") == "y":
            restricted_tsoauth_users(mainframe, client)
        if input("TCP/IP resources properly protected (y/N): ") == "y":
            tcp_ip_res_protected(mainframe, client)
        if input("Unix resources properly protected (y/N): ") == "y":
            unix_res_protected(mainframe, client)