from .ssh.test_ssh import *
from .ssh.sshv2_only import *
from .ssh.unix_system_file_security import *
from .ssh.fips_140_2_crypto import * 
from .ssh.umask_default import *
from .ssh.inetd_services import *

def ssh_checks(mainframe, client):
    """
    Perform the checks that the user wants to run

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    option = input("Run all SSH checks (a) or select checks (s): ")
    if option == "a":
        test_ssh(mainframe, client)
        sshv2_only(mainframe, client)
        unix_system_file_security(mainframe, client)
        fips_140_2_crypto(mainframe, client)
        umask_default(mainframe, client)
        inetd_services(mainframe, client)
    else:
        if input("Test SSH Connection (y/N): ") == "y":
            test_ssh(mainframe, client)
        if input("Only SSHv2 enabled (y/N): ") == "y":
            sshv2_only(mainframe, client)
        if input("File permissions on Unix files set properly (y/N): ") == "y":
            unix_system_file_security(mainframe, client)
        if input("SSH uses secure cryptography (y/N): ") == "y":
            fips_140_2_crypto(mainframe, client)
        if input("Umask values set correctly (y/N): ") == "y":
            umask_default(mainframe, client)
        if input("Sensitive services running (y/N): ") == "y":
            inetd_services(mainframe, client)
    
