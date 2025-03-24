# Ensure that commands can be run against a target system by executing `whoami` on the 
# target system. 
# Will print output to console

from utilities import colorprint


def test_ssh(mainframe, client):
    """
    Test running commands over an SSH connection by running 'whoami'.

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    print("Check: Can run SSH commands")
    result = mainframe.c_send(client, "whoami")
    if result != "":
        colorprint("[+] Can execute commands. Your username is " + result)
    else:
        colorprint("[-] Cannot execute commands. No user found")