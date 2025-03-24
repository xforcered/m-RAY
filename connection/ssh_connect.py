from .connect_interface import iConnect
import paramiko
from getpass import getpass

class Ssh(iConnect):
    """
    Class representing a connection to a mainframe over SSH
    """
    def c_connect(self, host, auth):
        """
        Set up the connection using account credentials on target system.
        Authentication can use a password or a key file.

        Args:
            host (str): IP of target mainframe
            auth (str): Type of SSH authentication (Password or Key)

        Return:
            client (SSHClient): SSH client to execute commands through
        """
        # Set up connection parameters
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        username = input("Username: ")
        password = ""
        key_file = ""
        key_pass = ""

        # Gather authentication credentials
        if auth == "p":
            password = getpass("Password: ")
            client.connect(host, username=username, password=password)
        elif auth == "k":
            key_file = input("Key file: ")
            key_pass = input("Key passphrase (leave blank for none): ")
            if key_pass != "":
                client.connect(host, username=username, key_filename=key_file, passphrase=key_pass)
            else:
                client.connect(host, username=username, key_filename=key_file)

        return client
        

    def c_send(self, client, command):
        """
        Execute a command over SSH and return the output

        Args:
            client (SSHClient): SSH client to execute commands through
            command (str): System command to run

        Return:
            result (str): Command output
        """
        stdin, stdout, stderr = client.exec_command(command)
        result = f'{stdout.read().decode("utf-8", errors="replace")}'
        stdin.close()
        stdout.close()
        stderr.close()
        return result
    

    def c_recv(self, client):
        pass


    def c_close(self, client):
        """
        Close SSH connection to target

        Args:
            client (SSHClient): SSH client to execute commands through
        """
        client.close()