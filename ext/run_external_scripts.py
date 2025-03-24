from scp import SCPClient
from utilities import scriptcolor

def run_script(mainframe, client, script, args, filepath):
    l_filepath = "ext/scripts/" + script
    if filepath[-1] != "/":
        r_filepath = filepath + "/" + script
    else:
        r_filepath = filepath + script

    with SCPClient(client.get_transport()) as scp:
        scp.put(l_filepath, r_filepath)

    print("------ Script: " + script + " ------")

    # Make script executable
    cmd = "chmod +x " + r_filepath
    mainframe.c_send(client, cmd)

    # Execute and obtain results
    cmd = r_filepath + args
    result = mainframe.c_send(client, cmd)
    print(result)
    print()

    # Clean up script from environment
    cmd = "rm " + r_filepath
    mainframe.c_send(client, cmd) 


def enum_scripts(mainframe, client):
    """
    Run external scripts

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    # See what the user wants to run
    print("Run Enumeration Scripts")
    print("Select which scripts you would like to run:")

    print()
    scriptcolor("--------------------------------------------")
    scriptcolor("Test REXX (textrexx.rex)")
    scriptcolor("Confirm that REXX scripts can run on the system.")
    scriptcolor("Contains a SAY statement")
    testrexx = input("Run Test REXX? (y, N): ")

    print()
    scriptcolor("--------------------------------------------")
    scriptcolor("REXX ENUM (ENUM.rex)")
    scriptcolor("Soldier of Fortran's REXX enumeration script.")
    sof_enum = input("Run ENUM? (y, N): ")

    print()
    scriptcolor("--------------------------------------------")
    scriptcolor("SETRRCVT (SETRRCVT.rex)")
    scriptcolor("Jay Taylor's script to pull SETROPTS from storage.")
    scriptcolor("Does not require SPECIAL or AUDITOR privs")
    setrrcvt = input("Run SETRRCVT? (y, N): ")

    print()
    filepath = input("Filepath to upload scripts: ")
    print()

    # Set up SFTP Connection
    # Run scripts, get results
    if testrexx == "y":
        run_script(mainframe, client, "testrexx.rex", "", filepath)
    if sof_enum == "y":
        run_script(mainframe, client, "ENUM.rex", " ALL", filepath)
    if setrrcvt == "y":
        run_script(mainframe, client, "SETRRCVT.rex", "", filepath)

