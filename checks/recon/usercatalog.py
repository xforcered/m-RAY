# User Catalog Information
# https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223669
# This file will return information, link provides information about potential 
# security implications of the results


def usercatalog(mainframe, client):
    """
    Provide information about User Catalogs

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    print("------ User Dataset Information ------")
    
    cmd = "tsocmd listcat usercatalog all noprefix"
    result = mainframe.c_send(client, cmd)
    result = result.strip()

    print(result)
    print()