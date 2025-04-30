# IBM z/OS UNIX SYSTEM FILE SECURITY SETTINGS must be properly protected or specified.
# https://www.stigviewer.com/stigs/ibm_zos_racf/2023-12-27/finding/V-223848
# Not all these files will exist on every system. If they do not exist, this is not a finding.
# These are the maximum file permissions that should be set. 

from utilities import colorprint


# Important system files and the permissions they should have according to the STIG
# TODO: Audit bits
perms = {
    "/bin/sh": "755",            # z/OS UNIX shell, should also have sticky bit
    "/dev/console": "740",        # The system console file receives messages that may require System Administrator (SA) attention.
    "/dev/null": "666",           # A null file; data written to it is discarded.
    "/etc/auto.master": "740",    # Configuration files for automount facility
    "/etc/inetd.conf": "740",     # Configuration file for network services
    "/etc/init.options": "740",   # Kernel initialization options file for z/OS UNIX environment
    "/etc/log": "744",            # Kernel initialization output file
    "/etc/profile": "755",        # Environment setup script executed for each user
    "/etc/rc": "744",             # Kernel initialization script for z/OS UNIX environment
    "/etc/steplib": "740",        # List of MVS data sets valid for set user ID and set group ID executables
    "/etc/tablename": "740",      # List of z/OS userids and group names with corresponding alias names
    "/usr/lib.cron/at.deny": "700",       # Configuration files for the at and batch commands
    "/usr/lib.cron/at.allow": "700",      # Configuration files for the at and batch commands
    "/usr/lib.cron/cron.deny": "700",     # Configuration files for the crontab command
    "/usr/lib.cron/cron.allow": "700",    # Configuration files for the crontab command
}

# Permissions ranked from least to most permissive
rank = {
    "---": 8,
    "--x": 7,
    "-w-": 4,
    "-wx": 3,
    "r--": 6,
    "r-x": 5,
    "rw-": 2,
    "rwx": 1
}

to_str = {
    "0": "---",
    "1": "--x",
    "2": "-w-",
    "3": "-wx",
    "4": "r--",
    "5": "r-x",
    "6": "rw-",
    "7": "rwx"
}

to_num = {
    "---": "0",
    "--x": "1",
    "-w-": "2",
    "-wx": "3",
    "r--": "4",
    "r-x": "5",
    "rw-": "6",
    "rwx": "7"
}

def unix_system_file_security(mainframe, client):
    """
    Ensures permissions are at least as restrictive as outlined above.

    Args:
        mainframe: SSH connection
        client: Active SSH client
    """
    print("Check: System files with incorrect permissions")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stigs/ibm_zos_racf/2023-12-27/finding/V-223848")
    
    for key in perms:
        cmd = "ls -alW " + key
        result = mainframe.c_send(client, cmd)
        result = result.strip()

        # The file is not on the system
        if "ls: " in result:
            continue

        if result != "": 
            perm = result.split(" ")[0]
            p = perms[key]
            if key == "/bin/sh":
                sticky = ""
                if "t" in perm:
                    sticky = "1"
                perm = perm.replace("t", "x")
                own = rank[perm[1:4]]
                grp = rank[perm[4:7]]
                all = rank[perm[7:]]
                if own < rank[to_str[p[0]]] or grp < rank[to_str[p[1]]] or all < rank[to_str[p[2]]]:
                    actual_perms = sticky + to_num[perm[1:4]] + to_num[perm[4:7]] + to_num[perm[7:]]
                    display = "[+] " + key + " permissions are " + actual_perms + ". Recommended permissions: " + p
                    colorprint(display)
            else:
                own = rank[perm[1:4]]
                grp = rank[perm[4:7]]
                all = rank[perm[7:]]
                if own < rank[to_str[p[0]]] or grp < rank[to_str[p[1]]] or all < rank[to_str[p[2]]]:
                    actual_perms = to_num[perm[1:4]] + to_num[perm[4:7]] + to_num[perm[7:]]
                    display = "[+] " + key + " permissions are " + actual_perms + ". Recommended permissions: " + p
                    colorprint(display)
    print()

            