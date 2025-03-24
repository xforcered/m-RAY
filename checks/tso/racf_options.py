# Many z/OS misconfigurations have to do with misconfigured RACF settings. 
# This is a set of checks against RACF, combined as one check to avoid running 
# the same command against the mainframe multiple times. 

from utilities import colorprint


def racf_options(mainframe, client):
    cmd = "tsocmd setropts list"
    result = mainframe.c_send(client, cmd)
    result = result.split("\n")

    sections = list()
    buildline = ""
    for line in result:
        if line == "":
            continue
        elif line[0].isspace():
            line = line.strip() + " "
            buildline += line
        else:
            sections.append(buildline)
            buildline == ""
            buildline = line.strip() + " "
            

    sections.append(buildline)

    return sections
    

def racf_for_unix_active(sections):
    """
    The IBM RACF classes required to properly secure the z/OS UNIX environment must be ACTIVE
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223850
    Sev = med

    If permissions for execution are higher than privs of users, the users indirectly
    have greater privileges when running those programs. Check that this is not the case.

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: UNIX environment is properly secured")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223850")

    # if the ACTIVE CLASSES list includes entries for the FACILITY, SURROGAT, and UNIXPRIV resource classes, this is not a finding.
    # If either of the above resource classes is missing, this is a finding. 
    active_classes = ["FACILITY", "SURROGAT", "UNIXPRIV"]
    result = True

    for i in sections:
        if "ACTIVE CLASSES" in i:
            for c in active_classes:
                if c not in i:
                    result = False

    if result == True:
        display = "[-] UNIX environment is properly secured."
    elif result == False:
        display = "[+] FACILITY, SURROGAT, or UNIXPRIV missing from RACF ACTIVE CLASSES."

    colorprint(display)
    print()


def jesspool_res_active(sections):
    """
    IBM z/OS JESSPOOL resources must be protected in accordance with security requirements. 
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223750
    Sev = med

    Access control should not just rely on possession of a certificate.

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: JESSPOOL resources properly protected")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223750")

    result = True

    for i in sections:
        if "ACTIVE CLASSES" in i:
            if "JESSPOOL" not in i:
                result = False

    if result == True:
        display = "[-] JESSPOOL resource class is active."
    elif result == False:
        display = "[+] JESSPOOL resource class missing from RACF ACTIVE CLASSES."

    colorprint(display)
    print()


def dfsms_racf_active(sections):
    """
    The IBM z/OS DFSMS-related RACF classes must be active.
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223817
    Sev = med

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: DFSMS properly secured in RACF")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223817")

    # if the ACTIVE CLASSES list includes entries for the FACILITY, MGMTCLAS, STORCLAS, and
    # PROGRAM resource classes, this is not a finding.
    # If any of the above resource classes is missing, this is a finding. 
    active_classes = ["FACILITY", "MGMTCLAS", "STORCLAS", "PROGRAM"]
    result = True

    for i in sections:
        if "ACTIVE CLASSES" in i:
            for c in active_classes:
                if c not in i:
                    result = False

    if result == True:
        display = "[-] DFSMS RACF classes are properly secured."
    elif result == False:
        display = "[+] FACILITY, MGMTCLAS, STORCLAS, or PROGRAM missing from RACF ACTIVE CLASSES."

    colorprint(display)
    print()


def mcs_console_res_active(sections):
    """
    The IBM RACF MCS consoles resource class must be active. 
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223659
    Sev = med

    Access control should not just rely on possession of a certificate.

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: MCS consoles resource class active")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223659")

    result = True

    for i in sections:
        if "ACTIVE CLASSES" in i:
            if "CONSOLE" not in i:
                result = False

    if result == True:
        display = "[-] CONSOLE resource class is active."
    elif result == False:
        display = "[+] CONSOLE resource class missing from RACF ACTIVE CLASSES."

    colorprint(display)
    print()


def opercmds_res_active(sections):
    """
    The IBM RACF OPERCMDS resource class must be active. 
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223658
    Sev = med

    Access control should not just rely on possession of a certificate.

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: OPERCMDS resource class active")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223658")

    result = True

    for i in sections:
        if "ACTIVE CLASSES" in i:
            if "OPERCMDS" not in i:
                result = False

    if result == True:
        display = "[-] OPERCMDS resource class is active."
    elif result == False:
        display = "[+] OPERCMDS resource class missing from RACF ACTIVE CLASSES."

    colorprint(display)
    print()


def facility_res_active(sections):
    """
    The IBM RACF FACILITY resource class must be active. 
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223657
    Sev = med

    FACILITY protects a number of features and products, if this is not activated,
    there will be a number of unprotected resources on the system. 

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: FACILITY resource class active")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223657")

    result = True

    for i in sections:
        if "ACTIVE CLASSES" in i:
            if "FACILITY" not in i:
                result = False

    if result == True:
        display = "[-] FACILITY resource class is active."
    elif result == False:
        display = "[+] FACILITY resource class missing from RACF ACTIVE CLASSES."

    colorprint(display)
    print()


def when_program_active(sections):
    """
    The IBM RACF WHEN(PROGRAM) SETROPTS value specified must be active. 
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223708
    Sev = med

    WHEN(PROGRAM) configures program security mode, so should be active for program profiles to be secure. 

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: WHEN(PROGRAM) value active")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223708")

    result = True

    for i in sections:
        if "ATTRIBUTES" in i:
            if "NOWHEN(PROGRAM)" in i:
                result = False

    if result == True:
        display = "[-] WHEN(PROGRAM) value set properly."
    elif result == False:
        display = "[+] WHEN(PROGRAM) value set to NOWHEN(PROGRAM)."

    colorprint(display)
    print()


def group_access_chk_active(sections):
    """
    The IBM RACF GRPLIST SETROPTS value must be set to ACTIVE. 
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223705
    Sev = med

    List of groups access checking should be active.

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: Groups Access Checking active")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223705")

    result = False

    for i in sections:
        if "LIST OF GROUPS ACCESS CHECKING IS ACTIVE." in i:
            result = True

    if result == True:
        display = "[-] Group Access Checking RACF value is ACTIVE."
    elif result == False:
        display = "[+] GRPLIST SETROPTS RACF value is not set."

    colorprint(display)
    print()


def real_data_set_names(sections):
    """
    The IBM RACF REALDSN SETROPTS value must be specified. 
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223700
    Sev = med

    Need to associate the identity of subjects with events. 

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: Real Data Set Names Option is Active")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223700")

    result = True

    for i in sections:
        if "REAL DATA SET NAMES OPTION IS INACTIVE" in i:
            result = False

    if result == True:
        display = "[-] REALDSN RACF value is ACTIVE."
    elif result == False:
        display = "[+] REALDSN RACF value is not set."

    colorprint(display)
    print()


def retention_period(sections):
    """
    The IBM RACF RETPD SETROPTS value must be properly set. 
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223706
    Sev = med

    Retention Period. 

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: RETPD Option is properly set")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223706")

    result = True

    for i in sections:
        if "SECURITY RETENTION PERIOD IN EFFECT IS" in i:
            if "NEVER-EXPIRES" in i:
                result = False

    if result == True:
        display = "[-] Retention Period is set correctly."
    elif result == False:
        display = "[+] Retention Period is not set to NEVER-EXPIRE"

    colorprint(display)
    print()


def saudit_value_set(sections):
    """
    The IBM RACF SETROPTS SAUDIT value must be specified. 
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223699
    Sev = med

    Audit records should be generated to attribute events.  

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: RETPD Option is properly set")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223699")

    result = True

    for i in sections:
        if "ATTRIBUTES" in i:
            if "NOSAUDIT" in i:
                result = False

    if result == True:
        display = "[-] SAUDIT attribute is set correctly."
    elif result == False:
        display = "[+] NOSAUDIT is set as an attribute."

    colorprint(display)
    print()


def jes_batchallracf(sections):
    """
    The IBM RACF JES(BATCHALLRACF) SETROPTS value must be set to JES(BATCHALLRACF). 
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223692
    Sev = med

    Require all batch jobs to run with a RACF identity.  

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: Batch Jobs use RACF Identity - BATCHALLRACF")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223692")

    result = True

    for i in sections:
        if "JES-BATCHALLRACF OPTION IS INACTIVE" in i:
            result = False

    if result == True:
        display = "[-] Batch jobs require RACF identity to run."
    elif result == False:
        display = "[+] Batch jobs do not require RACF identity to run."

    colorprint(display)
    print()


def jes_xbmallracf(sections):
    """
    The IBM RACF JES(XBMALLRACF) SETROPTS value must be set to JES(XBMALLRACF). 
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223693
    Sev = med

    Require all batch jobs to run with a RACF identity.  

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: Batch Jobs use RACF Identity - XBMALLRACF")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223693")

    result = True

    for i in sections:
        if "JES-XBMALLRACF OPTION IS INACTIVE" in i:
            result = False

    if result == True:
        display = "[-] JES(XBMALLRACF) option is set properly."
    elif result == False:
        display = "[+] JES(XBMALLRACF) option is inactive."

    colorprint(display)
    print()


def inactive_id_revoke(sections):
    """
    The IBM RACF INACTIVE SETROPTS value must be set to 35 days. 
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223723
    Sev = med

    Inactive identifiers should be revoked after 35 days.  

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: Inactive UserIDs revoked")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223723")

    result = True
    days = ""

    for i in sections:
        if "INACTIVE USERIDS ARE " in i:
            if "NOT BEING AUTOMATICALLY REVOKED" in i:
                days = "Inactive USERIDs are never revoked."
                result = False
            else:
                day = i.split(" ")[-2]
                if int(day) > 35:
                    days = "Inactive USERIDs are revoked after " + day
                    result = False

    if result == True:
        display = "[-] Inactive USERIDs are revoked in 35 days or less."
    elif result == False:
        display = "[+] " + days

    colorprint(display)
    print()


def password_history(sections):
    """
    The IBM RACF PASSWORD(HISTORY) SETROPTS value must be set to 5 or more. 
    https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223728
    Sev = med

    Password should not be any of 5 or more past passwords.

    Args:
        sections: SETROPTS LIST results
    """
    print("Check: Password History is set to 5 or more")
    print("       Severity if present: MEDIUM")
    print("       Context: https://www.stigviewer.com/stig/ibm_zos_racf/2023-12-27/finding/V-223728")

    result = True

    for i in sections:
        if "NO PASSWORD HISTORY BEING MAINTAINED." in i:
            result = False
        if "GENERATIONS OF PREVIOUS PASSWORDS BEING MAINTAINED" in i:
            words = i.split(" ")
            if int(words[0]) < 5:
                result = False

    if result == True:
        display = "[-] Password history is set to 5 or more."
    elif result == False:
        display = "[+] Password history is not being properly maintained."

    colorprint(display)
    print()
