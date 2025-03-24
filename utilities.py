from colorama import Fore, Style


def print_logo():
    """
    Display the logo
    """
    print()
    print()
    print()
    print()
    print()
    print()
    print()
    print()
    print()
    print()
    print()
    print()
    print(" __   __         ______    _______  __   __      |        ")
    print("|  |_|  |       |    _ |  |   _   ||  | |  |  - ( ) -     ")
    print("|       | ____  |   | ||  |  |_|  ||  |_|  |     | \\     ")
    print("|       ||____| |   |_||_ |       ||       |        \\\\  ")
    print("|       |       |    __  ||       ||_     _|         \\\\ ")
    print("| ||_|| |       |   |  | ||   _   |  |   |            \\\\")
    print("|_|   |_|       |___|  |_||__| |__|  |___|              \\")
    print()
    print("The (M)ainf(RAY)me Vulnerability Scanner")
    print()


def gather_info():
    """
    Get tool options from the user.

    Return:
        host (str): IP of target mainframe
        conn (str): Type of connection to use 
    """
    host = input("Target IP: ")
    conn = input("Check Type {unix, tso, enum, recon}: ")
    return host, conn


def colorprint(output):
    """
    Display the output of a check depending on its result
    """
    if output[0:3] == "[-]":
        print(Fore.RED + output)
    elif output[0:3] == "[+]":
        print(Fore.GREEN + output)
    elif output[0:3] == "[?]":
        print(Fore.YELLOW + output)
    else:
        print(output)

    print(Style.RESET_ALL, end="")


def scriptcolor(desc):
    """
    Print the description of a script in a different color
    """
    print(Fore.YELLOW + desc)
    print(Style.RESET_ALL, end="")