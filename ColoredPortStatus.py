"""
This file contains two functions, that can be used in engine.py scanning method functions.
"""

RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

def opened():
    """
    Generate green "open" text for open ports

    Returns:
        string: Green "open" text
    """

    return f"{GREEN}open{RESET}"

def closed():
    """
    Generate red "closed or filtered" text for closed or filtered ports

    Returns:
        string: Red "closed or filtered" text
    """

    return f"{RED}closed or filtered{RESET}"


