"""
This file contains functions, that can be used in engine.py in scanning method functions.
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
    Generate red "closed" text for closed ports

    Returns:
        string: Red "closed" text
    """

    return f"{RED}closed{RESET}"

def filtered():
    """
    Generate red "filtered" text for filtered ports

    Returns:
        string: Red "filtered" text
    """

    return f"{RED}filtered{RESET}"

def closed_or_filtered():
    """
    Generate red "closed or filtered" text for closed or filtered ports

    Returns:
        string: Red "closed or filtered" text
    """

    return f"{RED}closed or filtered{RESET}"


