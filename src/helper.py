"""
    Author: Cameron Oakley (Oakley.CameronJ@gmail.com)
    Date: April 2025
    Description: This file consists of helper functions to parse the datasets.
"""

import re

def determine_if_cmd_or_script(command: str) -> bool:
    """
        Function used to determine if a parsed command is a single-command
            or a script.
    
        Key difference: One key difference lies in the mode of execution. 
        Command line usage is interactive, meaning you type a command and 
        wait for the result before proceeding. In contrast, shell scripting 
        is batch-oriented; you write all the commands beforehand, 
        and the shell executes them in sequence without further input from 
        you.
    """
    
    # If any of the following conditions hold, it must be a script.
    # 1. Check if the command has a new-line character.
    if '\n' in command:
        return True
    
    # 2. Check for chaining or control characters.
    script_control = [
        r'&&',
        r'\|\|',
        r'>',
        r'<',
        r'2>',
        r'\|',
        r'\\',
        r';'
    ]
    for pattern in script_control:
        if re.search(pattern, command, re.IGNORECASE):
            return True

    # 3. Search keywords or structures.
    script_keywords = [
        r'\bfunction\b',
        r'\bfor\b',
        r'\bwhile\b',
        r'\bif\b',
        r'\bthen\b',
        r'\bdo\b'
    ]
    for pattern in script_keywords:
        if re.search(pattern, command, re.IGNORECASE):
            return True
    
    return False