"""
Author: Cameron Oakley (Oakley.CameronJ@gmail.com)
Date: April 2025
Description: This file consists of helper functions to parse the datasets.
"""

import logging as log
import re

log.getLogger(__name__)  # Set same logging parameters across contexts

SCRIPT_KEYWORD_RE = [
    r"\bfunction\b",
    r"\bfor\b",
    r"\bwhile\b",
    r"\bif\b",
    r"\bthen\b",
    r"\bdo\b",
]

CMD_RE = [
    r"@echo\s+(off|on)",  # Silence output (re.IGNORECASE?)
    r":\s*\w+",  # Labels
    r"\bif\b|\bgoto\b|\bcall\b|\bfor\b|\bsetlocal\b|\bendlocal\b",  # (re.IGNORECASE?)
    r"\bset\s+\w+",  # Variable setting (re.IGNORECASE?)
    r"%%\w+",  # For loop variables
    r"::.*",  # Comments
    r"rem\s+",  # REM comments (re.IGNORECASE?)
]

JAVASCRIPT_RE = [
    r"function\s+\w+|\b\w+\s*=\s*function",  # Function instantiation
    r"=>",  # Arrow functions
    r"class\s+\w+",  # Class instantiation
    r"import\s+|export\s+",  # Import libraries
    r"const\s+\w+|let\s+\w+|var\s+\w+",  # Variable instantiation
    r"//.*|/\*[\s\S]*?\*/",  # Comments
    r"try\s*{|catch\s*\(|finally\s*{",  # Exception handling
    r"^\s*async\s+",  # Async function instantiation
]

POWERSHELL_RE = [
    r"function\s+\w+",  # Function instantiation (re.IGNORECASE?)
    r"param\s*\(",  # Function parameters (re.IGNORECASE?)
    r"\$\w+\s*=",  # Variable assignment
    r"<#.*?#>",  # Block comments (re.DOTALL?)
    r"\[cmdletbinding\(\)",  # (re.IGNORECASE?)
    r"begin\s*{|process\s*{|end\s*{",  # (re.IGNORECASE?)
    r"try\s*{|catch\s*{|finally\s*{",  # Exception handling (re.IGNORECASE?)
]

PYTHON_RE = [
    r"def\s+\w+",  # Function instantiation
    r"class\s+\w+",  # Class instantiation
    r"import\s+\w+|from\s+\w+\s+import",  # Module import
    r'"""[\s\S]+?"""|\'\'\'[\s\S]+?\'\'\'',  # Docstrings
    r"with\s+\w+|try:|except\s+|finally:",  # Exception handling
    r"^\s*@\w+",  # Decorators, re.MULTILINE?
    r"lambda\s+\w+:",  # Lambda functions
    r"yield\s+\w+",  # Generators
]

SHELL_RE = [
    r"#!/bin/\w+|#!/usr/bin/env\s+\w+",  # Shell interpretter
    r"function\s+\w+|\w+\(\)\s*{",  # Function declaration
    r"\bif\b|\belse\b|\belif\b|\bfi\b|\bcase\b|\besac\b|\bfor\b|\bdone\b",
    r"export\s+\w+|local\s+\w+|readonly\s+\w+",
    r"\$\(\s*\w+|`\w+`",  # Command substitution
    r"\[\[.*?\]\]|\[.*?\]",  # Test constructs
    # script_string.count(';') > 2)                   # Multiple commands with semicolons
]

SQL_RE = [
    r"CREATE\s+(TABLE|VIEW|PROCEDURE|FUNCTION|TRIGGER)",  # SQL keyword (re.IGNORECASE?)
    r"BEGIN\s+|END;",  # SQL keyword (re.IGNORECASE?)
    r"DECLARE\s+",  # SQL keyword (re.IGNORECASE?)
    r"SELECT\s+.*?\s+FROM\s+.*?\s+(WHERE|GROUP BY|ORDER BY)",  # SQL query (re.IGNORECASE?)
    r"--.*|/\*[\s\S]*?\*/",  # Comments
    # script_string.count(';') > 1):                          # Multiple SQL statements
]


def determine_if_script(parsed_command: str) -> bool:
    """
        Function used to determine if a parsed command is a single-command
            or a script. This function determines this by looking at the
            structure of the command. If some regex pattern matches, we
            classify the command as a script.

    Args:
        command (str): The command we want to whether it is a script.

    Returns:
        bool: Return True if the parsed command matches any of the regex
            patterns. True means the parsed command is a script and False
            means it is just a single-command. By default return False.
    """

    script_control_re = re.compile(r"(?:^|\s)(&&|\|\||2>|>|<|\||;)(?=\s|$)")

    # First, start by checking indicators that apply to most script types.
    general_script_re = [
        # Multiple statements (2+ lines that aren't just whitespace/comments)
        len(
            [
                line
                for line in parsed_command.split("\n")
                if (
                    line.strip()
                    and not line.strip().startswith(("#", "//", "--", "/*", "::"))
                )
            ]
        )
        > 1,
        # Multiple statements separated by semicolons. One notable heuristic,
        #   3 or more likely indicates a script.
        len(re.findall(r";\s*\w+", parsed_command)) >= 2,
        # Control flow keywords. '\b' prevents us from matching on 'diff".
        re.search(
            r"\b(if|for|while|switch|case|do|foreach|loop)\b",
            parsed_command,
            re.IGNORECASE,
        ),
        # Variable assignments. One notable heuristic, multiple assignments
        #   indicates a script.
        len(
            re.findall(
                r"(\w+\s*=|\bset\b|\blet\b|\bvar\b|\bconst\b|\blet\b)", parsed_command
            )
        )
        > 1,
        # Multiple control operators. One notable heuristic, 2 or more
        #   likely indicates a script.
        # (?<=\s|^) means it must be preceded by a space or start-of-string
        len(script_control_re.findall(parsed_command)) >= 2,
    ]

    # general_script_indicators is a list of bools. If any elements are
    #   true, this command should be classified as a script.
    if any(general_script_re):
        return True

    # Use regex patterns specific to different languages. If any match,
    #   then the command is a script.

    re_script_patterns = [
        SCRIPT_KEYWORD_RE,
        CMD_RE,
        POWERSHELL_RE,
        SHELL_RE,
        PYTHON_RE,
        # SQL_RE,
        # JAVASCRIPT_RE,
    ]

    for list_of_patterns in re_script_patterns:
        for pattern in list_of_patterns:
            if re.search(pattern, parsed_command, re.IGNORECASE):
                return True

    return False


def determine_programming_language(
    command: str, programming_language: str = None
) -> str:
    """
    This function is responsible for determining the programming language of a
        parsed command. Most datasets don't classify this information, so we
        determine it by using characteristics of each programming language.

    Args:
        command (str): The command we want to know the programming language for.
        programming_language (str, optional): Some datasets identify the
            programming language for us. However, most don't. If the programming
            language is known, pass it in to the function to standardize the
            naming. Defaults to None.

    Returns:
        str: The programming language identified.

    Notes:
        - This function does not take into consideration obfuscation of commands.
            Command could be encoded in Base64, etc.
        - This matches the first programming language pattern. If we determine
            multiple languages overlap, we can add weights and classify using
            the highest scoring language.
    """

    # The atomic-red-team dataset already has a label for the shell
    #   language. This section will convert it to something standard
    #   for our dataset.
    if programming_language:
        programming_language = programming_language.lower()

        if programming_language == "powershell":
            return "ps1"
        elif (
            programming_language == "sh"
            or programming_language == "bash"
            or programming_language == "applescript"
        ):
            return "shell"
        elif programming_language == "command_prompt":
            return "cmd"
        elif programming_language == "manual":
            return "manual"

        # * Verify nothing in atomic-red-team meets this condition!
        else:
            log.warning(
                f"Condition not met in 'determine_programming_language': \t{command}, {programming_language}"
            )
            # Don't return anything amd figure it out in the next section...

    # Assume we don't know the shell language. Determine it by matching
    #   keywords of different languages. The section below will iterate
    #   over all rules. If any pattern matches, return the programming
    #   language associated with the rule.

    RE_LANGUAGE_MAP = {
        # list of regex patterns, programming language
        tuple(CMD_RE): "cmd",
        tuple(POWERSHELL_RE): "ps1",
        tuple(SHELL_RE): "shell",
        tuple(PYTHON_RE): "py",
        # tuple(SQL_RE): "sql",
        # tuple(JAVASCRIPT_RE): "js",
    }

    for list_of_patterns, language in RE_LANGUAGE_MAP.items():
        for pattern in list_of_patterns:

            # If the pattern matches, determine the language its
            #   associated with.
            if re.search(pattern, command, re.IGNORECASE):
                return language

    # Ideally, this case shouldn't be met. If none of the
    #   conditions match, just leave the value empty.
    log.error("No case matched in determine_programming_language:\t" + f"{command}")
    return None


def strip_command_formatting(command: str) -> str:
    """
        Normalize the special characters in the parsed commands.

    Args:
        command (str): The parsed command with raw formatting
        characters.

    Returns:
        str: The same command with stripped special and formatting
            characters.
    """
    # log.debug("Stripping special characters.")

    command = re.sub(r"[ ]{4}+", r"\\t", command)
    command = re.sub(r"\t+", r"\\t", command)
    command = command.replace("\r", "\\r")
    command = command.strip()

    return command
