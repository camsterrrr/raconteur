"""
    Author: Cameron Oakley (Oakley.CameronJ@gmail.com)
    Date: April 2025
    Description: 
"""

import logging as log
import os
from pathlib import Path
import re

from _parquet_ import *
from _yaml_ import read_yaml
from helper import determine_if_cmd_or_script

log.getLogger(__name__)  # Set same logging parameters across contexts

BASE_FILE_PATH: str = (
    "/tmp" + "/ThreatActorProcedures-MITRE-ATTACK/README.md"
)
DIRS_TO_SKIP: list = []
CONVERT_TO_PARQUET_DATASET: list = []


def parse_threat_actor_procedure():
    """ Main driver for parsing the ThreatActorProcedures dataset. """
    log.info("Parsing ThreatActorProcedure dataset!")
    try: 
        with open(BASE_FILE_PATH, "r", encoding="utf-8") as md_data:
        # with open("./test_data/test_md.md", "r", encoding="utf-8") as md_data:
            parse_md(md_data)
    except OSError as os_e:
        log.error(f"OSError Exception: {os_e}")
    except Exception as e:
        log.error(f"General Exception: {e}")

    # Write parsed data to a parquet file.
    p_db : parquet_dataset = parquet_dataset(CONVERT_TO_PARQUET_DATASET)
    # log.debug(p_db.parquet_entries)
    p_db.write_parquet_file("ThreatActorProcedures")
    
    return


def parse_md(md_data: str):
    """"""
    log.debug("Parsing MD data!")
    global CONVERT_TO_PARQUET_DATASET
    
    if (md_data is not None):
        pattern = r"T\d{4}(?:\.\d{3})?"
        in_code_block: bool = False
        technique_name: str = None
        
        for line in md_data:
            command: str
            
            matches = re.findall(pattern, line)
            
            # Set flag if we are in between "``` ... ```"
            if "```" in line:
                log.debug("Entered code block!")
                in_code_block = not in_code_block

            # Create parquet entry for commands.
            elif in_code_block:
                command = line.strip("\n")
                description = None
                shell = None
                cmd_or_script = (
                    "script" if determine_if_cmd_or_script(command) else "command"
                )
                dyn_tested = None
                
                log.debug(f"{command}; {description}; {technique_name}; {shell};")
                
                CONVERT_TO_PARQUET_DATASET.append(
                    parquet_entry(command, description, technique_name, shell, cmd_or_script, dyn_tested).parquet_dict
                )
            elif len(matches) > 0:
                technique_name = matches[0]
                
                # I don't expect this to occur
                if len(matches) > 1:
                    log.warning(f"Has more than one technique: {matches} - {line}")
    else: 
        log.debug("There exists no atomic-red-team YAML data!")
    
    return