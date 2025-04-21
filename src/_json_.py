"""
    Author: Cameron Oakley (Oakley.CameronJ@gmail.com)
    Date: April 2025
    Description: This file consists of logic to interact with JSON data.
"""

import json
import logging as log
import os
from pathlib import Path

log.getLogger(__name__)  # Set same logging parameters across contexts

def read_json(file_path_obj: Path) -> dict:
    # Check that the file exists; this string should come from a
    #   trusted source - better safe than sorry.
    if file_path_obj.exists(): 
        log.debug(f"{file_path_obj} exists!")
        
        with open(file_path_obj) as file_data:
            try:
                json_dict = json.load(file_data)
                
                return json_dict
            except json.JSONDecodeError as je:
                log.error(f"JSON exception in read_json:{je}")
            except Exception as e:
                log.error(f"General exception in read_json:{e}")
    else: 
        log.debug(f"{file_path_obj} doesn't exist!")

    return None