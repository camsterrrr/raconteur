"""
    Author: Cameron Oakley (Oakley.CameronJ@gmail.com)
    Date: April 2025
    Description: This file consists of logic to interact with YAML data.
"""

import logging as log
import os
from pathlib import Path
import yaml

log.getLogger(__name__)  # Set same logging parameters across contexts

def read_yaml(file_path: str) -> dict:
    file_path_obj = Path(file_path.strip())
    
    # Check that the file exists; this string should come from a
    #   trusted source - better safe than sorry.
    if file_path_obj.exists(): 
        log.debug(f"{file_path} exists!")
        
        with open(file_path_obj) as fd:
            try:
                file_str = fd.read()
                yaml_str = yaml.safe_load(file_str)
                
                # log.debug(file_str)
                # log.debug(yaml_str)
                
                return yaml_str
            except yaml.YAMLError as ye:
                log.error(f"{ye}")
            except Exception as e:
                log.error(f"{e}")
    else: 
        log.debug(f"{file_path} doesn't exist!")

    return None