"""
    Author: Cameron Oakley (Oakley.CameronJ@gmail.com)
    Date: April 2025
    Description: This file consists of logic to parse data from the 
        atomic-red-team dataset. This dataset shows malicious shell commands
        and classifies them based on the MITRE ATT&CK framework.
        
    atomic-red-team GitHub repo: https://github.com/redcanaryco/atomic-red-team/tree/master
"""

import logging as log

log.getLogger(__name__)  # Set same logging parameters across contexts

def parse_atomic_red_team(yaml_data: dict):
    if (yaml_data is not None):
        parquet = []
        
        technique_name = yaml_data["attack_technique"]
        
        for name in yaml_data["atomic_tests"]:
            yaml_subset = name
            description = yaml_subset[description]
            command = yaml_subset["executor"][""]
            
            # get command
            # get description
            # get shell language
            log.debug(f"{name}\n")
    else: 
        log.debug("There exists no atomic-red-team YAML data!")