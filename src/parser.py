"""
    Author: Cameron Oakley (Oakley.CameronJ@gmail.com)
    Date: April 2025
    Description: This file consists of a parsing application used 
        that will be built-up to parse various datasets.
"""
import logging as log
import os

from _logging_ import configure_project_logging
from _yaml_ import read_yaml
from atomic_red_team import parse_atomic_red_team

log.getLogger(__name__)  # Set same logging parameters across contexts


def main() -> int:
    log.info("Starting main application!")
    
    yaml_data= read_yaml("./test_data/T1001.002.yaml")
    parse_atomic_red_team(yaml_data)
    
    return 0


if (__name__ == "__main__"):
    configure_project_logging()
    main()