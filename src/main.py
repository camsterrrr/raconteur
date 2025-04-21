"""
    Author: Cameron Oakley (Oakley.CameronJ@gmail.com)
    Date: April 2025
    Description: This file consists of a parsing application used 
        that will be built-up to parse various datasets.
"""
import logging as log
import os

from _logging_ import configure_project_logging
from projects.atomic_red_team import parse_atomic_red_team
from projects.lolbas import parse_lolbas
from projects.ThreatActorProcedures import parse_threat_actor_procedure

log.getLogger(__name__)  # Set same logging parameters across contexts


def main() -> int:
    log.info("Starting main application!")
    
    # parse_atomic_red_team()
    parse_lolbas()
    # parse_threat_actor_procedure()
    
    return 0


if (__name__ == "__main__"):
    configure_project_logging()
    main()