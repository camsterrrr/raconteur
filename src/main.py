"""
Author: Cameron Oakley (Oakley.CameronJ@gmail.com)
Date: April 2025
Description: This file consists of a parsing application used
    that will be built-up to parse various datasets.
"""

import logging as log
import os

from src._logging_ import configure_project_logging
from src.helper import *
from src.projects.atomic_red_team import parse_atomic_red_team
from src.projects.lolbas import parse_lolbas
from src.projects.metta import parse_metta
from src.projects.ThreatActorProcedures import parse_threat_actor_procedure

log.getLogger(__name__)  # Set same logging parameters across contexts


def main() -> int:
    log.info("Starting main application!")

    # parse_atomic_red_team()
    # parse_lolbas()
    # parse_metta()
    # parse_threat_actor_procedure()

    return 0


if __name__ == "__main__":
    configure_project_logging()
    main()
