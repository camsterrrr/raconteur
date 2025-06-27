import logging as log
import os
from pathlib import Path
import re

from src._parquet_ import parquet_dataset, parquet_entry
from src._yaml_ import read_yaml
from src.helper import (
    determine_if_script,
    determine_programming_language,
    strip_command_formatting,
)

log.getLogger(__name__)  # Set same logging parameters across contexts

BASE_FILE_PATH: str = "/tmp" + "/PowerPeeler/samples/100-samples/"
DIRS_TO_SKIP: list = ["Indexes", "used_guids.txt"]
CONVERT_TO_PARQUET_DATASET: list = []


def parse_powerpeeler():
    """Main driver for parsing the PowerPeeler datasets."""
    log.info("Parsing PowerPeeler dataset!")

    for root, dirs, files in os.walk(BASE_FILE_PATH):
        for file in files:
            with open(BASE_FILE_PATH + file) as fd:
                file_data = fd.read()
            # log.debug(file)
            # log.debug(file_data)
            parse_file_data(file_data)

    log.debug(CONVERT_TO_PARQUET_DATASET)
    # Write parsed data to a parquet file.
    p_db: parquet_dataset = parquet_dataset(CONVERT_TO_PARQUET_DATASET)
    # log.debug(p_db.parquet_entries)
    p_db.write_parquet_file("PowerPeeler")

    return


def parse_file_data(file_data: str):
    """Function to iterate YAML data and create parquet dataset entries."""
    # log.debug("Parsing YAML data!")

    if file_data is not None:
        technique_name = ""
        description = ""
        command = file_data
        shell = ""
        programming_language = shell  # determine_programming_language(command, shell)
        cmd_or_script = "script" if determine_if_script(command) else "command"
        command = strip_command_formatting(command)

        # log.debug(dumps(yaml_data, indent=4))
        # log.debug(
        #     f"{command}\n{description}\n{technique_name}\n{shell}\n{cmd_or_script}\n"
        # )
        global CONVERT_TO_PARQUET_DATASET
        CONVERT_TO_PARQUET_DATASET.append(
            parquet_entry(
                command,
                description,
                technique_name,
                programming_language,
                cmd_or_script,
            ).parquet_dict
        )
    else:
        log.debug("There exists no PowerPeeler YAML data!")
