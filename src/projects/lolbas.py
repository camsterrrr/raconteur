"""
Author: Cameron Oakley (Oakley.CameronJ@gmail.com)
Date: April 2025
Description:
"""

import logging as log
import os
from pathlib import Path
import re
import yaml


from src._json_ import read_json
from src._parquet_ import parquet_dataset, parquet_entry
from src._yaml_ import read_yaml
from src.helper import determine_if_script, strip_command_formatting

log.getLogger(__name__)  # Set same logging parameters across contexts

BASE_FILE_PATH: str = "/tmp" + "/lolbas.json"
DIRS_TO_SKIP: list = []
CONVERT_TO_PARQUET_DATASET: list = []


def parse_lolbas():
    """Main driver for parsing the LOLBAS dataset."""
    log.info("Parsing LOLBAS dataset!")
    try:
        json_path = Path(BASE_FILE_PATH)
        json_data = read_json(json_path)
        # log.debug(dumps(json_data, indent=4))
        parse_json(json_data)

    except OSError as os_e:
        log.error(f"OSError Exception: {os_e}")
    except Exception as e:
        log.error(f"General Exception: {e}")

    # Write parsed data to a parquet file.
    p_db: parquet_dataset = parquet_dataset(CONVERT_TO_PARQUET_DATASET)
    # log.debug(p_db.parquet_entries)
    p_db.write_parquet_file("lolbas")

    return


def parse_json(json_data: dict):

    for ele in json_data:
        json_subset = ele.get("Commands")
        # log.debug(yaml.dump(json_subset, indent=4))
        # log.debug(len(json_subset))

        for lolbas_entry in json_subset:
            command = lolbas_entry.get("Command", str) or ""
            description = (
                lolbas_entry.get("Description", str)
                + " "
                + (ele.get("Description", str) or "")
            ) or ""
            technique_name = lolbas_entry.get("MitreID", str) or ""
            shell = ""
            cmd_or_script = "script" if determine_if_script(command) else "command"
            command = strip_command_formatting(command)

            # log.debug(f"{command}\n{description}\n{technique_name}\n{shell}\n")
            global CONVERT_TO_PARQUET_DATASET
            CONVERT_TO_PARQUET_DATASET.append(
                parquet_entry(
                    command, description, technique_name, shell, cmd_or_script
                ).parquet_dict
            )
