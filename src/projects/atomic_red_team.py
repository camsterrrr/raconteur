"""
Author: Cameron Oakley (Oakley.CameronJ@gmail.com)
Date: April 2025
Description: This file consists of logic to parse data from the
    atomic-red-team dataset. This dataset shows malicious shell commands
    and classifies them based on the MITRE ATT&CK framework.

atomic-red-team GitHub repo: https://github.com/redcanaryco/atomic-red-team/tree/master
"""

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

BASE_FILE_PATH: str = "/tmp" + "/atomic-red-team/atomics/"
DIRS_TO_SKIP: list = ["Indexes", "used_guids.txt"]
CONVERT_TO_PARQUET_DATASET: list = []


def get_yaml_files() -> list:
    """Function to iterate file system and store path to all YAML files."""
    list_of_yaml_files = []

    base_path = Path(BASE_FILE_PATH)
    if base_path.exists():
        log.debug(f"{base_path} exists!")

        # Track all YAML files in a list. They will be parsed in a later step.
        try:
            subdirs = os.listdir(base_path)

            for subdir in subdirs:
                yaml_path = Path(f"{base_path}/{subdir}/{subdir}.yaml")
                # log.debug(yaml_path)

                # Skip directories we don't want to parse.
                if subdir in DIRS_TO_SKIP:
                    # log.debug(f"Skipping {yaml_path}")
                    continue
                # Track the given YAML file.
                elif yaml_path.exists():
                    # log.debug(f"Now tracking {yaml_path}!")
                    list_of_yaml_files.append(yaml_path)
                else:
                    log.warning("Unexpected condition met in get_yaml_files.")

        except Exception as e:
            log.error(f"General exception in get_yaml_files:\n{e}")

    else:
        log.debug(f"{base_path} doesn't exist!")

    return list_of_yaml_files


def parse_atomic_red_team():
    """Main driver for parsing the atomic-red-team datasets."""
    log.info("Parsing atomic-red-team dataset!")

    list_of_yaml_files = get_yaml_files()
    # log.debug(list_of_yaml_files)

    for yaml_file_path in list_of_yaml_files:
        yaml_data = read_yaml(yaml_file_path)
        parse_yaml(yaml_data)
        # break

    # Write parsed data to a parquet file.
    p_db: parquet_dataset = parquet_dataset(CONVERT_TO_PARQUET_DATASET)
    # log.debug(p_db.parquet_entries)
    p_db.write_parquet_file("atomic-red-team")

    return


def parse_yaml(yaml_data: dict):
    """Function to iterate YAML data and create parquet dataset entries."""
    # log.debug("Parsing YAML data!")

    if yaml_data is not None:
        technique_name = yaml_data["attack_technique"]

        for name in yaml_data["atomic_tests"]:
            yaml_subset = name  # For less verbose indexing.

            # Some data may or may not be there... Account for this.
            # None will be translated to "NaN" automatically by Pandas.
            description = yaml_subset.get("description", {}) or None
            command = (
                yaml_subset.get("executor", {}).get("command")
                or yaml_subset.get("executor", {}).get("steps")
                or None
            )
            shell = yaml_subset.get("executor", {}).get("name") or None
            programming_language = determine_programming_language(command, shell)
            cmd_or_script = "script" if determine_if_script(command) else "command"
            command = strip_command_formatting(command)

            # Replace the default values. atomic-red-team provides placeholder
            #   values in the command that we need to fill in.
            if command:
                # Fill in any default values
                list_of_matches = re.findall(r"#\{[A-Za-z0-9_\-]+\}", command)
                for match in list_of_matches:
                    match_stripped = match.strip("#{}")

                    default = (
                        yaml_subset.get("input_arguments", {})
                        .get(match_stripped, {})
                        .get("default")
                    )
                    # Normalize to string, handling None or non-str values
                    default = str(default) if default is not None else ""

                    command = command.replace(match, default)
                    # There are four descriptions that use these placeholders.
                    description = description.replace(match, default)
                    # log.debug(f"Replaced {match} with {default}")

            # log.debug(dumps(yaml_data, indent=4))
            # log.debug(f"{command}\n{description}\n{technique_name}\n{shell}\n{cmd_or_script}\n")
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
        log.debug("There exists no atomic-red-team YAML data!")

    return
