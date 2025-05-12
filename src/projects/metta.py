"""
Author: Cameron Oakley (Oakley.CameronJ@gmail.com)
Date: April 2025
Description:
"""

import logging as log
import os
from pathlib import Path
import pandas as pd
import re
import yaml

from src._json_ import read_json
from src._parquet_ import parquet_dataset, parquet_entry
from src._yaml_ import read_yaml
from src.helper import determine_if_script

log.getLogger(__name__)  # Set same logging parameters across contexts

BASE_FILE_PATH: str = "/tmp" + "/metta/"
DIRS_TO_SKIP: list = []
CONVERT_TO_PARQUET_DATASET: list = []


def get_yaml_files() -> list:
    """Function to iterate file system and store path to all YML files."""
    list_of_yaml_files = []

    base_path = Path(BASE_FILE_PATH + "MITRE")
    if base_path.exists():
        log.debug(f"{base_path} exists!")

        # Track all YAML files in a list. They will be parsed in a later step.
        try:
            # log.debug(os.listdir(base_path))
            for subdir in os.listdir(base_path):
                # log.debug(os.listdir(base_path / Path(subdir)))
                for file in os.listdir(base_path / Path(subdir)):
                    yaml_path = Path(f"{base_path}/{subdir}/{file}")
                    # log.debug(yaml_path)

                    # Skip directories we don't want to parse.
                    if file.split(".")[-1:][0] != "yml":
                        log.debug(f"Skipping {yaml_path}")
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


def parse_metta():
    """Main driver for parsing the metta dataset."""
    log.info("Parsing metta dataset!")
    try:
        yaml_files = get_yaml_files()
        # log.debug(yaml_files)

        for yaml_file in yaml_files:
            log.debug(yaml_file)
            yaml_data = read_yaml(yaml_file)
            # log.debug(yaml.dumps(yaml_data, indent=4))
            parse_yaml(yaml_data)

    except OSError as os_e:
        log.error(f"OSError Exception: {os_e}")
    except Exception as e:
        log.error(f"General Exception: {e}")

    # Write parsed data to a parquet file.
    p_db: parquet_dataset = parquet_dataset(CONVERT_TO_PARQUET_DATASET)
    # log.debug(p_db.parquet_entries)
    p_db.write_parquet_file("metta")

    return


def parse_yaml(yaml_data: dict):
    yaml_subset = yaml_data.get("meta", {})
    # log.debug(yaml.dump(yaml_subset, indent=4))

    description = yaml_subset.get("description", str) or ""
    shell = ""

    # This requires some thought, because metta uses old MITRE techniques.
    #   Metta gives us the technique names, but not the IDs.
    technique_name = yaml_subset.get("mitre_attack_technique", str) or ""

    # 1. Try to match the given technique name with the technique ID.
    mitre_techniques = pd.read_csv("./att&ck/mitre_techniques.csv")
    match = mitre_techniques[mitre_techniques["name"] == technique_name]
    # log.debug(match)
    if not match.empty:
        # log.debug(f"Matched {technique_name} with {match["id"].values[0]}!")
        technique_name = match["id"].values[0]

    # # 2. If it has a "mitre_link" field, put the last \T{1-9}{4}.
    # #   Note that some entries have this, some don't...
    # # Example: mitre_link: https://attack.mitre.org/wiki/Technique/T1060
    # #   parse the T1060.
    # elif yaml_subset.get("mitre_link", str):
    #     mitre_link = yaml_subset.get("mitre_link", str)
    #     technique_name = mitre_link.split(   #? Just going to set nothing, see if Taya's RAG can help more.
    #         "/",
    #     )[-1:][0]
    #     log.debug(f"Parsed MITRE link {technique_name}!")

    # 3. Else, put some place holder value and worry about later.
    else:
        # technique_name = technique_name or ""  #? Just going to set nothing, see if Taya's RAG can help more.
        technique_name = ""
        log.info("No technique found in up-to-date MITRE ATT&CK techniques.")

    # Some files may or may not have these "purple actions".
    # Example:
    #   https://github.com/uber-common/metta/blob/master/MITRE/Adversarial_Simulation/simulation_admin338.yml
    if yaml_subset.get("purple_actions", {}):
        for command in yaml_subset.get("purple_actions", {}).values():
            log.debug(command)

            cmd_or_script = "script" if determine_if_script(command) else "command"

            # log.debug(f"{command}\n{description}\n{technique_name}\n{shell}\n")
            global CONVERT_TO_PARQUET_DATASET
            CONVERT_TO_PARQUET_DATASET.append(
                parquet_entry(
                    command, description, technique_name, shell, cmd_or_script
                ).parquet_dict
            )
