"""
Author: Cameron Oakley (Oakley.CameronJ@gmail.com)
Date: May 2025
Description: This file organizes different functions that make API calls
    to OpenAI.
"""

import argparse
from dotenv import load_dotenv
import logging as log
import openai
import os
from pathlib import Path


# Read in API key as an environment variable.
load_dotenv()
openai.api_key = os.getenv("openai_token")

# Initialize CLI argument parser.
parser = argparse.ArgumentParser()

# Configure logging.
log.basicConfig(
    datefmt="%Y-%m-%d %H:%M:%S",
    format="%(levelname)s;%(asctime)s;%(message)s",
    level=log.DEBUG,
)


# Prompts for models.
system_context_parse_dataset = """You will be provided with a GitHub repository containing log data files related to MITRE ATT&CK techniques. Your task is to parse the data into a structured JSON format. The dataset is heterogeneous: some log files are security logs, others are application or network logs. The structure and format of these logs are inconsistent.

    Your primary goals are:
    1. Identify the **MITRE ATT&CK technique** associated with each entry (this may be inferred from the directory structure).
    2. Extract the **command or script** that triggered the log entry (this is likely found in the log content).

    For each log entry, generate a JSON object with the following fields:
    - `ID` — a unique numeric identifier starting from 1.
    - `Command` — the command or script that caused the log to be generated.
    - `Description`: a description of the command, not the event. This should summarize what the command does and explain how it relates to the associated MITRE technique.
    - `Risk Score` — *leave blank*.
    - `Offensive-Malware-Benign` — *leave blank*.
    - `MitreAttackClassification` — the corresponding MITRE ATT&CK technique name or ID.
    - `ProgrammingLanguage`: if specified in the data, indicate the shell or scripting language used for the command. Do not infer this if it’s not explicitly given.
    - `CMD_Script` — *leave blank*.
    - `DynTested` — *leave blank*.
    - `ObfuscationLevel` — *leave blank*.

    At a minimum, each JSON entry must include: `ID`, `Command`, and `MitreAttackClassification`. If `Description` or `ProgrammingLanguage` are present in the data, include them. Do not infer or guess values for fields that are not explicitly stated.

    Your output must be a valid JSON **array** of parsed entries, with no extra commentary."""


LOG_FILE_CONTENT = []  # List of dictionaries, mapping file name to file content.
LOG_FILE_NAMES = ["file path, file size (bytes)\n"]


def parse_dataset_helper(start_dir: str, start_path: Path) -> list:
    """
    Helper function to assist the parser iterate the file system recursively when
        directories are found.
    """
    # Iterate over Splunk data and store file contents in a list
    for itr_path in start_path.rglob("*.*"):
        # Files should be 300KB or less. Models can only handl 400KB of data.
        if itr_path.is_file() and (os.path.getsize(itr_path) <= 300000):
            try:
                with open(itr_path) as fd:
                    content = fd.read()

                    global LOG_FILE_CONTENT
                    LOG_FILE_CONTENT.append({"Path": str(itr_path), "Content": content})

                    global LOG_FILE_NAMES
                    LOG_FILE_NAMES.append(
                        f"'{str(itr_path)}', {os.path.getsize(itr_path)}\n"
                    )
                    log.debug(start_dir + str(itr_path))

            except Exception as e:
                print(f"Failed to read {itr_path}: {e}")
        elif itr_path.is_dir():
            parse_dataset_helper(f"{start_dir}/{str(itr_path)}", itr_path)


def parse_dataset():
    """
    This function is used to prompt OpenAI's models to parse a specific dataset.

    Example from OpenAI: http://platform.openai.com/docs/examples/default-parse-data
    """
    # Store reference to file data.
    start_dir = "/tmp/attack_data/datasets/attack_techniques/"
    start_path = Path(start_dir)

    # Store the data returned form OpenAI in a list, write to a file later on...
    parsed_json_data = ["[\n"]

    # Iterate over Splunk data and store file contents in a list
    parse_dataset_helper(start_dir, start_path)

    # Log which files we parse, so we don't do double work later on...
    try:
        if os.path.exists("api/file_paths_parsed.csv"):
            os.remove("api/file_paths_parsed.csv")
        with open(
            "api/file_paths_parsed.csv", "w", encoding="utf-8"
        ) as output_log_data:
            output_log_data.writelines(LOG_FILE_NAMES)
    except OSError as os_e:
        log.error(f"OS Error caught in parse_dataset: {os_e}")
    except Exception as e:
        log.error(f"General exception caught in parse_dataset: {e}")

    # Send the file path and file data to OpenAI model.
    for i, log_data in enumerate(LOG_FILE_CONTENT[:5]):
        user_prompt = f"""Please parse the following log file and extract structured information based on the instructions. This log is part of a dataset of MITRE ATT&CK techniques.
        
        File path: {log_data['Path']}
        Content: {log_data['Content']}
        
        Please extract the following fields:

        - `ID` — A unique number you assign (e.g., 1).
        - `Command` — The command/script that likely triggered this log.
        - `Description` — A description of the command’s purpose as it relates to the MITRE technique. The description should only be based on what is explicitly mentioned in the log file, do not guess.
        - `Risk Score` — Leave blank.
        - `Offensive-Malware-Benign` — Leave blank.
        - `MitreAttackClassification` — Use the directory name ("T1059" in this case).
        - `ProgrammingLanguage` — Indicates the shell language. Include only if it is explicitly stated in the log content.
        - `CMD_Script` — Leave blank.
        - `DynTested` — Leave blank.
        - `ObfuscationLevel` — Leave blank.
        
        **Important:**  
        If you cannot confidently identify a `Command` from the log content, do **not** generate any output for this file. Additionally, if the description field cannot be filled from the log, leave it empty (i.e., ""). 

        Output a single JSON object (not a list). Example format:

        {
            {
                "ID": 1,
                "Command": "...",
                "Description": "...",
                "Risk Score": "",
                "Offensive-Malware-Benign": "",
                "MitreAttackClassification": "T1059",
                "ProgrammingLanguage": "bash",
                "CMD_Script": "",
                "DynTested": "",
                "ObfuscationLevel": ""
            }
        }
        """
        # log.debug(f"\n\n{log_data["Path"]}")
        try:
            response = openai.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": system_context_parse_dataset,
                    },
                    {
                        "role": "user",
                        "content": user_prompt,
                    },
                ],
            )

            response_text = response.choices[0].message.content
            response_text = response_text.replace("`", "")
            response_text = response_text.split("json\n")[1]
            response_text = response_text.strip("\n")
            response_text = response_text + ",\n"

            log.info("Response from model: " + response_text)
            parsed_json_data.append(response_text)

        except Exception as e:
            log.error(e)

    # The last step to make it an actual JSON file.
    parsed_json_data.append("]")

    try:
        if os.path.exists("api/returned_splunk.json"):
            os.remove("api/returned_splunk.json")
        with open(
            "api/returned_splunk.json", "w", encoding="utf-8"
        ) as output_json_data:
            output_json_data.writelines(parsed_json_data)
    except OSError as os_e:
        log.error(f"OS Error caught in parse_dataset: {os_e}")
    except Exception as e:
        log.error(f"General exception caught in parse_dataset: {e}")


def test_api_key():
    """
    This function is used to test the API key and ensure we can invoke an API
        call to OpenAI and that we receive data back.
    """
    try:
        response = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Who invented TCP/IP?"}],
        )
        # log.debug(f"Returned response object: {response}")
        log.debug(f"Returned message: {response.choices[0].message.content}")
    except Exception as e:
        log.error(e)

    log.debug("Done!")


if __name__ == "__main__":

    # test_api_key()
    parse_dataset()
