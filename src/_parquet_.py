import logging as log
from json import dumps
from pandas import DataFrame as df
from pathlib import Path

log.getLogger(__name__)  # Set same logging parameters across contexts

COLUMNS = [
    "ID",
    "Command",
    "Description",
    "Risk Score",
    "Offensive-Malware-Benign",
    "MitreAttackClassification",
    "ProgrammingLanguage",
    "CMD_Script",
    "DynTested",
]
GLOBAL_ID = 0
OUTPUT_DIR = "./parquet/separated_parquets"


class parquet_dataset:

    def __init__(self, parquet_entries: dict):
        self.parquet_entries: dict = parquet_entries

    def write_parquet_file(self, file_name: str):
        output_path_parquet = Path(f"{OUTPUT_DIR}/{file_name}.parquet")
        output_path_json = Path(f"{OUTPUT_DIR}/{file_name}.json")

        try:
            # log.debug(dumps(self.parquet_entries, indent=4))
            df_obj = df(self.parquet_entries)
            df_obj.to_parquet(
                output_path_parquet,
                # compression="gzip",
                # partition_cols=COLUMNS,
                index=False,
            )
            df_obj.to_json(output_path_json, orient="records", indent=4)
        except Exception as e:
            log.error(f"{e}")


class parquet_entry:

    def __init__(
        self,
        command: str,
        description: str,
        mitre_attack_classification: str,
        shell: str,
        cmd_or_script: str,
    ):
        global GLOBAL_ID
        GLOBAL_ID += 1

        self.parquet_dict = {
            "ID": GLOBAL_ID,
            "Command": command,
            "Description": description,
            "RiskScore": None,
            "Offensive-Malware-Benign": None,
            "MitreAttackClassification": mitre_attack_classification,
            "ProgrammingLanguage": shell,
            "CMD_Script": cmd_or_script,
            "DynTested": None,
        }

        # self.id: int = GLOBAL_ID
        # self.command: str = command
        # self.description: str = description
        # self.score: str = None
        # self.good_or_bad: str = None
        # self. mitre_attack_classification: str = mitre_attack_classification
        # self.shell: str = shell
