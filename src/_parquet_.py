import logging as log
from json import dumps
from pandas import DataFrame as df
from pathlib import Path

log.getLogger(__name__)  # Set same logging parameters across contexts

COLUMNS = ["ID", "Command", "Description", "Score", "GoodOrBad", "MitreAttackClassification", "Shell"]
GLOBAL_ID = 0
OUTPUT_DIR = "./parquet/"


class parquet_dataset():
    
    def __init__(
        self,
        parquet_entries: dict
    ):
        self.parquet_entries: dict = parquet_entries
    
    def write_parquet_file(
        self,
        file_name: str
    ):
        output_path = Path(f"{OUTPUT_DIR}/{file_name}.parquet")
        
        try:
            log.debug(dumps(self.parquet_entries, indent=4))
            df_obj = df(self.parquet_entries)
            df_obj.to_parquet(
                output_path,
                compression="gzip",
                partition_cols=COLUMNS
            )
        except Exception as e:
            log.error(f"{e}")


class parquet_entry():
    
    def __init__(
        self,
        command: str,
        description: str,
        mitre_attack_classification: str,
        shell: str
    ):
        global GLOBAL_ID
        GLOBAL_ID += 1
        
        # "ID", "Command", "Description", "Score", "GoodOrBad", "MitreAttackClassification"
        self.parquet_dict = {
            "ID": GLOBAL_ID,
            "Command": command,
            "Description": description,
            "Score": None,
            "GoodOrBad": None,
            "MitreAttackClassification": mitre_attack_classification,
            "Shell": shell
        }
        
        # self.id: int = GLOBAL_ID
        # self.command: str = command
        # self.description: str = description
        # self.score: str = None
        # self.good_or_bad: str = None
        # self. mitre_attack_classification: str = mitre_attack_classification
        # self.shell: str = shell

