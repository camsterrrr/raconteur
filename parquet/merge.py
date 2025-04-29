import pandas as pd
from pathlib import Path


def merge_and_save_parquet(
    input_dir: str,
    output_parquet_path: str,
    output_json_path: str,
    glob_pattern: str = "*.parquet",
) -> None:
    """ """
    input_path = Path(input_dir)
    parquet_files = list(input_path.glob(glob_pattern))

    if not parquet_files:
        return

    # Read and concatenate all parquet files
    dataframes = [pd.read_parquet(f) for f in parquet_files]
    combined_df = pd.concat(dataframes, ignore_index=True)

    combined_df["ID"] = range(1, len(combined_df) + 1)
    # Save as parquet
    combined_df.to_parquet(output_parquet_path, index=False)
    # Save as pretty-formatted JSON
    combined_df.to_json(output_json_path, orient="records", indent=4)


if __name__ == "__main__":
    merge_and_save_parquet(
        input_dir="./parquet/separated_parquets/",
        output_parquet_path="./parquet/bntbd_dataset.parquet",
        output_json_path="./parquet/bntbd_dataset.json",
    )
