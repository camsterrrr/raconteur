# Parquet Data

This directory contains a parquet and JSON file of four different datasets: atomic-red-team, lolbas, metta, and ThreatActorProcedures.

Some things worth noting:
- metta dataset was created in 2018 and has the old MITRE ATT&CK technique names. I attempted to match the given technique name with the current technique IDs, in cases where a match didn't occur, I left the "MitreAttackClassification" field empty. 
- Missing data was left with "" rather than "null".
- Each entry should have a command, unique ID, and MITRE AT&CK technique ID. Optional features were the shell language and description, if the dataset had these they were included.

## Individual parquet files

Again, this directory has a single parquet file of all of the datasets I parsed, but you can find individual parquet files in the `separated_parquets` subdirectory.