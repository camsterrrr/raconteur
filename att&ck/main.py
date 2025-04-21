import logging as log 
import re

BASE_FILE_PATH = "./att&ck/mitre_techniques.csv"

def isolate_technique_names():
    tracked_lines = []
    
    with open(BASE_FILE_PATH, "r", encoding="utf-8") as csv_data:
        for line in csv_data:
            split_list = line.split(",", 2)[:2]
            tracked_lines.append(f"{split_list[0]}, {split_list[1]}\n")
    
    log.debug(tracked_lines)
    with open("./att&ck/mitre_technique_names.csv", "w", encoding="utf-8") as csv_data:
        csv_data.writelines(tracked_lines)

def normalize_techniques():
    modified_lines = []  # Stores all of the lines, so we can write back after.
    
    # Read the data, modifying it as needed.
    with open(BASE_FILE_PATH, "r", encoding="utf-8") as csv_data:
        last_technique = ""
        
        for line in csv_data:
            focus_line = line.split(",", 1)[0]  # Focus on the first cell
            
            tactic_re = r"T[0-9]{4}"
            tactic_pattern = re.compile(tactic_re)
            
            technique_re = r".[0-9]{3}"
            technique_pattern = re.compile(technique_re)
            
            if tactic_pattern.match(focus_line):
                last_technique = focus_line
                log.debug(f"Tactic found: {focus_line}")
            elif technique_pattern.match(focus_line):
                new_focus_line = last_technique + focus_line
                line = line.replace(focus_line, new_focus_line)
                log.debug(f"New technique: {new_focus_line}")
            
            modified_lines.append(line)

    # Now write back all of the data to the same filename
    with open(BASE_FILE_PATH, "w", encoding="utf-8") as csv_data:
        csv_data.writelines(modified_lines)

def main():
    isolate_technique_names()
    # normalize_techniques()

if __name__ == "__main__":
    log.basicConfig(
        datefmt="%Y-%m-%d %H:%M:%S",
        format='%(levelname)s;%(asctime)s;%(message)s', 
        level=log.DEBUG
    )
    main()