import logging as log 

def configure_project_logging() :
	log.basicConfig(
        datefmt="%Y-%m-%d %H:%M:%S",
        format='%(levelname)s;%(asctime)s;%(message)s', 
        level=log.DEBUG
    )