# Raconteur

UCSC Masters Thesis 

Contributors: Cameron Oakley (CJOakley@ucsc.edu)

## Running Raconteur

### Docker Dependency

In order to run the Raconteur application, your host machine will need the Docker engine installed. There are plenty of guides out their for installing the engine - simple one-liner commands for Linux exist, otherwise Docker Desktop for MacOS and Windows will suffice. 

One Caveat, if Docker doesn't start on system boot, ensure that you've opened the program at least once, that way the engine has started.

### Build Docker Environment

These steps work regardless of the operating system you're using, as long as you meet the dependency requirements detailed above.

The commands below build image and run the Docker container. 

```bash
# Ensure your shell is in this project's root directory.
cd *project root*
# Build the image; uses the Dockerfile as a blueprint.
docker build -t raconteur-image .
# Create a container from the new image.
docker run -d -v "$(pwd):/raconteur" --name raconteur-container -it raconteur-image
```

The command below will create a shell with the container and allow you to enter commands.

```bash
# Open shell with container.
docker exec -it raconteur-container /bin/bash
```

The commands below will set the Python virtual environment and install the necessary Python modules.

```bash
# Activate the Python virtual environment.
source /tmp/.venv/bin/activate
# Install necessary modules.
python3 -m pip install pandas pyarrow pyyaml
```