import os
import sys
import configparser
import toml
import subprocess

# Helper to get previous version of a file from git history
def get_previous_version(file_path):
    try:
        # Get the previous version of the file from the last commit
        result = subprocess.run(['git', 'show', f'HEAD:{file_path}'], stdout=subprocess.PIPE, text=True)
        return result.stdout
    except subprocess.CalledProcessError:
        return None

# Function to check version in setup.cfg
def get_setup_cfg_version():
    config = configparser.ConfigParser()
    config.read('setup.cfg')

    if 'metadata' in config and 'version' in config['metadata']:
        return config['metadata']['version']
    return None

# Function to check previous version in setup.cfg using git
def get_previous_setup_cfg_version():
    previous_file_content = get_previous_version('setup.cfg')
    if previous_file_content:
        config = configparser.ConfigParser()
        config.read_string(previous_file_content)
        if 'metadata' in config and 'version' in config['metadata']:
            return config['metadata']['version']
    return None

# Function to check version in pyproject.toml
def get_pyproject_toml_version():
    try:
        with open('pyproject.toml', 'r') as file:
            pyproject_data = toml.load(file)
            return pyproject_data.get('project', {}).get('version')
    except (FileNotFoundError, toml.TomlDecodeError):
        return None

# Function to check previous version in pyproject.toml using git
def get_previous_pyproject_toml_version():
    previous_file_content = get_previous_version('pyproject.toml')
    if previous_file_content:
        try:
            pyproject_data = toml.loads(previous_file_content)
            return pyproject_data.get('project', {}).get('version')
        except toml.TomlDecodeError:
            return None
    return None

# Compare the current and previous versions for both setup.cfg and pyproject.toml
def main():
    # Check current and previous versions in setup.cfg
    setup_cfg_version = get_setup_cfg_version()
    prev_setup_cfg_version = get_previous_setup_cfg_version()

    # Check current and previous versions in pyproject.toml
    pyproject_toml_version = get_pyproject_toml_version()
    prev_pyproject_toml_version = get_previous_pyproject_toml_version()

    # Compare versions for setup.cfg
    if setup_cfg_version and setup_cfg_version != prev_setup_cfg_version:
        print(f"Version changed in setup.cfg: {prev_setup_cfg_version} -> {setup_cfg_version}")
        sys.exit(0)

    # Compare versions for pyproject.toml
    if pyproject_toml_version and pyproject_toml_version != prev_pyproject_toml_version:
        print(f"Version changed in pyproject.toml: {prev_pyproject_toml_version} -> {pyproject_toml_version}")
        sys.exit(0)

    print("No version changes detected.")
    sys.exit(1)

if __name__ == "__main__":
    main()

