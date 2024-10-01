import os
import sys
import configparser
import toml
import requests

# Function to fetch the current version from PyPI
def get_pypi_version(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return data['info']['version']
    except requests.exceptions.RequestException as e:
        print(f"Error fetching version from PyPI: {e}")
        return None

# Function to check version in setup.cfg
def get_setup_cfg_version():
    config = configparser.ConfigParser()
    config.read('setup.cfg')

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

# Compare the current version in setup.cfg and pyproject.toml with the version on PyPI
def main():
    package_name = "vinmap"  # Change to your package name

    # Get the version from PyPI
    pypi_version = get_pypi_version(package_name)

    # Get local versions from setup.cfg and pyproject.toml
    setup_cfg_version = get_setup_cfg_version()
    pyproject_toml_version = get_pyproject_toml_version()

    # Check version in setup.cfg
    if setup_cfg_version and setup_cfg_version != pypi_version:
        print(f"Version changed in setup.cfg: {pypi_version} -> {setup_cfg_version}")
        sys.exit(0)

    # Check version in pyproject.toml
    if pyproject_toml_version and pyproject_toml_version != pypi_version:
        print(f"Version changed in pyproject.toml: {pypi_version} -> {pyproject_toml_version}")
        sys.exit(0)

    print("No version changes detected.")
    sys.exit(1)

if __name__ == "__main__":
    main()

