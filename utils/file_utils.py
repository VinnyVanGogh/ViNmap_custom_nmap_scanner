import re
import os

def unique_file(base_name, extension, directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
    file_name = f"{base_name}.{extension}"
    file_path = os.path.join(directory, file_name)
    if not os.path.exists(file_path):
        return file_path
    print(f"File {file_path} already exists. Creating a new file with a unique name.")
    i = 1
    while True:
        file_name = f"{base_name}_{i}.{extension}"
        file_path = os.path.join(directory, file_name)
        print(f"Trying {file_path}")
        if not os.path.exists(file_path):
            print(f"File {file_path} does not exist. Using this file.")
            return file_path
        i += 1
