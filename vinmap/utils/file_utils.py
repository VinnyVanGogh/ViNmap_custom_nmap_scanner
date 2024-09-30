import re
import os

def unique_file(base_name, extension, directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
    file_name = f"{base_name}.{extension}"
    file_path = os.path.join(directory, file_name)
    if not os.path.exists(file_path):
        return file_path
    i = 1
    while True:
        file_name = f"{base_name}-{i}.{extension}"
        file_path = os.path.join(directory, file_name)
        if not os.path.exists(file_path):
            return file_path
        i += 1
