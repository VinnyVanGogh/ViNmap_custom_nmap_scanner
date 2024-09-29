import re
import os

def unique_file(base_name, extension):
    """
    Generate a unique file name by adding a number to the base name.
    """
    i = 1
    print(f"Generating a unique file name for {base_name}.{extension}")
    while True:
        last_counter = i - 1
        print_counter = i
        if i == 1:
            print(f"{base_name} alread exists. Trying {base_name}_{i}.{extension} next.")

        warning = f"{base_name}_{i} already exists. Generating a new file name, trying {base_name}_{print_counter}.{extension} next."

        file_name = f"{base_name}_{i}.{extension}"
        
        if i >= 1:
            first_file_name = f"{base_name}_{last_counter}.{extension}"
            # check if the first file name is _0 if so, remove the _0
            if last_counter == 0:
                first_file_name = f"{base_name}.{extension}"
            print(f"Warning {first_file_name} already exists. Generating a new file name, trying {base_name}_{print_counter}.{extension} next.")

        if not os.path.exists(file_name):
            print(f"File name {file_name} is unique. Creating file.")
            return file_name
        i += 1



