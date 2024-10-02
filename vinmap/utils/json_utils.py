import json
import xmltodict
from vinmap.utils.file_utils import format_filepath, unique_file


def convert_to_json(xml_file_path, json_file_path):
    json_file_path = str(json_file_path)
    json_dir, base_output, ext = format_filepath(json_file_path)
    json_output = unique_file(base_output, ext.lstrip('.'), json_dir)

    with open(xml_file_path) as xml_file:
        data_dict = xmltodict.parse(xml_file.read())
        json_data = json.dumps(data_dict, indent=4)

    with open(json_output, 'w') as json_file:
        json_file.write(json_data)

    return json_output
