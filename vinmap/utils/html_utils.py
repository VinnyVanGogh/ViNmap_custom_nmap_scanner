# ./utils./html_utils.py 

import subprocess
from pathlib import Path
from vinmap.core.color_codes import BOLD, LINK, ORANGE, END
from vinmap.utils.file_utils import format_filepath, unique_file

def generate_html_report(xml_file_path, html_file_path):
    xml_file_name = str(xml_file_path).split('/')[-1]

    html_dir, base_output, ext = format_filepath(str(html_file_path))
    
    html_output = unique_file(base_output, 'html', html_dir)
    
    html_filename = str(xml_file_path).split('/')[-1].replace('.xml', '.html')
    
    html_output = Path(html_dir) / Path(html_filename)
    
    html_report = subprocess.run(['xsltproc', xml_file_path, '-o', html_output])

    return html_output
