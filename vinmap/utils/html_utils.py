# ./utils./html_utils.py 

import subprocess
from pathlib import Path

def generate_html_report(output_file):
    home = str(Path.home())
    output_file = str(output_file)
    output_rm_path = output_file.split('/')[-1].split('.')[0]
    
    xml_file = output_rm_path + '.xml'
    html_file = output_rm_path + '.html' 
    
    html_dir = str(Path(__file__).parent.parent) + '/scan-results/' + 'html'
    
    xml_path = Path(home + '/NMAP/' + xml_file)
    html_path = Path(html_dir + '/' + html_file)
    
    print('Generating HTML report...', html_file)

    html_report = subprocess.run(['xsltproc', xml_path, '-o', html_path])
    
    print(html_report)
    
    return html_file
