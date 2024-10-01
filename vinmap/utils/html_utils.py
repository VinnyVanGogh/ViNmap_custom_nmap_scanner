# ./utils./html_utils.py 

import subprocess
from pathlib import Path
from vinmap.core.color_codes import BOLD, LINK, ORANGE, END

def generate_html_report(output_file):
    home = str(Path.home())
    output_file = str(output_file)
    output_rm_path = output_file.split('/')[-1].split('.')[0]
    
    xml_file = output_rm_path + '.xml'
    html_file = output_rm_path + '.html' 
    
    html_dir = str(Path(__file__).parent.parent) + '/scan-results/' + 'html'
    
    xml_path = Path(home + '/NMAP/' + xml_file)
    html_path = Path(html_dir + '/' + html_file)

    html_report = subprocess.run(['xsltproc', xml_path, '-o', html_path])
    
    print(f'{BOLD}HTML Report saved to:{END}\n{LINK}{html_path}{END}')
    return html_file
