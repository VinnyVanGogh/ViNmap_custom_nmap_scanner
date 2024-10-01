# ./utils./html_utils.py 

import subprocess

def generate_html_report(output_file):
    no_ext = output_file.split('.')[0]
    html_file = no_ext + '.html'
    print('Generating HTML report...', html_file)
    html_report = subprocess.run(['xsltproc', output_file, '-o', html_file])
    print(html_report)
    return html_file
