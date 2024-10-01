# ./utils/scan_utils.py 
import subprocess
import sys
from vinmap.utils.ip_utils import parse_ip_range, create_chunks, format_chunk
from vinmap.core.cli import args_setup
from vinmap.core.color_codes import BOLD, CYAN, ORANGE, LINK, END

def prepare_ip_ranges(ip_range, num_chunks):
    if ',' in ip_range:
        ip_list = ip_range.split(',')
        ip_list = [parse_ip_range(ip) for ip in ip_list]
        ip_list = [ip for sublist in ip_list for ip in sublist]
    else:
        ip_list = parse_ip_range(ip_range)

    if not ip_list:
        print(f"{ORANGE}Invalid IP range. Please provide a valid IP range and try again.{END}")
        sys.exit(1)

    chunks = create_chunks(ip_list, num_chunks)
    formatted_chunks = [format_chunk(chunk) for chunk in chunks]
    return formatted_chunks

def nmap_scan(chunk, output_file, scan_type):

    cmd = [
        'nmap',
        scan_type,
        '-oX', output_file,
        chunk
    ]

    cmd_no_chunk = cmd[:-1]
    chunk_number = chunk.split('_')[-1]
    cmd_no_output = cmd_no_chunk[:-1]

    #TODO: Replace this with a progress bar to show the progress of the scan
    print(f"""{BOLD}Scanning with:{END}
    
        {ORANGE}{' '.join(cmd_no_output)}{END} {LINK}{output_file}{END} {CYAN}{chunk_number}{END}
""")
    
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, check=True)
        interactive_output = process.stdout
        return output_file, interactive_output
    except subprocess.CalledProcessError as e:
        print(f"{ORANGE}An error occurred during Nmap scan for {chunk}:\n{e.stderr}{END}")
        return None, None
    except FileNotFoundError:
        print(f"{ORANGE}Nmap not found. Please install Nmap and try again.{END}")
        sys.exit(1)
