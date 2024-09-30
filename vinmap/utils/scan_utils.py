# ./utils/scan_utils.py 
import subprocess
import sys
# from utils.ip_utils import parse_ip_range, create_chunks, format_chunk
from vinmap.utils.ip_utils import parse_ip_range, create_chunks, format_chunk

def prepare_ip_ranges(ip_range, num_chunks):
    if ',' in ip_range:
        ip_list = ip_range.split(',')
        ip_list = [parse_ip_range(ip) for ip in ip_list]
        ip_list = [ip for sublist in ip_list for ip in sublist]
    else:
        ip_list = parse_ip_range(ip_range)

    if not ip_list:
        print("No IPs to scan.")
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
    # make a variable that contains what number of chunk we are scanning 
    chunk_number = chunk.split('_')[-1]
    print(f"Scanning chunk with command: {' '.join(cmd_no_chunk)} {chunk_number}")
    
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, check=True)
        interactive_output = process.stdout
        return output_file, interactive_output
    except subprocess.CalledProcessError as e:
        print(f"An error occurred during Nmap scan for {chunk}:\n{e.stderr}")
        return None, None
    except FileNotFoundError:
        print("Nmap is not installed or not found in PATH.")
        sys.exit(1)
