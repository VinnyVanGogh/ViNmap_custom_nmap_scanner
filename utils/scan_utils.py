# ./utils/scan_utils.py 
import subprocess
import sys
from utils.ip_utils import parse_ip_range, create_chunks, format_chunk

def prepare_ip_ranges(ip_range, num_chunks):
    print(f'parsing ip range: {ip_range}')
    ip_list = parse_ip_range(ip_range)

    if not ip_list:
        print("No IPs to scan.")
        sys.exit(1)

    # Create chunks
    chunks = create_chunks(ip_list, num_chunks)
    formatted_chunks = [format_chunk(chunk) for chunk in chunks]
    print(f"Splitting IP range into {num_chunks} chunks: {formatted_chunks}")
    return formatted_chunks

def nmap_scan(chunk, output_file, scan_type=None):
    print(f"Scanning chunk: {chunk}")
    cmd = [
        'nmap',
        '-T4',
        '-F',
        '-oX', output_file,
        chunk
    ]

    if scan_type:
        # Split the scan_type string into a list of arguments
        cmd += scan_type.split()

    print(f"Running command: {' '.join(cmd)}")

    try:
        # Run the scan
        process = subprocess.run(cmd, capture_output=True, text=True, check=True)
        interactive_output = process.stdout
        return output_file, interactive_output
    except subprocess.CalledProcessError as e:
        print(f"An error occurred during Nmap scan for {chunk}:\n{e.stderr}")
        return None, None
    except FileNotFoundError:
        print("Nmap is not installed or not found in PATH.")
        sys.exit(1)

