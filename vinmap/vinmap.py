# ./vinmap.py
#TODO: Add more JSON support, currently mostly focused on XML
#TODO: Add an echo wrapper for logging and debugging
#TODO: Add a progress bar for the progress of each scan to give the user a better idea of how long the scan will take to complete 
#TODO: Add a gui for the tool to make it more user friendly, and to display the xml output in a more readable format instead of using zenmap

import subprocess
import os
import sys
import threading 
import tempfile
import signal
import socket
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from vinmap.core import ActiveProcesses, ThreadKiller
from vinmap.core.cli import args_setup
from vinmap.utils.xml_utils import format_nmap_xml, merge_xml_files, generate_merged_xml
from vinmap.utils.scan_utils import prepare_ip_ranges, nmap_scan
from vinmap.utils.html_utils import generate_html_report
from vinmap.utils.json_utils import convert_to_json
from vinmap.core.color_codes import BOLD, CYAN, LINK, ORANGE, END

def main():
    args = args_setup()

    ip_range = args.ip_range
    
    domain = re.search(r'([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}', ip_range)

    if domain:
        ip_range = socket.gethostbyname(ip_range)

    num_chunks = args.num_chunks if args.num_chunks else os.cpu_count() // 2
    scan_type = args.scan_type
    if not scan_type:
        scan_type = "-T4 -F"
    output_file = args.output if args.output else f"nmap-{ip_range.replace('/', '-')}-merged.xml"
    num_threads = args.threads if args.threads else os.cpu_count() // 2

    formatted_chunks = prepare_ip_ranges(ip_range, num_chunks)

    temp_xml_files = []
    for idx, chunk in enumerate(formatted_chunks, start=1):
        temp_dir = tempfile.gettempdir()
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
        temp_xml = os.path.join(temp_dir, f"temp_scan_{idx}.xml")
        temp_xml_files.append(temp_xml)

    active_processes = ActiveProcesses()
    executor = ThreadPoolExecutor(max_workers=num_threads)

    killer = ThreadKiller(active_processes, executor, temp_xml_files)

    
    future_to_chunk = {
        executor.submit(nmap_scan, chunk, temp_xml, scan_type): chunk
        for chunk, temp_xml in zip(formatted_chunks, temp_xml_files)
    }


    
    for future in as_completed(future_to_chunk):
        chunk = future_to_chunk[future]
        try:
            result_file, interactive_output = future.result()
            if result_file:
                format_nmap_xml(result_file, interactive_output, ['nmap'] + chunk.split())
            else:
                print(f"Scan failed for {chunk}")
        except Exception as e:
            print(f"An error occurred while scanning {chunk}: {e}")

    final_output_file = generate_merged_xml(output_file, temp_xml_files, scan_type, args.ip_range)

    print(f"{BOLD}Final output saved to:\n{END}{LINK}{final_output_file}{END}")

    if args.format == 'html':

        if str(final_output_file)[-1] == '/':
            final_output_path = str(args.output).split('/')[0:-1]
            html_output_path = final_output_path
            html_file = html_output_path + str(final_output_file).split('/')[-1].split('.')[0] + '.html'
        else:
            cwd = Path.cwd()
            final_output_path = str(cwd)
            html_output_path = final_output_path + '/scan-results/html/'
            html_file = html_output_path + '/html-' + str(final_output_file).split('/')[-1].split('.')[0] + '.html'
        html_path = Path(html_file)
        slash_regex = re.compile(r'/')
        if slash_regex.search(str(args.output)):
            html_output = generate_html_report(final_output_file, args.output)
        else:
            html_output = generate_html_report(final_output_file, html_path)
        print(f"{BOLD}HTML output saved to:\n{END}{LINK}{html_output}{END}")



    if args.format == 'json':
        # check if final output path is a directory or a file
        if str(final_output_file)[-1] == '/':
            final_output_path = str(args.output).split('/')[0:-1]
        else:
            cwd = Path.cwd()
            final_output_path = str(cwd)
        json_output_filename = str(final_output_file).split('/')[-1].split('.')[0] + '.json'
        json_output_file = f"{final_output_path}/json-{json_output_filename}"
        json_path = Path(json_output_file)
        json_output = convert_to_json(final_output_file, json_path)
        print(f"{BOLD}JSON output saved to:\n{END}{LINK}{json_output}{END}")

        

if __name__ == '__main__':
    main()
