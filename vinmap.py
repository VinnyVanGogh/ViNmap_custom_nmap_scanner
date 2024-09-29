# ./vinmap.py

import subprocess
import os
import sys
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.threading_classes import ActiveProcesses, ThreadKiller
from core.cli import args_setup
from utils.xml_utils import format_nmap_xml, merge_xml_files, generate_merged_xml
from utils.scan_utils import prepare_ip_ranges, nmap_scan

def main():
    args = args_setup()

    ip_range = args.ip_range
    num_chunks = args.num_chunks if args.num_chunks else os.cpu_count() // 2
    scan_type = args.scan_type
    output_file = args.output if args.output else f"nmap_{ip_range.replace('/', '-')}_merged.xml"
    num_threads = args.threads if args.threads else os.cpu_count() // 2

    # Prepare IP ranges by breaking them into chunks to scan in parallel
    formatted_chunks = prepare_ip_ranges(ip_range, num_chunks)

    # Prepare temporary output files
    temp_xml_files = []
    for idx, chunk in enumerate(formatted_chunks, start=1):
        temp_xml = f"temp_scan_{idx}.xml"
        temp_xml_files.append(temp_xml)

    active_processes = ActiveProcesses()
    executor = ThreadPoolExecutor(max_workers=num_threads)

    # Submit scan tasks
    future_to_chunk = {
        executor.submit(nmap_scan, chunk, temp_xml, scan_type): chunk
        for chunk, temp_xml in zip(formatted_chunks, temp_xml_files)
    }

    # Collect results
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

    generate_merged_xml(output_file, temp_xml_files)

if __name__ == '__main__':
    main()


