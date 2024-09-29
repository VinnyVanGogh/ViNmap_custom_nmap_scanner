import subprocess
import os
import sys
import ipaddress
import math
import re
import xml.etree.ElementTree as ET
import argparse
import threading
import signal
from xml.dom import minidom
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class ActiveProcesses:
    def __init__(self):
        self.processes = []
        self.lock = threading.Lock()

class ThreadKiller:
    def __init__(self, active_processes, executor):
        self.active_processes = active_processes
        self.executor = executor
        self.shutdown_event = threading.Event()
        signal.signal(signal.SIGINT, self.handle_signal)

    def handle_signal(self, signum, frame):
        print("\nReceived interrupt signal. Shutting down gracefully...")
        self.shutdown_event.set()
        self.terminate_processes()
        self.executor.shutdown(wait=False)
        sys.exit(0)

    def terminate_processes(self):
        print("Terminating active Nmap scans...")
        with self.active_processes.lock:
            for proc in self.active_processes.processes:
                if proc.poll() is None:
                    print(f"Terminating subprocess with PID {proc.pid}")
                    proc.terminate()
            self.active_processes.processes.clear()

def args_setup():
    """
    Sets up command-line argument parsing.
    """
    parser = argparse.ArgumentParser(description="Multithreaded Nmap Scanner with XML Merging")
    parser.add_argument("-ip", "--ip_range", required=True,
                        help="IP range or subnet to scan (e.g., 192.168.1.0/24 or 192.168.1.1-192.168.1.255)")
    parser.add_argument("-n", "--num_chunks", default=2, type=int,
                        help="Number of chunks to split the IP range into (default: 2)")
    parser.add_argument("-s", "--scan_type", type=str,
                        help="Additional scan types/options to run (e.g., '-sV -O')")
    parser.add_argument("-o", "--output", type=str,
                        help="Final output XML file to save merged scan results (default: merged_scan.xml)", default="merged_scan.xml")
    parser.add_argument("-f", "--format", choices=["json", "xml"], default="xml",
                        help="Output format: json or xml (default: xml). Note: Current script focuses on XML.")
    parser.add_argument("-t", "--threads", default=2, type=int,
                        help="Number of concurrent threads (default: 2)")
    return parser.parse_args()

def parse_ip_range(ip_range):
    """
    Parses the IP range into a list of individual IP addresses.
    Supports CIDR notation and dash-separated ranges.
    """
    try:
        if '/' in ip_range:
            # CIDR notation
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        elif '-' in ip_range:
            # Dash-separated range (e.g., 192.168.1.1-192.168.1.255 or 192.168.1.1-255)
            parts = ip_range.split('-')
            if len(parts) == 2:
                start_ip = parts[0]
                end_part = parts[1]
                if '.' in start_ip:
                    base = '.'.join(start_ip.split('.')[:-1]) + '.'
                    print(base)
                    start = int(start_ip.split('.')[-1])
                    print(start)
                    end = int(end_part)
                    print(end)
                    print(f"{base}{i}" for i in range(start, end + 1))
                    return [f"{base}{i}" for i in range(start, end + 1)]
                # if the first and second in a dash-separated range match, make it a single IP
                else:
                    raise ValueError("Invalid IP range format.")
            else:
                raise ValueError("Invalid IP range format.")
        else:
            # Single IP
            ip = ipaddress.ip_address(ip_range)
            print(ip)
            return [str(ip)]
    except Exception as e:
        print(f"Error parsing IP range: {e}")
        sys.exit(1)

def create_chunks(ip_list, num_chunks):
    """
    Splits the list of IPs into the specified number of chunks.
    """
    total_ips = len(ip_list)
    if num_chunks < 1:
        num_chunks = 1
    chunk_size = math.ceil(total_ips / num_chunks)
    chunks = [ip_list[i:i + chunk_size] for i in range(0, total_ips, chunk_size)]
    return chunks

def format_chunk(chunk):
    """
    Formats a chunk of IPs into a comma-separated string for Nmap targeting.
    """
    if not chunk:
        return ""
    # Check if the chunk is contiguous
    contiguous = True
    start = int(ipaddress.IPv4Address(chunk[0]))
    last_ip = str(chunk[-1])
    last_octet = last_ip.split('.')[-1]
    for idx, ip in enumerate(chunk):
        if int(ipaddress.IPv4Address(ip)) != start + idx:
            contiguous = False
            break
    if contiguous:
        return f"{chunk[0]}-{last_octet}"
    else:
        return ",".join(chunk)

def unique_file(base_name, extension):
    """
    Generates a unique filename by appending a timestamp.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base_name}_{timestamp}.{extension}"

def nmap_scan(chunk, output_file, scan_type=None):
    """
    Executes an Nmap scan on the given IP chunk and saves the output to the specified XML file.
    
    Args:
        chunk (str): The target IPs as a comma-separated string or range.
        output_file (str): The filename to save the scan results.
        scan_type (str, optional): Additional Nmap scan options.
    
    Returns:
        tuple: (output_file, interactive_output)
    """
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

def format_nmap_xml(output_file, interactive_output, cmd):
    """
    Parses the generated XML file, appends the interactive output, and formats it nicely.
    """
    current_time = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    comment = f"<!-- Nmap 7.93 scan initiated {current_time} as: {' '.join(cmd)} -->\n"
    try:
        tree = ET.parse(output_file)
        root = tree.getroot()
        output_element = ET.Element('output', type="interactive")
        output_element.text = interactive_output.strip()

        root.append(output_element)

        # Convert the ElementTree to a string
        xml_str = ET.tostring(root, encoding='utf-8')

        # Parse the string with minidom for pretty printing
        parsed_xml = minidom.parseString(xml_str)
        pretty_xml_as_string = parsed_xml.toprettyxml(indent="    ", encoding='iso-8859-1').decode('iso-8859-1')

        # Remove the default XML declaration added by minidom
        if pretty_xml_as_string.startswith('<?xml'):
            pretty_xml_as_string = '\n'.join(pretty_xml_as_string.split('\n')[1:])

        # Remove DOCTYPE and stylesheet if present
        pretty_xml_as_string = re.sub(r'<!DOCTYPE nmaprun>\n', '', pretty_xml_as_string)
        pretty_xml_as_string = re.sub(r'<\?xml-stylesheet href=".*?" type="text/xsl"\?>\n', '', pretty_xml_as_string)

        # Add the comment
        final_xml = (
            '<?xml version="1.0" encoding="iso-8859-1"?>\n' +
            '<!DOCTYPE nmaprun>\n' +
            '<?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n' +
            comment +
            pretty_xml_as_string
        )

        # Write the final XML to the output file
        with open(output_file, 'w', encoding='iso-8859-1') as f:
            f.write(final_xml)

    except ET.ParseError as e:
        print(f"Error parsing the XML file {output_file}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while formatting XML {output_file}: {e}")

def merge_xml_files(xml_files, final_output_file):
    """
    Merges multiple Nmap XML files into a single XML file.
    
    Args:
        xml_files (list): List of XML filenames to merge.
        final_output_file (str): The filename for the merged XML.
    """
    if not xml_files:
        print("No XML files to merge.")
        sys.exit(1)

    # Initialize the final XML structure
    combined_root = ET.Element('nmaprun', {
        'scanner': 'nmap',
        'args': 'Merged Nmap scans',
        'start': str(int(datetime.now().timestamp())),
        'startstr': datetime.now().strftime("%a %b %d %H:%M:%S %Y"),
        'version': '7.93',
        'xmloutputversion': '1.05'
    })

    total_hosts_up = 0
    total_hosts_down = 0
    total_hosts = 0
    combined_output_text = "Merged Interactive Outputs:\n"

    for xml_file in xml_files:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            # Append all <host> elements
            for host in root.findall('host'):
                combined_root.append(host)

            # Sum up runstats
            runstats = root.find('runstats')
            if runstats is not None:
                hosts = runstats.find('hosts')
                if hosts is not None:
                    total_hosts_up += int(hosts.get('up', 0))
                    total_hosts_down += int(hosts.get('down', 0))
                    total_hosts += int(hosts.get('total', 0))

            # Append interactive output
            output_elem = root.find('output')
            if output_elem is not None and output_elem.text:
                combined_output_text += output_elem.text.strip() + "\n\n"

        except ET.ParseError as e:
            print(f"Error parsing XML file {xml_file}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred while merging {xml_file}: {e}")

    # Create runstats for the combined scan
    runstats_combined = ET.SubElement(combined_root, 'runstats')
    finished = ET.SubElement(runstats_combined, 'finished', {
        'time': str(int(datetime.now().timestamp())),
        'timestr': datetime.now().strftime("%a %b %d %H:%M:%S %Y"),
        'summary': f"Merged Nmap scans: {total_hosts} IPs scanned",
        'elapsed': '0',  # Placeholder, could be improved by summing elapsed times if available
        'exit': 'success'
    })
    hosts_elem = ET.SubElement(runstats_combined, 'hosts', {
        'up': str(total_hosts_up),
        'down': str(total_hosts_down),
        'total': str(total_hosts)
    })

    # Create the combined <output> element
    output_element = ET.Element('output', type="interactive")
    output_element.text = combined_output_text.strip()
    combined_root.append(output_element)

    # Convert the combined XML tree to a pretty-printed string
    xml_str = ET.tostring(combined_root, encoding='utf-8')
    parsed_xml = minidom.parseString(xml_str)
    pretty_xml_as_string = parsed_xml.toprettyxml(indent="    ")

    # Remove any XML declarations from the pretty printed string
    if pretty_xml_as_string.startswith('<?xml'):
        pretty_xml_as_string = '\n'.join(pretty_xml_as_string.split('\n')[1:])

    # Remove DOCTYPE and stylesheet if present
    pretty_xml_as_string = re.sub(r'<!DOCTYPE nmaprun>\n', '', pretty_xml_as_string)
    pretty_xml_as_string = re.sub(r'<\?xml-stylesheet href=".*?" type="text/xsl"\?>\n', '', pretty_xml_as_string)

    # Add the comment
    comment = f"<!-- Merged Nmap scans initiated at {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} -->\n"

    # Combine all components into the final XML string
    final_xml = (
        '<?xml version="1.0" encoding="iso-8859-1"?>\n' +
        '<!DOCTYPE nmaprun>\n' +
        '<?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n' +
        comment +
        pretty_xml_as_string
    )

    # Write the final XML to the output file
    with open(final_output_file, 'w', encoding='iso-8859-1') as f:
        f.write(final_xml)

    print(f"Merged XML saved to {final_output_file}")

def main():
    """
    Main function to orchestrate scanning and merging.
    """
    args = args_setup()

    ip_range = args.ip_range
    num_chunks = args.num_chunks
    scan_type = args.scan_type
    output_file = args.output
    num_threads = args.threads

    # Parse IP range
    print(f'parsing ip range: {ip_range}')
    ip_list = parse_ip_range(ip_range)

    if not ip_list:
        print("No IPs to scan.")
        sys.exit(1)

    # Create chunks
    chunks = create_chunks(ip_list, num_chunks)
    formatted_chunks = [format_chunk(chunk) for chunk in chunks]
    print(f"Splitting IP range into {num_chunks} chunks: {formatted_chunks}")

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
                print(f"Scan completed for {chunk}, results saved to {result_file}")
                format_nmap_xml(result_file, interactive_output, ['nmap'] + chunk.split())
            else:
                print(f"Scan failed for {chunk}")
        except Exception as e:
            print(f"An error occurred while scanning {chunk}: {e}")

    # Generate a unique merged XML filename if it already exists
    base_output, ext = os.path.splitext(output_file)
    if os.path.exists(output_file):
        merged_output = unique_file(base_output, ext.lstrip('.'))
        print(f"Warning: {output_file} already exists. Merged results will be saved to {merged_output}.")
    else:
        merged_output = output_file

    merge_xml_files(temp_xml_files, merged_output)

    for temp_file in temp_xml_files:
        os.remove(temp_file)
    print(f"All scans have been merged into {merged_output}")

if __name__ == '__main__':
    main()

