# ./core/cli.py

import argparse

def args_setup():
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
