# ./utils/xml_utils.py 
import re 
import sys 
import os
import xml.etree.ElementTree as ET 
from pathlib import Path 
from utils.file_utils import unique_file
from xml.dom import minidom 
from datetime import datetime 

def format_nmap_xml(output_file, interactive_output, cmd):
    current_time = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    comment = f"<!-- Nmap 7.93 scan initiated {current_time} as: {' '.join(cmd)} -->\n"
    try:
        tree = ET.parse(output_file)
        root = tree.getroot()
        output_element = ET.Element('output', type="interactive")
        output_element.text = interactive_output.strip()

        root.append(output_element)

        xml_str = ET.tostring(root, encoding='utf-8')

        parsed_xml = minidom.parseString(xml_str)
        pretty_xml_as_string = parsed_xml.toprettyxml(indent="    ", encoding='iso-8859-1').decode('iso-8859-1')

        if pretty_xml_as_string.startswith('<?xml'):
            pretty_xml_as_string = '\n'.join(pretty_xml_as_string.split('\n')[1:])

        pretty_xml_as_string = re.sub(r'<!DOCTYPE nmaprun>\n', '', pretty_xml_as_string)
        pretty_xml_as_string = re.sub(r'<\?xml-stylesheet href=".*?" type="text/xsl"\?>\n', '', pretty_xml_as_string)

        final_xml = (
            '<?xml version="1.0" encoding="iso-8859-1"?>\n' +
            '<!DOCTYPE nmaprun>\n' +
            '<?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n' +
            comment +
            pretty_xml_as_string
        )

        with open(output_file, 'w', encoding='iso-8859-1') as f:
            f.write(final_xml)

    except ET.ParseError as e:
        print(f"Error parsing the XML file {output_file}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while formatting XML {output_file}: {e}")

def merge_xml_files(xml_files, final_output_file):
    if not xml_files:
        print("No XML files to merge.")
        sys.exit(1)

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

            for host in root.findall('host'):
                combined_root.append(host)

            runstats = root.find('runstats')
            if runstats is not None:
                hosts = runstats.find('hosts')
                if hosts is not None:
                    total_hosts_up += int(hosts.get('up', 0))
                    total_hosts_down += int(hosts.get('down', 0))
                    total_hosts += int(hosts.get('total', 0))

            output_elem = root.find('output')
            if output_elem is not None and output_elem.text:
                combined_output_text += output_elem.text.strip() + "\n\n"

        except ET.ParseError as e:
            print(f"Error parsing XML file {xml_file}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred while merging {xml_file}: {e}")

    runstats_combined = ET.SubElement(combined_root, 'runstats')
    finished = ET.SubElement(runstats_combined, 'finished', {
        'time': str(int(datetime.now().timestamp())),
        'timestr': datetime.now().strftime("%a %b %d %H:%M:%S %Y"),
        'summary': f"Merged Nmap scans: {total_hosts} IPs scanned",
        'elapsed': '0',
        'exit': 'success'
    })
    hosts_elem = ET.SubElement(runstats_combined, 'hosts', {
        'up': str(total_hosts_up),
        'down': str(total_hosts_down),
        'total': str(total_hosts)
    })

    output_element = ET.Element('output', type="interactive")
    output_element.text = combined_output_text.strip()
    combined_root.append(output_element)

    xml_str = ET.tostring(combined_root, encoding='utf-8')
    parsed_xml = minidom.parseString(xml_str)
    pretty_xml_as_string = parsed_xml.toprettyxml(indent="    ")

    if pretty_xml_as_string.startswith('<?xml'):
        pretty_xml_as_string = '\n'.join(pretty_xml_as_string.split('\n')[1:])

    pretty_xml_as_string = re.sub(r'<!DOCTYPE nmaprun>\n', '', pretty_xml_as_string)
    pretty_xml_as_string = re.sub(r'<\?xml-stylesheet href=".*?" type="text/xsl"\?>\n', '', pretty_xml_as_string)

    comment = f"<!-- Merged Nmap scans initiated at {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} -->\n"

    final_xml = (
        '<?xml version="1.0" encoding="iso-8859-1"?>\n' +
        '<!DOCTYPE nmaprun>\n' +
        '<?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n' +
        comment +
        pretty_xml_as_string
    )

    with open(final_output_file, 'w', encoding='iso-8859-1') as f:
        f.write(final_xml)

    print(f"Merged XML saved to {final_output_file}")

def generate_merged_xml(output_file, temp_xml_files):
    base_output, ext = os.path.splitext(output_file)
    scan_dir = Path(__file__).parent.parent / 'scan_results'
    print(f"Saving merged XML to {scan_dir}")

    if not os.path.exists(scan_dir):
        os.makedirs(scan_dir)

    
    merged_output = unique_file(base_output, ext.lstrip('.'), scan_dir)

    merge_xml_files(temp_xml_files, merged_output)

    for temp_file in temp_xml_files:
        os.remove(temp_file)
    print(f"All scans have been merged into {merged_output}")
