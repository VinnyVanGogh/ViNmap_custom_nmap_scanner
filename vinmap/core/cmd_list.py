# ./vinmap/core/cmd_list.py

def nmap_commands():
    nmap_scan_types = {
        "TCP Connect Scan": {
            "option": "-sT",
            "description": "Performs a full TCP connection scan, where a complete handshake is made."
        },
        "SYN Scan": {
            "option": "-sS",
            "description": "Performs a SYN scan (half-open scan), which is faster and stealthier than a TCP Connect scan."
        },
        "UDP Scan": {
            "option": "-sU",
            "description": "Scans for open UDP ports by sending empty UDP packets and awaiting responses."
        },
        "ACK Scan": {
            "option": "-sA",
            "description": "Used to map out firewall rulesets by determining whether ports are filtered."
        },
        "FIN Scan": {
            "option": "-sF",
            "description": "Sends FIN packets to scan for open ports, useful for bypassing some firewalls."
        },
        "Xmas Scan": {
            "option": "-sX",
            "description": "Sends packets with FIN, URG, and PSH flags set to probe for open ports."
        },
        "NULL Scan": {
            "option": "-sN",
            "description": "Sends packets with no flags set to identify open or closed ports."
        },
        "Idle Scan": {
            "option": "-sI",
            "description": "A stealthy scan that uses a third party (zombie host) to send packets and hide the real scanner's identity."
        },
        "Ping Scan": {
            "option": "-sn",
            "description": "Only discovers active hosts without port scanning."
        },
        "Aggressive Scan": {
            "option": "-A",
            "description": "Performs OS detection, version detection, script scanning, and traceroute."
        },
        "Version Detection": {
            "option": "-sV",
            "description": "Attempts to detect the version of services running on open ports."
        },
        "OS Detection": {
            "option": "-O",
            "description": "Tries to determine the operating system of the target."
        },
        "Traceroute": {
            "option": "--traceroute",
            "description": "Performs a traceroute to the target to discover the path taken by packets."
        },
        "List Scan": {
            "option": "-sL",
            "description": "Lists targets without sending any packets to them (host discovery without scanning)."
        },
        "SYN + UDP Scan": {
            "option": "-sS -sU",
            "description": "Combines a SYN scan on TCP ports with a UDP scan to scan both protocols simultaneously."
        },
        "SYN + OS Detection": {
            "option": "-sS -O",
            "description": "Performs a SYN scan to identify open ports and OS detection to identify the target's operating system."
        },
        "SYN + Version Detection": {
            "option": "-sS -sV",
            "description": "Performs a SYN scan to detect open ports and service version detection to identify service versions."
        },
        "SYN + OS + Version Detection + Traceroute": {
            "option": "-sS -O -sV --traceroute",
            "description": "Combines SYN scan, OS detection, version detection, and traceroute for a comprehensive scan."
        },
        "UDP + OS Detection": {
            "option": "-sU -O",
            "description": "Combines a UDP scan with OS detection to gather more information on the target."
        },
        "Aggressive + UDP Scan": {
            "option": "-A -sU",
            "description": "Performs an aggressive scan (OS detection, version detection, script scanning, and traceroute) along with a UDP scan."
        },
        "SYN + UDP + OS + Version Detection": {
            "option": "-sS -sU -O -sV",
            "description": "Performs SYN and UDP scans, OS detection, and version detection for a complete scan of both protocols."
        },
        "Ping + SYN Scan": {
            "option": "-sn -sS",
            "description": "First detects live hosts using a ping scan and then performs a SYN scan on those hosts."
        },
        "TCP SYN + ACK Scan": {
            "option": "-PS -PA",
            "description": "Uses TCP SYN packets to detect live hosts and ACK packets to check for firewall rulesets."
        }
    }
    return nmap_scan_types

