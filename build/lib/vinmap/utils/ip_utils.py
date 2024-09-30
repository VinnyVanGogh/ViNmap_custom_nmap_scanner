import ipaddress 
import math 
import sys

def parse_ip_range(ip_range):
    try:
        if '/' in ip_range:
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        elif '-' in ip_range:
            parts = ip_range.split('-')
            if len(parts) == 2:
                start_ip = parts[0]
                end_part = parts[1]
                if '.' in start_ip:
                    base = '.'.join(start_ip.split('.')[:-1]) + '.'
                    start = int(start_ip.split('.')[-1])
                    end = int(end_part)
                    return [f"{base}{i}" for i in range(start, end + 1)]
                else:
                    raise ValueError("Invalid IP range format.")
            else:
                raise ValueError("Invalid IP range format.")
        else:
            ip = ipaddress.ip_address(ip_range)
            return [str(ip)]
    except Exception as e:
        print(f"Error parsing IP range: {e}")
        sys.exit(1)

def create_chunks(ip_list, num_chunks):
    total_ips = len(ip_list)
    if num_chunks < 1:
        num_chunks = 1
    chunk_size = math.ceil(total_ips / num_chunks)
    chunks = [ip_list[i:i + chunk_size] for i in range(0, total_ips, chunk_size)]
    return chunks

def format_chunk(chunk):
    if not chunk:
        return ""
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
