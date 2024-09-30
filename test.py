import sys
import re
import socket

ip_address = 'scanme.nmap.org'

domain = re.search(r'([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}', ip_address)

if domain:
    # change to ip address 
    ip_address = socket.gethostbyname(ip_address)

print(ip_address)
