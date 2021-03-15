#
# pynmap-sockets.py

import socket
import re

ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

port_range_pattern = re.compile("([0-9]+)-([0-9]+)")

port_min = 0
port_max = 65535

open_ports = []

while True:
  print("Range of ports to scan: (i.e. 20-443)")
  
  port_range = input("Enter port range: ")
  port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
  if port_range_valid:
    port_min = int(port_range_valid.group(1))
    port_max = int(port_range_valid.group(2))
    break
    
for port in range(port_min, port_max + 1):
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(0.5)
      s.connect((ip_add_entered, port))
      open_ports.append(port)
      
  except:
    pass
  
for port in open_ports:
  print("f"Port {port} is open on {ip_add_entered}.")
        
