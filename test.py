from flask import Flask, render_template, request, jsonify, redirect, url_for
import nmap
import socket
import threading
import psutil
import ipaddress

app = Flask(__name__)
# This scanner is for the detailed single-host view
nm = nmap.PortScanner()

# This scanner is for the main async scanning
scanner = nmap.PortScanner()
scan_data = {"status": "idle", "progress": 0, "phase": "Idle", "results": {}, "current_host": ""}
lock = threading.Lock()

# ---------------- Helper Functions ---------------- #
def get_local_network():
    """
    Detects the active private network range (CIDR format, e.g., 192.168.1.0/24)
    based on the default gateway / active interface.
    """
    try:
        # Step 1: Find the local IP actually used for internet access
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # connect to Google DNS
        local_ip = s.getsockname()[0]
        print(local_ip)
        s.close()

        # Step 2: Find the netmask of this IP using psutil
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            for addr in addr_list:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    netmask = addr.netmask
                    ip_interface = ipaddress.IPv4Interface(f"{local_ip}/{netmask}")
                    print(ip_interface.network)
                    return str(ip_interface.network)
                
    except Exception as e:
        print(f"Error detecting local network: {e}")

    # Fallback default
    return "192.168.1.0/24"
print(get_local_network())