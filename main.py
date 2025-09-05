from flask import Flask, render_template, request, jsonify
import nmap
import socket
import threading
import psutil
import ipaddress
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import re
import platform

app = Flask(__name__)
# This scanner is for the detailed single-host view
nm = nmap.PortScanner()

# This scanner is for the main async scanning
scanner = nmap.PortScanner()
scan_data = {"status": "idle", "progress": 0, "phase": "Idle", "results": {}, "current_host": "", "scanned_hosts": 0, "total_hosts": 0}
lock = threading.Lock()

# Detailed scan progress tracking
detailed_scan_progress = {}
detailed_lock = threading.Lock()

# Network graph data
network_graph = {"nodes": [], "edges": []}
graph_lock = threading.Lock()

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
        s.close()

        # Step 2: Find the netmask of this IP using psutil
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            for addr in addr_list:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    netmask = addr.netmask
                    ip_interface = ipaddress.IPv4Interface(f"{local_ip}/{netmask}")
                    return str(ip_interface.network)

    except Exception as e:
        print(f"Error detecting local network: {e}")

    # Fallback default
    return "192.168.1.0/24"

def get_default_gateway():
    """Get the default gateway IP address using cross-platform methods"""
    try:
        # Try different methods based on the platform
        if platform.system() == "Windows":
            # For Windows
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Default Gateway' in line:
                    ip = re.search(r'[0-9]+(?:\.[0-9]+){3}', line)
                    if ip:
                        return ip.group(0)
        else:
            # For Linux and macOS
            # Method 1: Using 'ip route'
            try:
                result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'default via' in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                return parts[2]
            except:
                pass
            
            # Method 2: Using 'netstat'
            try:
                result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'default' in line or '0.0.0.0' in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                # Try to find an IP address in the line
                                ip = re.search(r'[0-9]+(?:\.[0-9]+){3}', line)
                                if ip:
                                    return ip.group(0)
            except:
                pass
    
    except Exception as e:
        print(f"Error getting default gateway: {e}")
    
    # Final fallback - try to guess based on local IP
    try:
        # Get local IP using the same method as get_local_network
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        parts = local_ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    except:
        return "192.168.1.1"

def detect_device_type(os_info):
    """Detect device type based on OS information"""
    if not os_info:
        return "unknown"
    
    os_str = str(os_info).lower()
    
    if any(x in os_str for x in ['router', 'mikrotik', 'cisco', 'netgear', 'tp-link', 'd-link']):
        return "router"
    elif any(x in os_str for x in ['windows', 'microsoft']):
        return "windows"
    elif any(x in os_str for x in ['linux', 'ubuntu', 'debian', 'centos', 'fedora']):
        return "linux"
    elif any(x in os_str for x in ['android']):
        return "android"
    elif any(x in os_str for x in ['apple', 'macos', 'ios']):
        return "apple"
    elif any(x in os_str for x in ['printer', 'hp', 'canon', 'epson']):
        return "printer"
    elif any(x in os_str for x in ['camera', ' surveillance']):
        return "camera"
    else:
        return "unknown"

def get_device_icon(device_type):
    """Get icon class based on device type"""
    icons = {
        "router": "bi-router",
        "windows": "bi-microsoft",
        "linux": "bi-ubuntu",
        "android": "bi-android2",
        "apple": "bi-apple",
        "printer": "bi-printer",
        "camera": "bi-camera-video",
        "unknown": "bi-pc"
    }
    return icons.get(device_type, "bi-pc")

def scan_single_host(host):
    """Scan a single host and return the result"""
    try:
        scanner.scan(hosts=host, arguments="-sn")
        return host, True
    except:
        return host, False

def reset_scan_data():
    """Reset the scan data to initial state"""
    global scan_data
    with lock:
        scan_data = {"status": "idle", "progress": 0, "phase": "Idle", "results": {}, "current_host": "", "scanned_hosts": 0, "total_hosts": 0}

def run_scan(target, phase):
    global scan_data

    # Reset scan data at the beginning
    reset_scan_data()
    
    with lock:
        scan_data["status"] = "running"
        scan_data["phase"] = phase

    try:
        if phase == "Discovery":
            with lock:
                scan_data["current_host"] = f"Enumerating hosts in range: {target}"
            
            # Get the list of all IPs in the target range
            try:
                network = ipaddress.ip_network(target, strict=False)
                all_hosts = [str(ip) for ip in network.hosts()]
            except:
                # If it's a single host or invalid range, handle it
                all_hosts = [target]
            
            with lock:
                scan_data["total_hosts"] = len(all_hosts)
            
            # If no hosts to scan, set progress to 100% immediately
            if len(all_hosts) == 0:
                with lock:
                    scan_data["progress"] = 100
                    scan_data["status"] = "done"
                return
            
            # Scan hosts in parallel with a thread pool
            discovered_hosts = []
            with ThreadPoolExecutor(max_workers=10) as executor:
                # Submit all the scanning tasks
                future_to_host = {executor.submit(scan_single_host, host): host for host in all_hosts}
                
                # Process results as they complete
                for i, future in enumerate(as_completed(future_to_host)):
                    host = future_to_host[future]
                    try:
                        scanned_host, is_up = future.result()
                        if is_up and scanned_host in scanner.all_hosts():
                            discovered_hosts.append(scanned_host)
                    except Exception as e:
                        print(f"Error scanning {host}: {e}")
                    
                    # Update progress - ensure we don't exceed 100%
                    progress = min(100, int((i + 1) / len(all_hosts) * 100))
                    with lock:
                        scan_data["scanned_hosts"] = i + 1
                        scan_data["progress"] = progress
                        scan_data["current_host"] = f"Scanning: {host}"

            # Ensure progress reaches 100% at the end
            with lock:
                scan_data["results"]["hosts"] = discovered_hosts
                scan_data["progress"] = 100
                scan_data["current_host"] = "Discovery complete"

    except Exception as e:
        with lock:
            scan_data["status"] = f"error: {e}"

    with lock:
        scan_data["status"] = "done"
        scan_data["current_host"] = ""

def build_network_graph(hosts):
    """Build a network graph from discovered hosts"""
    global network_graph
    
    try:
        with graph_lock:
            network_graph = {"nodes": [], "edges": []}
            
            # Add gateway node
            gateway = get_default_gateway()
            network_graph["nodes"].append({
                "id": gateway,
                "label": "Gateway",
                "title": f"Default Gateway: {gateway}",
                "group": "router",
                "icon": get_device_icon("router")
            })
            
            # Add discovered hosts (ensure they're not the gateway)
            for host in hosts:
                if host == gateway:
                    continue  # Skip if host is the gateway
                    
                # Try to detect device type with a quick scan
                device_type = "unknown"
                try:
                    quick_scanner = nmap.PortScanner()
                    quick_scanner.scan(hosts=host, arguments="-O --osscan-limit")
                    if host in quick_scanner.all_hosts():
                        os_info = quick_scanner[host].get('osmatch', [{}])[0].get('name', '') if quick_scanner[host].get('osmatch') else ''
                        device_type = detect_device_type(os_info)
                except:
                    pass
                    
                network_graph["nodes"].append({
                    "id": host,
                    "label": host,
                    "title": f"IP: {host}\nType: {device_type}",
                    "group": device_type,
                    "icon": get_device_icon(device_type)
                })
                
                # Add connection to gateway
                network_graph["edges"].append({
                    "from": gateway,
                    "to": host,
                    "label": "connected"
                })
    except Exception as e:
        print(f"Error building network graph: {e}")
        # Create a basic graph as fallback
        with graph_lock:
            network_graph = {"nodes": [], "edges": []}
            gateway = get_default_gateway()
            network_graph["nodes"].append({
                "id": gateway,
                "label": "Gateway",
                "title": f"Default Gateway: {gateway}",
                "group": "router",
                "icon": get_device_icon("router")
            })
            
            for host in hosts:
                if host != gateway:
                    network_graph["nodes"].append({
                        "id": host,
                        "label": host,
                        "title": f"IP: {host}\nType: unknown",
                        "group": "unknown",
                        "icon": get_device_icon("unknown")
                    })
                    
                    network_graph["edges"].append({
                        "from": gateway,
                        "to": host,
                        "label": "connected"
                    })


# ---------------- Routes ---------------- #
@app.route("/")
def index():
    return render_template("index.html")
    
@app.route("/visual")
def visual():
    return render_template("visual.html")

@app.route("/scan_host/<ip>")
def scan_host(ip):
    # This route just renders the template with a button to start the scan
    return render_template("host.html", ip=ip)

@app.route("/api/detailed_scan/<ip>")
def detailed_scan(ip):
    try:
        # Update progress
        with detailed_lock:
            detailed_scan_progress[ip] = {"phase": "Initializing", "progress": 5}
        
        # Create a new scanner instance for this detailed scan
        detailed_scanner = nmap.PortScanner()
        
        # Update progress
        with detailed_lock:
            detailed_scan_progress[ip] = {"phase": "Ping Check", "progress": 10}
        
        # Perform a comprehensive scan
        detailed_scanner.scan(ip, arguments="-sV -O --script=default")
        
        # Update progress
        with detailed_lock:
            detailed_scan_progress[ip] = {"phase": "Complete", "progress": 100}
        
        if ip not in detailed_scanner.all_hosts():
            return jsonify({"status": "error", "message": "Host not found or not reachable"})
        
        # Get the scan results
        details = detailed_scanner[ip]
        
        # Convert the details to a JSON-serializable format
        result = {
            "state": details.state(),
            "hostnames": details.hostnames(),
            "osmatch": details.get('osmatch', []),
            "tcp": details.get('tcp', {})
        }
        
        return jsonify({"status": "success", "details": result})
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/api/detailed_progress/<ip>")
def detailed_progress(ip):
    with detailed_lock:
        progress = detailed_scan_progress.get(ip, {"phase": "Not started", "progress": 0})
    return jsonify(progress)

@app.route("/api/localrange")
def localrange():
    return jsonify({"range": get_local_network()})

@app.route("/api/gateway")
def gateway():
    return jsonify({"gateway": get_default_gateway()})

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = data.get("target")
    phase = data.get("phase", "Discovery")
    threading.Thread(target=run_scan, args=(target, phase), daemon=True).start()
    return jsonify({"status": "started", "phase": phase})

@app.route("/api/visual_scan", methods=["POST"])
def visual_scan():
    data = request.get_json()
    target = data.get("target")
    phase = data.get("phase", "Discovery")
    
    # Start the scan in a thread
    def visual_scan_task():
        run_scan(target, phase)
        # After scan completes, build the network graph
        with lock:
            if "hosts" in scan_data["results"]:
                build_network_graph(scan_data["results"]["hosts"])
    
    threading.Thread(target=visual_scan_task, daemon=True).start()
    return jsonify({"status": "started", "phase": phase})

@app.route("/api/network_graph")
def get_network_graph():
    with graph_lock:
        return jsonify(network_graph)

@app.route("/api/reset_scan", methods=["POST"])
def api_reset_scan():
    reset_scan_data()
    return jsonify({"status": "reset"})

@app.route("/api/status")
def status():
    with lock:
        return jsonify(scan_data)


# ---------------- Run ---------------- #
if __name__ == "__main__":
    app.run(debug=True)