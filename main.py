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
import mysql.connector
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- Database Configuration ---
DB_CONFIG = {
    'host': 'localhost',
    'user': 'network_mapper',
    'password': 'password123',
    'database': 'network_scanner'
}

def get_db_connection():
    """Create and return database connection"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as e:
        logger.error(f"Database connection error: {e}")
        # Try to create database if it doesn't exist
        if e.errno == 1049:  # Database doesn't exist
            try:
                # Connect without database specified
                temp_config = DB_CONFIG.copy()
                temp_config.pop('database')
                temp_conn = mysql.connector.connect(**temp_config)
                cursor = temp_conn.cursor()
                cursor.execute(f"CREATE DATABASE {DB_CONFIG['database']}")
                cursor.close()
                temp_conn.close()
                logger.info(f"Created database {DB_CONFIG['database']}")
                # Now connect with database
                return mysql.connector.connect(**DB_CONFIG)
            except Exception as create_error:
                logger.error(f"Failed to create database: {create_error}")
        return None

def init_database():
    """Initialize database tables"""
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            
            # Create scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    target_range VARCHAR(255) NOT NULL,
                    scan_type ENUM('discovery', 'visual', 'detailed') NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    hosts_found INT DEFAULT 0,
                    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    end_time DATETIME NULL,
                    duration_seconds INT DEFAULT 0,
                    saved_result BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # Create hosts table with device_type for visual mapping
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hosts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    scan_id INT,
                    ip_address VARCHAR(45) NOT NULL,
                    hostname VARCHAR(255),
                    mac_address VARCHAR(17),
                    vendor VARCHAR(255),
                    os_info TEXT,
                    status ENUM('up', 'down', 'unknown') DEFAULT 'unknown',
                    device_type VARCHAR(50),
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                    INDEX idx_ip (ip_address),
                    INDEX idx_scan (scan_id)
                )
            ''')
            
            # Create ports table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ports (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    host_id INT,
                    port_number INT NOT NULL,
                    protocol VARCHAR(10) DEFAULT 'tcp',
                    state VARCHAR(20),
                    service_name VARCHAR(100),
                    service_version TEXT,
                    banner TEXT,
                    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
                    INDEX idx_host (host_id),
                    INDEX idx_port (port_number)
                )
            ''')
            
            conn.commit()
            logger.info("Database tables initialized successfully")
            
        except mysql.connector.Error as e:
            logger.error(f"Database initialization error: {e}")
        finally:
            cursor.close()
            conn.close()

# Initialize database on startup
init_database()

# --- Global State Management ---
scan_data = {}
scan_lock = threading.Lock()

detailed_scans = {}
detailed_lock = threading.Lock()

network_graph = {"nodes": [], "edges": []}
graph_lock = threading.Lock()

current_scan_id = None  # Track current scan ID for saving

def reset_scan_data():
    global scan_data, current_scan_id
    with scan_lock:
        scan_data.update({
            "status": "idle", "progress": 0, "phase": "Idle", "results": {},
            "current_host": "", "scanned_hosts": 0, "total_hosts": 0
        })
        current_scan_id = None

reset_scan_data()

# --- Database Operations ---
def save_scan_session(target_range, scan_type, status, hosts_found=0, duration=0):
    """Save scan session to database and return scan_id"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scans (target_range, scan_type, status, hosts_found, duration_seconds)
            VALUES (%s, %s, %s, %s, %s)
        ''', (target_range, scan_type, status, hosts_found, duration))
        
        scan_id = cursor.lastrowid
        conn.commit()
        logger.info(f"Saved scan session {scan_id} for target {target_range}")
        return scan_id
    except mysql.connector.Error as e:
        logger.error(f"Error saving scan session: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def mark_scan_as_saved(scan_id):
    """Mark a scan as saved in database"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE scans SET saved_result = TRUE WHERE id = %s
        ''', (scan_id,))
        conn.commit()
        return True
    except mysql.connector.Error as e:
        logger.error(f"Error marking scan as saved: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def update_scan_session(scan_id, status, hosts_found=None, duration=None):
    """Update scan session status"""
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        cursor = conn.cursor()
        if hosts_found is not None and duration is not None:
            cursor.execute('''
                UPDATE scans SET status=%s, hosts_found=%s, duration_seconds=%s, end_time=NOW()
                WHERE id=%s
            ''', (status, hosts_found, duration, scan_id))
        else:
            cursor.execute('''
                UPDATE scans SET status=%s WHERE id=%s
            ''', (status, scan_id))
        
        conn.commit()
    except mysql.connector.Error as e:
        logger.error(f"Error updating scan session: {e}")
    finally:
        cursor.close()
        conn.close()

def save_host_discovery(scan_id, hosts_list):
    """Save discovered hosts to database"""
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        cursor = conn.cursor()
        for host in hosts_list:
            cursor.execute('''
                INSERT INTO hosts (scan_id, ip_address, status, last_seen)
                VALUES (%s, %s, 'up', NOW())
            ''', (scan_id, host))
        
        conn.commit()
        logger.info(f"Saved {len(hosts_list)} hosts for scan {scan_id}")
    except mysql.connector.Error as e:
        logger.error(f"Error saving hosts: {e}")
    finally:
        cursor.close()
        conn.close()

def save_host_with_device_type(scan_id, ip_address, device_type):
    """Save or update host with device type information"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE hosts SET device_type = %s 
            WHERE scan_id = %s AND ip_address = %s
        ''', (device_type, scan_id, ip_address))
        
        conn.commit()
        return True
    except mysql.connector.Error as e:
        logger.error(f"Error saving host device type: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def get_saved_scans(scan_type=None):
    """Get all saved scans from database"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        if scan_type:
            cursor.execute('''
                SELECT id, target_range, scan_type, status, hosts_found, 
                       start_time, end_time, duration_seconds
                FROM scans 
                WHERE saved_result = TRUE AND scan_type = %s
                ORDER BY start_time DESC
            ''', (scan_type,))
        else:
            cursor.execute('''
                SELECT id, target_range, scan_type, status, hosts_found, 
                       start_time, end_time, duration_seconds
                FROM scans 
                WHERE saved_result = TRUE
                ORDER BY start_time DESC
            ''')
        
        return cursor.fetchall()
    except mysql.connector.Error as e:
        logger.error(f"Error retrieving saved scans: {e}")
        return []
    finally:
        cursor.close()
        conn.close()

def get_scan_details(scan_id):
    """Get detailed scan information including hosts"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get scan basic info
        cursor.execute('''
            SELECT * FROM scans WHERE id = %s
        ''', (scan_id,))
        scan_info = cursor.fetchone()
        
        if not scan_info:
            return None
        
        # Get hosts for this scan with device types
        cursor.execute('''
            SELECT * FROM hosts WHERE scan_id = %s
        ''', (scan_id,))
        hosts = cursor.fetchall()
        
        scan_info['hosts'] = hosts
        
        return scan_info
    except mysql.connector.Error as e:
        logger.error(f"Error retrieving scan details: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def delete_scan(scan_id):
    """Delete a scan and all associated data"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # Delete scan (cascade will delete hosts and ports)
        cursor.execute('DELETE FROM scans WHERE id = %s', (scan_id,))
        
        conn.commit()
        logger.info(f"Deleted scan {scan_id} from database")
        return True
    except mysql.connector.Error as e:
        logger.error(f"Error deleting scan: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

# --- Core Nmap Executor with Timeout ---
def run_nmap_with_timeout(hosts, arguments, timeout=120):
    """Executes Nmap as a subprocess with a strict timeout."""
    try:
        command = ['nmap', '-oX', '-'] + arguments.split() + hosts.split()
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
        if "command not found" in proc.stderr.lower() or "not recognized" in proc.stderr.lower():
            return "NOT_FOUND"
        if proc.returncode != 0 and not proc.stdout:
            print(f"Nmap error for host {hosts} with args '{arguments}': {proc.stderr}")
            return "ERROR"
        
        scanner = nmap.PortScanner()
        scanner.analyse_nmap_xml_scan(proc.stdout)
        return scanner
    except subprocess.TimeoutExpired:
        print(f"Nmap scan timed out for host {hosts} with args '{arguments}'")
        return "TIMEOUT"
    except Exception as e:
        print(f"An unexpected error occurred in run_nmap_with_timeout: {e}")
        return "ERROR"

# --- Helper & Utility Functions ---
def get_local_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        for iface, addr_list in psutil.net_if_addrs().items():
            for addr in addr_list:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    netmask = addr.netmask
                    ip_interface = ipaddress.IPv4Interface(f"{local_ip}/{netmask}")
                    return str(ip_interface.network)
    except Exception:
        return "192.168.1.0/24"

def get_default_gateway():
    try:
        if platform.system() == "Windows":
            result = subprocess.check_output("ipconfig").decode()
            match = re.search(r"Default Gateway.*: ([\d.]+)", result)
            if match:
                return match.group(1)
        else:
            result = subprocess.check_output(["ip", "route"]).decode()
            match = re.search(r"default via ([\d.]+)", result)
            if match:
                return match.group(1)
    except Exception:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        except:
            return "192.168.1.1"

def detect_device_type(os_info):
    if not os_info:
        return "unknown"
    
    os_str = str(os_info).lower()
    
    if any(x in os_str for x in ['router', 'gateway', 'cisco', 'juniper', 'mikrotik']):
        return "router"
    elif 'windows' in os_str:
        return "windows"
    elif 'linux' in os_str:
        return "linux"
    elif 'android' in os_str:
        return "android"
    elif any(x in os_str for x in ['apple', 'macos', 'ios']):
        return "apple"
    elif any(x in os_str for x in ['printer', 'epson', 'canon', 'hp']):
        return "printer"
    elif 'camera' in os_str:
        return "camera"
    else:
        return "unknown"

def get_device_icon(device_type):
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

def scan_single_host_fast(host):
    """Fast single host scan with optimized settings"""
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=host, arguments="-sn -T4 --max-retries 1 --host-timeout 5s")
        return host, host in scanner.all_hosts()
    except nmap.PortScannerError:
        raise  # Propagate the error to be handled by the caller
    except Exception:
        return host, False

# --- Background Scan Logic ---
def perform_discovery_scan(target):
    """Worker for initial host discovery with database saving"""
    global current_scan_id
    reset_scan_data()
    scan_start_time = time.time()
    current_scan_id = save_scan_session(target, 'discovery', 'running')
    
    with scan_lock:
        scan_data.update({
            "status": "running", 
            "phase": "Host Discovery", 
            "scan_id": current_scan_id,
            "progress": 0
        })
    
    try:
        network = ipaddress.ip_network(target, strict=False)
        all_hosts = [str(ip) for ip in network.hosts()]
        # Limit scan size for performance
        if len(all_hosts) > 254:
            all_hosts = all_hosts[:254]
            
        with scan_lock:
            scan_data["total_hosts"] = len(all_hosts)
        
        if not all_hosts:
            with scan_lock:
                scan_data["status"] = "done"
                scan_data["progress"] = 100
            if current_scan_id:
                update_scan_session(current_scan_id, 'completed', 0, int(time.time() - scan_start_time))
            return

        discovered_hosts = []
        
        # Reduced max_workers to prevent system overload and improve stability
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_host = {executor.submit(scan_single_host_fast, host): host for host in all_hosts}
            
            for i, future in enumerate(as_completed(future_to_host)):
                host = future_to_host[future]
                try:
                    scanned_host, is_up = future.result()
                    if is_up:
                        discovered_hosts.append(scanned_host)
                except nmap.PortScannerError:
                    with scan_lock:
                        scan_data["status"] = "error: 'nmap' is not installed. Please install it from https://nmap.org"
                    if current_scan_id:
                        update_scan_session(current_scan_id, 'error: nmap not found')
                    # Cancel remaining tasks
                    executor.shutdown(wait=False, cancel_futures=True)
                    return
                except Exception as e:
                    print(f"Error scanning {host}: {e}")
                
                # Update progress with smooth increments
                progress = min(100, int(((i + 1) / len(all_hosts)) * 100))
                with scan_lock:
                    scan_data["scanned_hosts"] = i + 1
                    scan_data["progress"] = progress
                    scan_data["current_host"] = f"Scanning: {host}"

        # Save discovered hosts to database
        if current_scan_id:
            save_host_discovery(current_scan_id, discovered_hosts)
            duration = int(time.time() - scan_start_time)
            update_scan_session(current_scan_id, 'completed', len(discovered_hosts), duration)

        with scan_lock:
            scan_data["results"]["hosts"] = discovered_hosts
            scan_data["progress"] = 100
            scan_data["current_host"] = f"Found {len(discovered_hosts)} hosts"

    except Exception as e:
        with scan_lock: 
            scan_data["status"] = f"error: {e}"
            scan_data["progress"] = 0
        if current_scan_id:
            update_scan_session(current_scan_id, f'error: {e}')
    finally:
        with scan_lock:
            scan_data["status"] = "done"

def perform_visual_scan(target):
    """Worker for the visual scan process - saves device types for graph recreation"""
    global current_scan_id
    scan_start_time = time.time()
    current_scan_id = save_scan_session(target, 'visual', 'running')
    
    # Reset the scan data first
    reset_scan_data()
    
    with scan_lock:
        scan_data.update({
            "status": "running", 
            "phase": "Discovery",
            "scan_id": current_scan_id,
            "progress": 0
        })

    try:
        # Get the list of all IPs in the target range
        try:
            network = ipaddress.ip_network(target, strict=False)
            all_hosts = [str(ip) for ip in network.hosts()]
            # Limit scan size for performance
            if len(all_hosts) > 254:
                all_hosts = all_hosts[:254]
        except:
            # If it's a single host or invalid range, handle it
            all_hosts = [target]
        
        with scan_lock:
            scan_data["total_hosts"] = len(all_hosts)
        
        # If no hosts to scan, set progress to 100% immediately
        if len(all_hosts) == 0:
            with scan_lock:
                scan_data["progress"] = 100
                scan_data["status"] = "done"
            return
        
        # Initialize graph with gateway
        gateway = get_default_gateway()
        with graph_lock:
            network_graph.update({"nodes": [], "edges": []})
            network_graph["nodes"].append({
                "id": gateway,
                "label": "Gateway",
                "title": f"Default Gateway: {gateway}",
                "group": "router",
                "icon": get_device_icon("router")
            })
        
        # Save discovered hosts first
        discovered_hosts = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            # Submit all the scanning tasks
            future_to_host = {executor.submit(scan_single_host_fast, host): host for host in all_hosts}
            
            # Process results as they complete
            for i, future in enumerate(as_completed(future_to_host)):
                host = future_to_host[future]
                try:
                    scanned_host, is_up = future.result()
                    if is_up and scanned_host not in discovered_hosts:
                        discovered_hosts.append(scanned_host)
                        
                        # Save host to database
                        if current_scan_id:
                            save_host_discovery(current_scan_id, [scanned_host])
                        
                        # Add to graph in real-time (only if not gateway)
                        if scanned_host != gateway:
                            device_type = "unknown"
                            # This also uses nmap, so it's wrapped in the same try-except
                            quick_scanner = nmap.PortScanner()
                            quick_scanner.scan(hosts=scanned_host, arguments="-T4 -F --max-retries 1 --host-timeout 10s")
                            if scanned_host in quick_scanner.all_hosts():
                                os_match = quick_scanner[scanned_host].get('osmatch', [])
                                if os_match:
                                    device_type = detect_device_type(os_match[0].get('name'))

                                # Save device type to database for graph recreation
                                save_host_with_device_type(current_scan_id, scanned_host, device_type)
                            
                            with graph_lock:
                                network_graph["nodes"].append({
                                    "id": scanned_host,
                                    "label": scanned_host,
                                    "title": f"IP: {scanned_host}\nType: {device_type}",
                                    "group": device_type,
                                    "icon": get_device_icon(device_type)
                                })
                                
                                network_graph["edges"].append({
                                    "from": gateway,
                                    "to": scanned_host,
                                    "label": "connected"
                                })
                except nmap.PortScannerError:
                    with scan_lock:
                        scan_data["status"] = "error: 'nmap' is not installed. Please install it from https://nmap.org"
                    if current_scan_id:
                        update_scan_session(current_scan_id, 'error: nmap not found')
                    # Cancel remaining tasks
                    executor.shutdown(wait=False, cancel_futures=True)
                    return
                except Exception as e:
                    print(f"Error scanning {host}: {e}")
                
                # Update progress - ensure we don't exceed 100%
                progress = min(100, int((i + 1) / len(all_hosts) * 100))
                with scan_lock:
                    scan_data["scanned_hosts"] = i + 1
                    scan_data["progress"] = progress
                    scan_data["current_host"] = f"Scanning: {host}"

        # Ensure progress reaches 100% at the end
        with scan_lock:
            scan_data["results"]["hosts"] = discovered_hosts
            scan_data["progress"] = 100
            scan_data["current_host"] = f"Found {len(discovered_hosts)} hosts"

        # Update scan completion in database
        if current_scan_id:
            duration = int(time.time() - scan_start_time)
            update_scan_session(current_scan_id, 'completed', len(discovered_hosts), duration)

    except Exception as e:
        with scan_lock:
            scan_data["status"] = f"error: {e}"
            scan_data["progress"] = 0
        if current_scan_id:
            update_scan_session(current_scan_id, f'error: {e}')

    with scan_lock:
        scan_data["status"] = "done"

def perform_detailed_scan(ip):
    """Worker for the intensive per-host scan"""
    def update_status(phase, progress, result=None, error=None):
        with detailed_lock:
            # Preserve existing result data while updating phase/progress
            scan_state = detailed_scans.get(ip, {})
            scan_state.update({"phase": phase, "progress": progress})
            if result:
                # Merge new result data into existing data
                existing_result = scan_state.get("result", {})
                existing_result.update(result)
                scan_state["result"] = existing_result
            if error:
                scan_state["error"] = error
            detailed_scans[ip] = scan_state
    
    try:
        # Step 1: Ping host to ensure it's online
        update_status("Pinging host...", 10)
        scanner = run_nmap_with_timeout(ip, '-sn -T4', timeout=20)
        if scanner == "TIMEOUT":
            raise ValueError("Host ping timed out.")
        if not isinstance(scanner, nmap.PortScanner) or ip not in scanner.all_hosts():
            raise ValueError("Host is down or not responding.")

        # Step 2: Scan for open ports and services (fast and reliable)
        update_status("Scanning for open ports and services...", 30)
        # -sV for service version, but no -O for OS detection yet
        scanner = run_nmap_with_timeout(ip, '-sV -T4 --top-ports 1000', timeout=120)
        if scanner == "TIMEOUT":
            raise ValueError("Service scan timed out.")
        if not isinstance(scanner, nmap.PortScanner):
            raise ValueError("Service scan failed.")

        # Store the valuable results we have so far
        result = {
            "state": scanner[ip].state(),
            "hostnames": scanner[ip].hostnames(),
            "tcp": scanner[ip].get('tcp', {}),
            "osmatch": []  # Default to empty
        }
        update_status("Service scan complete. Attempting OS detection...", 80, result=result)

        # Step 3: Attempt OS Detection separately with a short timeout
        os_scanner = run_nmap_with_timeout(ip, '-O -T4 --osscan-limit --max-os-tries 1', timeout=60)
        if isinstance(os_scanner, nmap.PortScanner) and ip in os_scanner.all_hosts():
            result["osmatch"] = os_scanner[ip].get('osmatch', [])
        else:
            print(f"OS detection failed or timed out for {ip}. Proceeding without it.")

        # Final update with all collected data
        update_status("Complete", 100, result=result)

    except Exception as e:
        update_status(f"Error: {e}", 100, error=str(e))

# --- Flask Routes ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/visual")
def visual():
    return render_template("visual.html")

@app.route("/scan_host/<ip>")
def scan_host(ip):
    return render_template("host.html", ip=ip)

@app.route("/saved_scan/<int:scan_id>")
def view_saved_scan(scan_id):
    """Route to view saved scan details"""
    scan_details = get_scan_details(scan_id)
    if scan_details:
        return render_template("saved_scan.html", scan=scan_details)
    else:
        return "Scan not found", 404

# --- API Routes ---
@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = data.get("target")
    phase = data.get("phase", "Discovery")
    threading.Thread(target=perform_discovery_scan, args=(target,), daemon=True).start()
    return jsonify({"status": "started", "phase": phase})

@app.route("/api/visual_scan", methods=["POST"])
def visual_scan():
    data = request.get_json()
    target = data.get("target")
    phase = data.get("phase", "Discovery")
    
    threading.Thread(target=perform_visual_scan, args=(target,), daemon=True).start()
    return jsonify({"status": "started", "phase": phase})

@app.route("/api/detailed_scan/<ip>", methods=["POST"])
def start_detailed_scan(ip):
    """Start a detailed scan for a specific host"""
    with detailed_lock:
        if detailed_scans.get(ip, {}).get("phase") not in [None, "Complete", "Error"]:
            if "result" not in detailed_scans[ip] and "error" not in detailed_scans[ip]:
                return jsonify({"status": "Scan already in progress"}), 409
    
    threading.Thread(target=perform_detailed_scan, args=(ip,), daemon=True).start()
    return jsonify({"status": "Detailed scan initiated"})

@app.route("/api/detailed_progress/<ip>")
def get_detailed_status(ip):
    """Get progress of detailed scan"""
    with detailed_lock:
        return jsonify(detailed_scans.get(ip, {"phase": "Not Started", "progress": 0}))

@app.route("/api/status")
def status():
    with scan_lock:
        return jsonify(scan_data)

@app.route("/api/network_graph")
def get_network_graph():
    with graph_lock:
        return jsonify(network_graph)

@app.route("/api/reset_scan", methods=["POST"])
def api_reset_scan():
    reset_scan_data()
    with graph_lock:
        network_graph["nodes"] = []
        network_graph["edges"] = []
    return jsonify({"status": "reset"})

@app.route("/api/localrange")
def localrange():
    return jsonify({"range": get_local_network()})

@app.route("/api/gateway")
def gateway():
    return jsonify({"gateway": get_default_gateway()})

# --- Database API Routes ---
@app.route("/api/save_current_scan", methods=["POST"])
def save_current_scan():
    """Save the current scan results to database"""
    global current_scan_id
    if not current_scan_id:
        return jsonify({"status": "error", "message": "No active scan to save"})
    
    if mark_scan_as_saved(current_scan_id):
        return jsonify({"status": "success", "message": "Scan saved successfully", "scan_id": current_scan_id})
    else:
        return jsonify({"status": "error", "message": "Failed to save scan"})

@app.route("/api/saved_scans")
def get_saved_scans_api():
    """Get all saved scans"""
    scan_type = request.args.get('type')
    scans = get_saved_scans(scan_type)
    return jsonify({"status": "success", "scans": scans})

@app.route("/api/saved_scan/<int:scan_id>")
def get_saved_scan_details(scan_id):
    """Get detailed information for a saved scan"""
    scan_details = get_scan_details(scan_id)
    if scan_details:
        return jsonify({"status": "success", "scan": scan_details})
    else:
        return jsonify({"status": "error", "message": "Scan not found"})

@app.route("/api/delete_scan/<int:scan_id>", methods=["DELETE"])
def delete_scan_api(scan_id):
    """Delete a saved scan"""
    if delete_scan(scan_id):
        return jsonify({"status": "success", "message": "Scan deleted successfully"})
    else:
        return jsonify({"status": "error", "message": "Failed to delete scan"})

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')