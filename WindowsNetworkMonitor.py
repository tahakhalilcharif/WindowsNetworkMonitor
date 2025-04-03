#!/usr/bin/env python3
"""
Enhanced Website Traffic Monitor - Tracks DNS queries and HTTP hosts
to log websites being visited on a network interface.
Fixed for scheduled task operation under SYSTEM account.
"""

import argparse
import csv
import os
import sys
import signal
import time
import getpass
from datetime import datetime
from collections import defaultdict

# Silent mode control - set to False for debugging
SILENT_MODE = True

# Global variables
log_file = None
csv_writer = None
domains_seen = defaultdict(set)
running = True

def silent_print(*args, **kwargs):
    """Only print if not in silent mode"""
    if not SILENT_MODE:
        print(*args, **kwargs)

def setup_logging():
    """Configure logging for scheduled task operation"""
    log_dir = r"C:\MonitorLogs"
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
        except Exception as e:
            silent_print(f"Failed to create log directory: {e}")
            return None
    
    log_path = os.path.join(log_dir, "network_monitor.log")
    try:
        return open(log_path, 'a')
    except Exception as e:
        silent_print(f"Failed to open log file: {e}")
        return None

def log_message(message):
    """Log messages to file and console (if not silent)"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    
    debug_log = setup_logging()
    if debug_log:
        debug_log.write(full_message + "\n")
        debug_log.flush()
        debug_log.close()
    
    silent_print(full_message)

def check_privileges():
    """Check for admin/root privileges"""
    if os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            log_message("This script requires administrator privileges.")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            log_message("This script requires root privileges.")
            sys.exit(1)

def load_scapy():
    """Load scapy with proper error handling"""
    try:
        from scapy.all import sniff, IP, DNS, DNSQR, TCP, Raw
        from scapy.layers.http import HTTPRequest
        from scapy.arch import get_if_list
        return True
    except ImportError:
        try:
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"],
                                stdout=subprocess.DEVNULL if SILENT_MODE else None,
                                stderr=subprocess.DEVNULL if SILENT_MODE else None)
            from scapy.all import sniff, IP, DNS, DNSQR, TCP, Raw
            from scapy.layers.http import HTTPRequest
            from scapy.arch import get_if_list
            return True
        except Exception as e:
            log_message(f"Failed to load scapy: {e}")
            return False

def signal_handler(sig, frame):
    """Handle Ctrl+C to gracefully stop the script"""
    global running
    log_message("Stopping capture...")
    running = False

def get_default_interface():
    """Get the first available network interface"""
    try:
        from scapy.arch import get_if_list
        interfaces = get_if_list()
        return interfaces[0] if interfaces else None
    except Exception as e:
        log_message(f"Error getting interfaces: {e}")
        return None

def extract_domain_from_dns(pkt):
    """Extract domain name from DNS query"""
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname
        if isinstance(qname, bytes):
            return qname.decode('utf-8', errors='ignore').rstrip('.')
        return str(qname).rstrip('.')
    return None

def extract_domain_from_http(pkt):
    """Extract domain from HTTP Host header"""
    if pkt.haslayer(HTTPRequest):
        if hasattr(pkt[HTTPRequest], 'Host'):
            host = pkt[HTTPRequest].Host
            if isinstance(host, bytes):
                return host.decode('utf-8', errors='ignore')
            return str(host)
    return None

def extract_tls_info(pkt):
    """Detect TLS traffic"""
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw_data = bytes(pkt[Raw])
        if len(raw_data) > 5 and raw_data[0] == 0x16 and raw_data[1:3] == b'\x03\x01':
            return "tls_traffic"
    return None

def packet_callback(pkt):
    """Process packet and extract domain information"""
    global domains_seen, csv_writer
    
    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    domain = None
    
    if pkt.haslayer(DNS):
        domain = extract_domain_from_dns(pkt)
    elif pkt.haslayer(HTTPRequest):
        domain = extract_domain_from_http(pkt)
    elif pkt.haslayer(TCP) and pkt[TCP].dport == 443:
        tls_info = extract_tls_info(pkt)
        if tls_info:
            domain = f"https://{dst_ip}"
    
    if domain and domain != "":
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        if dst_ip not in domains_seen[domain]:
            domains_seen[domain].add(dst_ip)
            try:
                csv_writer.writerow([timestamp, domain, dst_ip])
                log_file.flush()
                silent_print(f"[{timestamp}] {domain} -> {dst_ip}")
            except Exception as e:
                log_message(f"Error writing to log: {e}")

def main():
    global log_file, csv_writer, running
    
    # Hide console window on Windows if in silent mode
    if SILENT_MODE and os.name == 'nt':
        try:
            import win32gui, win32con
            win32gui.ShowWindow(win32gui.GetForegroundWindow(), win32con.SW_HIDE)
        except:
            pass
    
    check_privileges()
    if not load_scapy():
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description='Monitor network traffic for website visits')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-o', '--output', help='Output CSV file')
    args = parser.parse_args()
    
    # Set default output file
    if not args.output:
        args.output = r"C:\MonitorLogs\network_traffic.csv"
    
    # Get interface
    selected_interface = args.interface if args.interface else get_default_interface()
    if not selected_interface:
        log_message("No network interface available")
        sys.exit(1)
    
    log_message(f"Selected interface: {selected_interface}")
    
    # Set up output file
    try:
        log_dir = os.path.dirname(args.output)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        file_exists = os.path.isfile(args.output)
        log_file = open(args.output, 'a', newline='', encoding='utf-8')
        csv_writer = csv.writer(log_file)
        
        if not file_exists:
            csv_writer.writerow(['Timestamp', 'Domain', 'IP'])
            log_file.flush()
    except Exception as e:
        log_message(f"Failed to initialize output file: {e}")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    log_message(f"Starting capture on {selected_interface}")
    log_message(f"Logging to: {os.path.abspath(args.output)}")
    
    try:
        sniff(
            iface=selected_interface,
            filter="udp port 53 or tcp port 80 or tcp port 443",
            prn=packet_callback,
            store=0,
            stop_filter=lambda x: not running,
            quiet=SILENT_MODE
        )
    except Exception as e:
        log_message(f"Error during capture: {e}")
    finally:
        if log_file:
            log_file.close()
        log_message("Capture stopped")

if __name__ == "__main__":
    main()