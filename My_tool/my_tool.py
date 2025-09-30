import os
import socket
import subprocess
import ipaddress
from datetime import datetime
import time
import signal
from concurrent.futures import ThreadPoolExecutor
import argparse
import getpass

# -------- CONFIGURATION -------- #
DEFAULT_PORTS =[
    20,    # FTP data
    21,    # FTP control
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    69,    # TFTP
    80,    # HTTP
    110,   # POP3
    111,   # RPCbind
    135,   # MS RPC
    137,   # NetBIOS Name Service
    138,   # NetBIOS Datagram Service
    139,   # NetBIOS Session Service
    143,   # IMAP
    161,   # SNMP
    162,   # SNMP trap
    443,   # HTTPS
    445,   # SMB
    465,   # SMTPS
    514,   # Syslog
    587,   # SMTP Submission
    631,   # IPP (printer)
    993,   # IMAPS
    995,   # POP3S
    1433,  # Microsoft SQL Server
    1521,  # Oracle DB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8080,  # HTTP-alt
    8443,  # HTTPS-alt
    9000,  # Web apps / admin panels
]

DEFAULT_TIMEOUT = 0.5  # Socket timeout in seconds
DEFAULT_CAPTURE_FILE = "/tmp/network_scan_capture.pcap"  # Temporary safe location
DEFAULT_MAX_THREADS = 50  # Max threads for ping/port scanning
# -------------------------------- #

def get_active_interface():
    """Return manually set interface and IP (hardcoded)"""
    interface = "wlo1"       # Your active Wi-Fi interface
    ip = "192.168.56.84"     # Your current IP
    print(f"[INFO] Using interface: {interface} with IP {ip}")
    return interface, ip

def calculate_network_prefix(ip):
    """Calculate subnet /24 prefix for ping sweep"""
    try:
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return str(network.network_address).rstrip('.0')
    except ValueError:
        octets = ip.split('.')
        return f"{octets[0]}.{octets[1]}.{octets[2]}."

def start_capture(interface, capture_file):
    """Start tshark capture in background with sudo"""
    print("[INFO] Starting Wireshark capture... (requires sudo and tshark installed)")
    try:
        tshark_cmd = ["sudo", "tshark", "-i", interface, "-w", capture_file]
        proc = subprocess.Popen(
            tshark_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid  # Create a new process group for proper termination
        )
        time.sleep(2)  # Wait for capture to start
        if proc.poll() is not None:  # Check if process terminated prematurely
            error = proc.stderr.read().decode()
            raise Exception(f"tshark failed to start: {error}")
        return proc
    except Exception as e:
        print(f"[ERROR] Failed to start capture: {e}")
        return None

def stop_capture(proc, capture_file):
    """Stop tshark capture and fix file permissions"""
    if proc:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)  # Terminate process group
            proc.communicate(timeout=5)
            # Fix file permissions to allow current user to read the capture file
            current_user = getpass.getuser()
            subprocess.run(["sudo", "chown", f"{current_user}:{current_user}", capture_file], check=True)
            subprocess.run(["sudo", "chmod", "644", capture_file], check=True)
            print(f"[INFO] Wireshark capture saved to {capture_file} with updated permissions")
        except Exception as e:
            print(f"[ERROR] Failed to stop capture or set permissions: {e}")

def ping_host(ip):
    """Return True if host responds to ping"""
    try:
        subprocess.check_output(
            ["ping", "-c", "1", "-W", "1", ip],
            stderr=subprocess.DEVNULL,
            timeout=2
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False

def ping_sweep(network_prefix, max_threads):
    """Find live hosts using threaded ping sweep"""
    print("\n[INFO] Starting Ping Sweep...")
    live_hosts = []

    def check_ip(i):
        ip = f"{network_prefix}.{i}"
        if ping_host(ip):
            print(f"[+] Host online: {ip}")
            live_hosts.append(ip)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(check_ip, range(1, 255))

    if not live_hosts:
        print("[-] No live hosts found.")
    return live_hosts

def scan_port(host, port, timeout):
    """Scan a single port on a host"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except Exception as e:
        print(f"[WARNING] Error scanning port {port} on {host}: {e}")
        return None

def port_scan(host, ports, timeout):
    """Scan ports on a host using threads"""
    print(f"\n[INFO] Scanning ports on {host}...")
    open_ports = []

    def check_port(port):
        result = scan_port(host, port, timeout)
        if result:
            print(f"[+] Port {result} is OPEN")
            open_ports.append(result)

    with ThreadPoolExecutor(max_workers=len(ports)) as executor:
        executor.map(check_port, ports)

    if not open_ports:
        print("[-] No open ports found.")
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="Fully Automated Network Scanner")
    parser.add_argument("--ports", type=str, default=",".join(map(str, DEFAULT_PORTS)),
                        help="Comma-separated list of ports to scan (default: 21,22,23,80,443,8080)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="Socket timeout in seconds (default: 0.5)")
    parser.add_argument("--capture-file", type=str, default=DEFAULT_CAPTURE_FILE,
                        help="Path to save capture file (default: /tmp/network_scan_capture.pcap)")
    parser.add_argument("--max-threads", type=int, default=DEFAULT_MAX_THREADS,
                        help="Max threads for scanning (default: 50)")
    parser.add_argument("--no-capture", action="store_true",
                        help="Disable packet capture")
    args = parser.parse_args()

    ports_to_scan = [int(p) for p in args.ports.split(",")]

    start_time = datetime.now()
    print("=== Fully Automated Network Scanner ===")
    print(f"Start time: {start_time}\n")

    interface, ip = get_active_interface()
    network_prefix = calculate_network_prefix(ip)

    capture_proc = None
    if not args.no_capture:
        capture_proc = start_capture(interface, args.capture_file)

    try:
        # Ping sweep
        live_hosts = ping_sweep(network_prefix, args.max_threads)

        # Port scan
        all_results = {}
        for host in live_hosts:
            all_results[host] = port_scan(host, ports_to_scan, args.timeout)

    finally:
        # Ensure capture is stopped even if an error occurs
        stop_capture(capture_proc, args.capture_file)

    # Print summary
    print("\n=== SCAN SUMMARY ===")
    for host, ports in all_results.items():
        if ports:
            print(f"{host}: Open ports -> {ports}")
        else:
            print(f"{host}: No open ports found.")

    end_time = datetime.now()
    print(f"\nScan completed in: {end_time - start_time}")
    if not args.no_capture and capture_proc:
        print(f"\n[INFO] You can now open {args.capture_file} in Wireshark to analyze ICMP/TCP packets.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user")
        # Ensure capture is stopped on Ctrl+C
        if 'capture_proc' in locals() and capture_proc:
            stop_capture(capture_proc, DEFAULT_CAPTURE_FILE)