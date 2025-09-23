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
DEFAULT_PORTS = [
    20, 21, 22, 23, 25, 53, 69, 80, 110, 111, 135, 137, 138, 139, 143,
    161, 162, 443, 445, 465, 514, 587, 631, 993, 995, 1433, 1521,
    3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000
]

DEFAULT_TIMEOUT = 0.5
DEFAULT_CAPTURE_FILE = f"/tmp/{getpass.getuser()}_network_capture.pcap"
DEFAULT_MAX_THREADS = 50
# -------------------------------- #

# Read environment variables for sensitive info
INTERFACE = os.getenv("SCAN_INTERFACE", "eth0")  # default dummy interface
LOCAL_IP = os.getenv("SCAN_IP", "192.168.0.0")  # default placeholder IP
CAPTURE_FILE = os.getenv("CAPTURE_FILE", DEFAULT_CAPTURE_FILE)


def get_active_interface():
    """Return interface and IP from env or defaults"""
    print(f"[INFO] Using interface: {INTERFACE} with IP {LOCAL_IP}")
    return INTERFACE, LOCAL_IP


def calculate_network_prefix(ip):
    """Calculate subnet /24 prefix for ping sweep"""
    try:
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return str(network.network_address).rstrip('.0')
    except ValueError:
        octets = ip.split('.')
        return f"{octets[0]}.{octets[1]}.{octets[2]}"


def start_capture(interface, capture_file):
    """Start tshark capture in background with sudo"""
    print("[INFO] Starting Wireshark capture... (requires sudo and tshark installed)")
    try:
        tshark_cmd = ["sudo", "tshark", "-i", interface, "-w", capture_file]
        proc = subprocess.Popen(
            tshark_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
        time.sleep(2)
        if proc.poll() is not None:
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
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.communicate(timeout=5)
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
                        help="Comma-separated list of ports to scan")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="Socket timeout in seconds")
    parser.add_argument("--capture-file", type=str, default=CAPTURE_FILE,
                        help="Path to save capture file")
    parser.add_argument("--max-threads", type=int, default=DEFAULT_MAX_THREADS,
                        help="Max threads for scanning")
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
        live_hosts = ping_sweep(network_prefix, args.max_threads)
        all_results = {}
        for host in live_hosts:
            all_results[host] = port_scan(host, ports_to_scan, args.timeout)
    finally:
        stop_capture(capture_proc, args.capture_file)

    print("\n=== SCAN SUMMARY ===")
    for host, ports in all_results.items():
        if ports:
            print(f"{host}: Open ports -> {ports}")
        else:
            print(f"{host}: No open ports found.")

    end_time = datetime.now()
    print(f"\nScan completed in: {end_time - start_time}")
    if not args.no_capture and capture_proc:
        print(f"\n[INFO] You can now open {args.capture_file} in Wireshark.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user")
        if 'capture_proc' in locals() and capture_proc:
            stop_capture(capture_proc, DEFAULT_CAPTURE_FILE)