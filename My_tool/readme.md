
# Fully Automated Network Scanner

A Python-based network scanning tool for educational and lab purposes.  
It performs **ping sweeps**, **port scans**, and optionally captures network traffic for analysis with Wireshark.

---

## Features

- **Ping Sweep**: Identify live hosts in a network.
- **Port Scan**: Check for open ports on live hosts.
- **Packet Capture**: Optionally capture network packets using `tshark`.
- **Threaded Scanning**: Uses multithreading for faster performance.
- **Environment Variables**: Hide sensitive information like IPs and network interface names.

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/Aadith1422/WEEK13/My_tool.git
cd My_tool
```

2. Install required dependencies (Python 3.x required):

```bash
pip install -r requirements.txt
```

> **Note**: `tshark` must be installed for packet capture:

```bash
sudo apt install tshark
```

---

## Usage

### Environment Variables (Optional)

You can configure the network interface and local IP without hardcoding:

```bash
export SCAN_INTERFACE=""
export SCAN_IP=""
export CAPTURE_FILE=""
```

---

### Basic Scan

Run a scan with default ports:

```bash
python network_scanner.py
```

---

### Custom Ports

Scan specific ports:

```bash
python network_scanner.py --ports 22,80,443
```

---

### Adjust Timeout

Set custom socket timeout:

```bash
python network_scanner.py --timeout 1.0
```

---

### Disable Packet Capture

Skip capturing network packets:

```bash
python network_scanner.py --no-capture
```

---

### Max Threads

Control number of threads:

```bash
python network_scanner.py --max-threads 100
```

---

## Output

- **Live Hosts**: Lists all reachable hosts.
- **Open Ports**: Lists open ports for each host.
- **Capture File**: Saves `.pcap` file (if capture enabled) for Wireshark analysis.

---

## Security & Ethical Use

- Only scan networks you own or have explicit permission to scan.
- Environment variables help keep sensitive information private.
- Avoid pushing real internal IPs or network data to public repositories.

---

## Example Command

```bash
SCAN_INTERFACE=eth0 SCAN_IP=192.168.0.0 python network_scanner.py --ports 22,80,443 --timeout 0.5
```

---

## License

This project is licensed under the MIT License.