# 🌐 TCP/IP Model – Transport Layer

## 1. Functionality
- Provides **end-to-end communication** between applications on different hosts.
- Ensures **data reliability, sequencing, and error recovery** (for TCP).
- Implements **flow control** to prevent sender from overwhelming receiver.
- Supports **multiplexing/demultiplexing** using port numbers.
- Manages **connection setup and termination** (for connection-oriented communication).

---

## 2. Sublayers
The Transport Layer can be logically divided into:
1. **Reliable Transport Sublayer**  
   - Connection-oriented communication (TCP).  
   - Guarantees delivery, sequencing, and error recovery.
2. **Unreliable Transport Sublayer**  
   - Connectionless communication (UDP).  
   - Provides fast, low-overhead communication without reliability guarantees.

---

## 3. Devices
- **Firewalls** – Filter traffic based on TCP/UDP ports.  
- **Load Balancers** – Distribute traffic based on transport-layer information.  
- **Gateways / Proxies** – May handle session or transport layer translation.  

---

## 4. Protocols
- **TCP (Transmission Control Protocol)** – Reliable, connection-oriented, ensures ordered delivery.  
- **UDP (User Datagram Protocol)** – Fast, connectionless, low-overhead, no guarantee of delivery.  
- **SCTP (Stream Control Transmission Protocol)** – Reliable transport with multi-streaming and multi-homing.  
- **DCCP (Datagram Congestion Control Protocol)** – For congestion-controlled datagram flows.

---

## 5. Attacks
- **TCP SYN Flood** – Exhaust server resources by abusing TCP handshake.  
- **UDP Flood** – Overwhelm systems with high-volume UDP packets.  
- **Session Hijacking** – Take control of an active TCP session.  
- **TCP Reset Attack (RST Injection)** – Force session termination.  
- **Port Scanning** – Identify open ports to exploit vulnerabilities.  
- **Fragmentation Attacks** – Exploit TCP segmentation to bypass security devices.

---

## 6. Mitigation
- **SYN Cookies** – Protect servers from SYN flood attacks.  
- **Firewalls & ACLs** – Restrict access to unnecessary ports.  
- **Rate Limiting** – Throttle excessive TCP/UDP connections.  
- **TLS/SSL Encryption** – Secure sessions from hijacking or tampering.  
- **IDS/IPS Deployment** – Detect abnormal traffic patterns at Layer 4.  
- **Session Timeout & Reset Controls** – Prevent prolonged idle sessions.  
- **Secure Port Management** – Close unused ports, restrict sensitive ones.
