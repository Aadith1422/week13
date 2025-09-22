# Transport Layer of the OSI Model

The **Transport Layer (Layer 4)** is responsible for **end-to-end communication, reliability, error recovery, and flow control** between applications on different hosts. It ensures that data is delivered **accurately, in sequence, and without loss or duplication**.

---

## Functionalities of the Transport Layer
- **Segmentation & Reassembly** – Divides application data into smaller segments and reassembles them at the destination.  
- **End-to-End Communication** – Provides logical communication between processes on different hosts.  
- **Reliability** – Ensures delivery with mechanisms like acknowledgments, retransmissions, and error checking.  
- **Flow Control** – Prevents fast senders from overwhelming slow receivers (e.g., sliding window mechanism).  
- **Error Detection & Recovery** – Uses checksums and retransmission on error.  
- **Multiplexing & Demultiplexing** – Allows multiple applications to use the network simultaneously (via ports).  
- **Connection Management** – Establishes, maintains, and terminates sessions between hosts.  

---

## Sublayers of the Transport Layer
1. **Transmission Control (Reliable Sublayer)**  
   - Provides connection-oriented communication (TCP).  
   - Guarantees delivery, ordering, and error recovery.  

2. **User Datagram (Unreliable Sublayer)**  
   - Provides connectionless communication (UDP).  
   - Faster but without reliability guarantees.  

---

## Devices Operating at the Transport Layer
- **Firewalls (Stateful)** – Inspect TCP/UDP ports and sessions.  
- **Load Balancers** – Distribute traffic based on transport layer info (ports).  
- **Proxies / Application Gateways** – Sometimes operate at transport level for session handling.  

---

## Protocols at the Transport Layer
- **TCP (Transmission Control Protocol)** – Reliable, connection-oriented, ordered delivery.  
- **UDP (User Datagram Protocol)** – Unreliable, connectionless, low-overhead communication.  
- **SCTP (Stream Control Transmission Protocol)** – Combines features of TCP and UDP, supports multi-homing.  
- **DCCP (Datagram Congestion Control Protocol)** – Provides congestion control for datagram flows.  

---

## Attacks at the Transport Layer
- **TCP SYN Flooding** – Exploits TCP’s 3-way handshake to exhaust server resources.  
- **Session Hijacking** – Attacker takes over an active TCP session.  
- **UDP Flooding** – Overwhelms a system with high volumes of UDP packets.  
- **TCP Reset Attack (RST Injection)** – Forcing termination of sessions by injecting forged RST packets.  
- **Port Scanning** – Identifying open transport layer ports to find vulnerabilities.  
- **Fragmentation & Reassembly Attacks** – Exploit TCP segmentation to bypass IDS/IPS.  
- **Reflection & Amplification Attacks (UDP/ICMP-based)** – Used in DDoS amplification.  

---

## Mitigation Techniques
- **SYN Cookies** – Protect servers from SYN flood attacks.  
- **Firewalls & ACLs** – Restrict access to unnecessary ports.  
- **Rate Limiting** – Throttle excessive TCP/UDP connections.  
- **Encryption (TLS/SSL)** – Protects session data from hijacking and tampering.  
- **IDS/IPS Deployment** – Detect abnormal traffic patterns at Layer 4.  
- **Session Timeout & Reset Controls** – Prevent prolonged idle sessions.  
- **Secure Port Management** – Close unused ports, restrict access to sensitive ones.  

---

## ✅ Summary
The **Transport Layer** ensures reliable, efficient, and correct delivery of data between applications on different hosts. It provides **segmentation, reliability, flow control, and multiplexing**. However, it is vulnerable to **SYN floods, session hijacking, and port scanning**. Strong **firewall rules, encryption, rate limiting, and intrusion detection** are essential to secure this layer.

